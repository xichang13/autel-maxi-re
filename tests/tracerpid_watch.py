# ABOUTME: 持续附加当前运行的目标应用，记录存活、分离、崩溃及脚本事件。
# ABOUTME: 提供完整、原生、Java 与空脚本独立对照，结束时仅分离测试会话。
import argparse
import base64
import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

import frida


def invoke(timeout, operation, *args, **kwargs):
    token = frida.Cancellable()
    timer = threading.Timer(timeout, token.cancel)
    timer.daemon = True
    timer.start()
    try:
        with token:
            return operation(*args, **kwargs)
    finally:
        timer.cancel()


def serialize(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {'base64': base64.b64encode(value).decode('ascii')}
    if isinstance(value, dict):
        return {str(key): serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize(item) for item in value]
    details = {}
    for name in ('pid', 'process_name', 'summary', 'report', 'parameters'):
        if hasattr(value, name):
            details[name] = serialize(getattr(value, name))
    return details if details else repr(value)


def selected_source(args):
    transformations = []
    source = '' if args.mode == 'empty' else args.script.read_text(encoding='utf-8-sig')
    if args.mode == 'native-only':
        entry = 'if (Java.available) Java.perform(function () {'
        if source.count(entry) != 1:
            raise ValueError('原生对照要求恰好一个已知 Java 入口；生产脚本入口需要人工核查')
        source = source.replace(entry, 'if (false) Java.perform(function () {', 1)
        transformations.append('disable-java-entry')
    elif args.mode == 'java-only':
        flag = 'var HIDE_TRACERPID = true;'
        if source.count(flag) != 1:
            raise ValueError('Java 对照要求恰好一个已知 TracerPid 配置；生产脚本配置需要人工核查')
        source = source.replace(flag, 'var HIDE_TRACERPID = false;', 1)
        transformations.append('disable-native-entry')
    diagnostic = args.diagnostic.read_text(encoding='utf-8-sig') if args.diagnostic else ''
    combined = "'use strict';\n" + diagnostic + '\n' + source
    metadata = {
        'production_path': str(args.script.resolve()) if args.mode != 'empty' else None,
        'production_sha256': hashlib.sha256(args.script.read_bytes()).hexdigest() if args.mode != 'empty' else None,
        'loaded_sha256': hashlib.sha256(combined.encode('utf-8')).hexdigest(),
        'transformations': transformations,
        'diagnostic_path': str(args.diagnostic.resolve()) if args.diagnostic else None,
        'diagnostic_sha256': hashlib.sha256(args.diagnostic.read_bytes()).hexdigest() if args.diagnostic else None,
    }
    return combined, metadata


def arguments():
    parser = argparse.ArgumentParser(description='持续观察当前应用，四种模式分别运行并记录真实退出证据。')
    parser.add_argument('--host', default='127.0.0.1:9527')
    parser.add_argument('--package', default='com.autel.update')
    parser.add_argument('--pid', type=int)
    parser.add_argument('--mode', choices=('full', 'native-only', 'java-only', 'empty'), default='full')
    parser.add_argument('--duration', type=float, default=60.0)
    parser.add_argument('--poll-interval', type=float, default=1.0)
    parser.add_argument('--timeout', type=float, default=15.0)
    parser.add_argument('--stdout-limit', type=int, default=40)
    parser.add_argument('--script', type=Path, default=Path(__file__).resolve().parents[1] / 'hook_JniEncryptData.js')
    parser.add_argument('--diagnostic', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.duration < 60:
        parser.error('--duration 必须至少为 60 秒')
    if not 0.1 <= args.poll_interval <= 10:
        parser.error('--poll-interval 必须介于 0.1 与 10 秒之间')
    if args.timeout <= 0:
        parser.error('--timeout 必须大于零')
    if args.stdout_limit < 0:
        parser.error('--stdout-limit 不能为负数')
    return args


def run(args):
    started = time.monotonic()
    lock = threading.RLock()
    wake = threading.Event()
    report = {
        'passed': False, 'stage': 'preparing', 'mode': args.mode,
        'host': args.host, 'package': args.package, 'requested_pid': args.pid,
        'requested_duration_seconds': args.duration, 'poll_interval_seconds': args.poll_interval,
        'frida_client_version': frida.__version__, 'started_unix': time.time(),
        'events': [], 'polls': [], 'detached': [], 'crashes': [], 'cleanup': [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    event_path = args.output.with_name(args.output.stem + '.events.jsonl')
    report['event_path'] = str(event_path.resolve())
    stream = event_path.open('w', encoding='utf-8', buffering=1)
    session = None
    device = None
    device_signals = []
    cleanup_started = False
    printed_logs = 0
    exit_code = 1
    watch_started = None

    def record(kind, payload):
        nonlocal printed_logs
        with lock:
            entry = {
                'sequence': len(report['events']) + 1, 'kind': kind,
                'unix': time.time(), 'elapsed_seconds': round(time.monotonic() - started, 6),
                'payload': serialize(payload),
            }
            report['events'].append(entry)
            if not stream.closed:
                stream.write(json.dumps(entry, ensure_ascii=False) + '\n')
                stream.flush()
            if kind in ('detached', 'process-crashed', 'device-lost', 'failure', 'stage'):
                print('{}: {}'.format(kind, json.dumps(entry['payload'], ensure_ascii=False)[:1000]), flush=True)
            elif kind in ('script-log', 'script-message') and printed_logs < args.stdout_limit:
                printed_logs += 1
                print('{}: {}'.format(kind, json.dumps(entry['payload'], ensure_ascii=False)[:1000]), flush=True)

    def save():
        with lock:
            report['updated_unix'] = time.time()
            text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
        temporary = args.output.with_name(args.output.name + '.tmp')
        temporary.write_text(text, encoding='utf-8')
        os.replace(str(temporary), str(args.output))

    def stage(value):
        with lock:
            report['stage'] = value
        record('stage', {'value': value})
        save()

    def on_detached(*values):
        reason = str(values[0]) if values else None
        item = {
            'reason': reason, 'crash': serialize(values[1]) if len(values) > 1 else None,
            'raw_arguments': serialize(values),
            'requested_by_harness': cleanup_started and reason == 'application-requested',
        }
        with lock:
            report['detached'].append(item)
        record('detached', item)
        wake.set()

    def on_crashed(crash):
        details = serialize(crash)
        if isinstance(details, dict) and details.get('pid') == report.get('pid'):
            with lock:
                report['crashes'].append(details)
            record('process-crashed', details)
            wake.set()

    def on_lost(*values):
        record('device-lost', {'arguments': values})
        wake.set()

    def on_message(message, data):
        record('script-message', {'message': message, 'data': data})

    def on_log(level, text):
        record('script-log', {'level': level, 'text': text})

    try:
        source, metadata = selected_source(args)
        report['source'] = metadata
        stage('connecting')
        device = invoke(args.timeout, frida.get_device_manager().add_remote_device, args.host)
        processes = invoke(args.timeout, device.enumerate_processes)
        if args.pid is not None:
            candidates = [item for item in processes if item.pid == args.pid]
            if candidates and not (candidates[0].name == args.package or candidates[0].name.startswith(args.package + ':')):
                raise ValueError('所选 PID 不属于指定应用: ' + candidates[0].name)
        else:
            candidates = [item for item in processes if item.name == args.package]
        if not candidates:
            report['needs_start'] = True
            exit_code = 2
            raise RuntimeError('目标进程未运行，请先手动启动 ' + args.package)
        if len(candidates) != 1:
            raise RuntimeError('找到多个候选进程，请使用 --pid 明确选择')
        report['pid'] = candidates[0].pid
        report['process_name'] = candidates[0].name
        device.on('process-crashed', on_crashed)
        device_signals.append(('process-crashed', on_crashed))
        device.on('lost', on_lost)
        device_signals.append(('lost', on_lost))
        stage('attaching')
        session = invoke(args.timeout, device.attach, report['pid'])
        session.on('detached', on_detached)
        report['attached_unix'] = time.time()
        stage('loading')
        script = invoke(args.timeout, session.create_script, source, name='tracerpid-watch-' + args.mode, runtime='duk')
        script.on('message', on_message)
        script.set_log_handler(on_log)
        invoke(args.timeout, script.load)
        watch_started = time.monotonic()
        report['loaded_unix'] = time.time()
        stage('watching')
        deadline = watch_started + args.duration
        last_progress = 0.0
        while True:
            processes = invoke(args.timeout, device.enumerate_processes)
            alive = any(item.pid == report['pid'] for item in processes)
            replacements = [{'pid': item.pid, 'name': item.name} for item in processes
                            if item.name == report['process_name'] and item.pid != report['pid']]
            elapsed = time.monotonic() - watch_started
            poll = {'unix': time.time(), 'watched_seconds': round(elapsed, 6), 'alive': alive,
                    'replacement_processes': replacements}
            with lock:
                report['polls'].append(poll)
                report['watched_seconds'] = poll['watched_seconds']
                report['last_alive'] = alive
            record('poll', poll)
            save()
            if not alive:
                raise RuntimeError('原目标进程已退出；替代进程仅记录，不重新附加')
            if any(not item['requested_by_harness'] for item in report['detached']):
                raise RuntimeError('Frida 会话在观察期内分离，详见 detached 事件')
            if report['crashes']:
                raise RuntimeError('收到目标应用的真实崩溃事件')
            if wake.is_set():
                raise RuntimeError('观察会话或设备连接状态发生变化，详见事件')
            if elapsed - last_progress >= 5 or last_progress == 0:
                print('观察中: mode={}, pid={}, {:.1f}/{:.1f}s'.format(args.mode, report['pid'], elapsed, args.duration), flush=True)
                last_progress = elapsed
            if elapsed >= args.duration:
                break
            wake.wait(min(args.poll_interval, max(0, deadline - time.monotonic())))
        report['duration_reached'] = True
        script_errors = [entry for entry in report['events'] if entry['kind'] == 'script-message'
                         and entry['payload']['message'].get('type') == 'error']
        log_entries = [entry['payload'] for entry in report['events'] if entry['kind'] == 'script-log']
        report['script_errors'] = script_errors
        report['script_error_logs'] = [entry for entry in log_entries if entry['level'] == 'error'
                                       or '[!] TracerPid hook 安装失败' in entry['text']
                                       or '[!] TracerPid 处理失败' in entry['text']]
        report['native_hook_ready'] = any('[*] TracerPid hook:' in item['text'] for item in log_entries)
        report['java_hook_ready'] = any('[*] hook 已安装' in item['text'] for item in log_entries)
        if script_errors or report['script_error_logs']:
            raise RuntimeError('观察期包含脚本错误，详见完整日志')
        if args.mode in ('full', 'native-only') and not report['native_hook_ready']:
            raise RuntimeError('观察期未确认原生 hook 安装成功')
        if args.mode in ('full', 'java-only') and not report['java_hook_ready']:
            raise RuntimeError('观察期未确认 Java hook 安装成功')
        report['passed'] = True
        exit_code = 0
    except KeyboardInterrupt:
        report['failure'] = '观察由使用者中断，未完成持续存活验证'
        record('failure', report['failure'])
        exit_code = 130
    except Exception as error:
        report['failure'] = '{}: {}'.format(type(error).__name__, error)
        record('failure', report['failure'])
    finally:
        cleanup_started = True
        if session is not None:
            try:
                invoke(args.timeout, session.detach)
                report['cleanup'].append({'session_detached': True})
            except frida.InvalidOperationError as error:
                report['cleanup'].append({'session_already_detached': str(error)})
            except Exception as error:
                report['cleanup'].append({'detach_error': '{}: {}'.format(type(error).__name__, error)})
                report['passed'] = False
                exit_code = 1
        if any(not item['requested_by_harness'] for item in report['detached']) or report['crashes']:
            report['passed'] = False
            if exit_code == 0:
                exit_code = 1
                report['failure'] = '清理前后收到非主动分离或目标崩溃事件'
        if device is not None:
            for signal, callback in device_signals:
                device.off(signal, callback)
        report['finished_unix'] = time.time()
        report['stage'] = 'complete' if report['passed'] else ('needs-start' if report.get('needs_start') else 'failed')
        if watch_started is not None:
            report['attached_observation_seconds'] = round(time.monotonic() - watch_started, 6)
        save()
        stream.close()
    print('{}: mode={}, pid={}, observed={}s, report={}'.format(
        'PASS' if report['passed'] else 'FAIL', args.mode, report.get('pid'),
        report.get('watched_seconds', 0), args.output.resolve()), flush=True)
    return exit_code


if __name__ == '__main__':
    sys.exit(run(arguments()))

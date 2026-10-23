# ABOUTME: 在两只测试专用 sleep 进程中验证真实 TracerPid 及状态文件读取行为。
# ABOUTME: 记录基线、注入结果和文件语义，并清理本次创建的进程与会话。
import argparse
import json
import re
import sys
import threading
import time
from pathlib import Path

import frida


VOLATILE_FIELDS = {
    'State', 'FDSize', 'Threads', 'SigQ', 'SigPnd', 'ShdPnd', 'SigBlk',
    'SigIgn', 'SigCgt', 'voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches',
    'RssAnon', 'RssFile', 'RssShmem', 'CoreDumping',
}
TRACER_LINE = re.compile(r'^TracerPid:([ \t]*)([0-9]+)(\r?)$', re.MULTILINE)
CLOSE_RACE_ERROR = re.compile(r'^Error: close\(status 快照\).*errno=9(?:\D|$)')
CLOSE_RACE_SOURCE = r'''
rpc.exports.cleanupCloseRace = function () {
    if (typeof closeStatusFiles !== 'function') throw new Error('生产脚本缺少 closeStatusFiles');
    var realOpen = new SystemFunction(Module.getExportByName('libc.so', 'open'), 'int', ['pointer', 'int']);
    var realClose = new SystemFunction(Module.getExportByName('libc.so', 'close'), 'int', ['int']);
    var realFcntl = new SystemFunction(Module.getExportByName('libc.so', 'fcntl'), 'int', ['int', 'int', 'int']);
    var path = Memory.allocUtf8String('/dev/null');
    var first = -1, second = -1;
    var result = { cleanup: [] };
    try {
        var opened = realOpen(path, 0x80000);
        if (opened.value < 0) throw new Error('open(first) 失败, errno=' + opened.errno);
        first = opened.value;
        opened = realOpen(path, 0x80000);
        if (opened.value < 0) throw new Error('open(second) 失败, errno=' + opened.errno);
        second = opened.value;
        result.firstFd = first;
        result.secondFd = second;
        var initialClose = realClose(first);
        result.initialClose = { value: initialClose.value, errno: initialClose.errno };
        if (initialClose.value !== 0) throw new Error('close(first) 失败, errno=' + initialClose.errno);
        try {
            closeStatusFiles(realClose, first, second);
            result.error = null;
        } catch (error) {
            result.error = String(error);
        }
        var firstState = realFcntl(first, 1, 0);
        var secondState = realFcntl(second, 1, 0);
        result.firstState = { value: firstState.value, errno: firstState.errno };
        result.secondState = { value: secondState.value, errno: secondState.errno };
    } finally {
        var cleanupErrors = [];
        [first, second].forEach(function (fd) {
            if (fd < 0) return;
            var state = realFcntl(fd, 1, 0);
            if (state.value >= 0) {
                var closed = realClose(fd);
                result.cleanup.push({ fd: fd, value: closed.value, errno: closed.errno });
                if (closed.value !== 0) cleanupErrors.push('close(probe) 失败, errno=' + closed.errno);
            } else if (state.errno !== 9) {
                cleanupErrors.push('fcntl(probe) 失败, errno=' + state.errno);
            }
        });
        if (cleanupErrors.length !== 0) throw new Error(cleanupErrors.join('; '));
    }
    return result;
};
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def status_fields(text):
    return dict(line.split(':', 1) for line in text.splitlines() if ':' in line)


def stable_fields(text):
    return {
        key: value for key, value in status_fields(text).items()
        if key != 'TracerPid' and key not in VOLATILE_FIELDS and not key.startswith('Vm')
    }


def expected_stable_fields(text, hide_names):
    expected = stable_fields(text)
    if hide_names and 'Name' in expected:
        names = {
            '\tgum-js-loop': '\tpool-worker',
            '\tgmain': '\tpool0',
            '\tgdbus': '\tpool1',
        }
        expected['Name'] = names.get(expected['Name'], expected['Name'])
    return expected


def tracer_value(text):
    matches = list(TRACER_LINE.finditer(text))
    require(len(matches) == 1, 'status 必须包含且只包含一行十进制 TracerPid')
    return int(matches[0].group(2)), matches[0]


def verify_link_buffer(result, expected, capacity, label):
    require(result['guardBefore'] == 0xa5 and result['guardAfter'] == 0xa5, label + ' 越过缓冲区边界')
    require(result['tailUntouched'], label + ' 在返回内容之后写入 NUL 或改动哨兵')
    require(result['value'] == len(expected.encode('ascii')), label + ' 返回长度发生变化')
    require(result['value'] <= capacity, label + ' 返回长度超过缓冲区容量')
    require(result['text'] == expected, label + ' 链接文本不符合精确期望')


def verify_descriptor_links(result, hide_marker):
    kernel = result['kernel']
    require(kernel['value'] > 0 and 'linjector' in kernel['text'], '真实 syscall 基线缺少 linjector')
    verify_link_buffer(kernel, kernel['text'], 4096, '完整内核链接')
    for case in result['cases']:
        require(case['scope'] in ('proc-fd', 'other'), '链接案例缺少明确的作用域')
        expected_kernel = kernel['text'][:case['capacity']]
        label = case['path'] + ' ' + case['kind'] + ' capacity=' + str(case['capacity'])
        verify_link_buffer(case['kernel'], expected_kernel, case['capacity'], label + ' syscall')
        expected = expected_kernel.replace('linjector', 'cachefile') if hide_marker and case['scope'] == 'proc-fd' else expected_kernel
        verify_link_buffer(case['result'], expected, case['capacity'], label)
        if case['scope'] == 'other':
            require(not case['path'].startswith('/proc/'), '范围外案例意外指向 /proc 路径')
            require(case['result']['errno'] == case['kernel']['errno'] == case['initialErrno'], label + ' 改变了初始 errno')
    for case in result['errors']:
        for source in ('result', 'kernel'):
            error = case[source]
            require(error['value'] == -1 and error['errno'] == 2, case['kind'] + ' ENOENT 返回发生变化')
            require(error['text'] is None, case['kind'] + ' 失败时返回了链接文本')
            require(error['guardBefore'] == 0xa5 and error['guardAfter'] == 0xa5 and error['tailUntouched'], case['kind'] + ' 失败时改动了输出缓冲区')


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


def arguments():
    parser = argparse.ArgumentParser(description='在测试专用进程中验证 TracerPid hook，不启动或注入业务应用。')
    parser.add_argument('--host', default='127.0.0.1:2199')
    parser.add_argument('--script', type=Path, default=Path(__file__).resolve().parents[1] / 'hook_JniEncryptData.js')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=float, default=30.0)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--baseline', action='store_true', help='仅证明真实非零 TracerPid，跳过生产脚本加载。')
    mode.add_argument('--expect-bypass', action='store_true', help='加载生产脚本并要求所有受测路径归零；默认模式。')
    mode.add_argument('--open-before-trace', action='store_true', help='先加载生产脚本并持有状态文件，再施加真实线程跟踪。')
    mode.add_argument('--cleanup-close-race', action='store_true', help='实际提前关闭首个临时文件，验证生产清理遇到 EBADF 时仍关闭第二个文件。')
    mode.add_argument('--descriptor-links', action='store_true', help='使用真实 memfd 和内核 readlinkat 验证描述符链接文本及缓冲区语义。')
    args = parser.parse_args()
    require(args.timeout > 0, '--timeout 必须大于零')
    return args


def run(args):
    report = {
        'host': args.host,
        'mode': 'descriptor-links' if args.descriptor_links else ('cleanup-close-race' if args.cleanup_close_race else ('open-before-trace' if args.open_before_trace else ('baseline' if args.baseline else 'expect-bypass'))),
        'frida_version': frida.__version__, 'started_unix': time.time(),
        'created_pids': [], 'messages': [], 'logs': [], 'cases': [], 'cleanup': [], 'passed': False,
    }
    device = None
    sessions = []
    scripts = []
    helper_source = Path(__file__).with_suffix('.js').read_text(encoding='utf-8-sig')
    source = args.script.read_text(encoding='utf-8-sig') if not args.baseline else None

    def message_handler(label):
        def on_message(message, data):
            report['messages'].append({'script': label, 'message': message})
        return on_message

    def log_handler(label):
        def on_log(level, text):
            report['logs'].append({'script': label, 'level': level, 'text': text})
        return on_log

    def validate_logs():
        unexpected = []
        for entry in report['logs']:
            if entry['level'] in ('warning', 'error') or entry['text'].startswith(('[!]', '[x]')):
                unexpected.append(entry)
        require(not unexpected, '出现未预期的脚本错误日志: ' + json.dumps(unexpected, ensure_ascii=False))

    def create_helper(label):
        pid = invoke(args.timeout, device.spawn, ['/system/bin/sleep', '300'])
        report['created_pids'].append(pid)
        session = invoke(args.timeout, device.attach, pid)
        sessions.append(session)
        script = invoke(args.timeout, session.create_script, helper_source, name='tracerpid-' + label, runtime='duk')
        scripts.append(script)
        script.on('message', message_handler(label))
        script.set_log_handler(log_handler(label))
        invoke(args.timeout, script.load)
        info = invoke(args.timeout, script.exports.info)
        require(info['pid'] == pid, label + ' PID 与已创建的进程不一致')
        invoke(args.timeout, device.resume, pid)
        return session, script, info

    def rpc(script, name, *values):
        return invoke(args.timeout, getattr(script.exports, name), *values)

    def load_production(session):
        loaded_source = source + CLOSE_RACE_SOURCE if args.cleanup_close_race else source
        production = invoke(args.timeout, session.create_script, loaded_source, name='tracerpid-production', runtime='duk')
        scripts.append(production)
        production.on('message', message_handler('production'))
        production.set_log_handler(log_handler('production'))
        invoke(args.timeout, production.load)
        return production

    try:
        device = invoke(args.timeout, frida.get_device_manager().add_remote_device, args.host)
        target_session, target, info = create_helper('target')
        if args.descriptor_links:
            report['target'] = info
            report['descriptors_before_link_baseline'] = rpc(target, 'descriptor_count')
            baseline = rpc(target, 'descriptor_links')
            report['descriptor_links_baseline'] = baseline
            verify_descriptor_links(baseline, False)
            report['descriptors_after_link_baseline'] = rpc(target, 'descriptor_count')
            require(report['descriptors_before_link_baseline']['count'] == report['descriptors_after_link_baseline']['count'], '链接基线测试泄露文件描述符')
            production = load_production(target_session)
            report['descriptors_before_link_hooked'] = rpc(target, 'descriptor_count')
            hooked = rpc(target, 'descriptor_links')
            report['descriptor_links_hooked'] = hooked
            report['cases'] = hooked['cases'] + hooked['errors']
            report['descriptors_after_link_hooked'] = rpc(target, 'descriptor_count')
            verify_descriptor_links(hooked, True)
            require(hooked['kernel']['text'] == baseline['kernel']['text'], '加载 hook 后内核 memfd 链接意外变化')
            require(report['descriptors_before_link_hooked']['count'] == report['descriptors_after_link_hooked']['count'], '链接 hook 测试泄露文件描述符')
            validate_logs()
            require(not any(item['message'].get('type') == 'error' for item in report['messages']), '链接测试脚本出现运行时异常')
            report['passed'] = True
        else:
            _, tracer, tracer_info = create_helper('tracer')
            report['target'] = info
            report['tracer'] = tracer_info
            report['comm_before'] = rpc(target, 'read_path', '/proc/self/comm', 'open', 3)
            held_status = None
            if args.open_before_trace:
                untraced = rpc(target, 'read_path', '/proc/self/status', 'syscall', 4096)
                require(tracer_value(untraced['text'])[0] == 0, '持有文件测试的初始内核 TracerPid 必须为零')
                report['untraced'] = untraced
                load_production(target_session)
                report['descriptors_before_hold'] = rpc(target, 'descriptor_count')
                held_status = rpc(target, 'hold_status', '/proc/self/status')
                report['held_before_trace'] = held_status
            thread_ids = list(dict.fromkeys([info['pid'], info['tid']]))
            seize = rpc(tracer, 'seize', thread_ids)
            report['seize'] = seize
            require(len(seize) == len(thread_ids), 'PTRACE_SEIZE 未完成所有线程，详见 seize 的 errno')
            for item in seize:
                require(item['value'] == 0, 'PTRACE_SEIZE 失败: ' + json.dumps(item))
            tracer_tids = {item['tracerTid'] for item in seize}
            paths = [
                '/proc/self/status', '/proc/{}/status'.format(info['pid']),
                '/proc/thread-self/status', '/proc/self/task/{}/status'.format(info['tid']),
                '/proc/{}/task/{}/status'.format(info['pid'], info['tid']),
            ]
            baselines = {}
            for path in paths:
                baseline = rpc(target, 'read_path', path, 'syscall', 4096)
                actual, _ = tracer_value(baseline['text'])
                require(actual > 0 and actual in tracer_tids, '内核基线没有真实的测试 tracer: ' + path)
                baselines[path] = baseline
            report['baseline'] = baselines
            print('真实基线通过: target={}, tracer={}, traced_threads={}'.format(info['pid'], tracer_info['pid'], thread_ids), flush=True)

            if held_status is not None:
                try:
                    held_result = rpc(target, 'read_held_status', held_status['fd'], 7)
                    report['held_after_trace'] = held_result
                    held_value, held_line = tracer_value(held_result['text'])
                    require(held_value == 0, '跟踪前打开并持有的 status fd 在跟踪后泄露 TracerPid={}'.format(held_value))
                    require(stable_fields(held_result['text']) == expected_stable_fields(report['untraced']['text'], True), '持有文件中的稳定字段不符合精确期望')
                    require(len(held_line.group(2)) == len(tracer_value(report['untraced']['text'])[1].group(2)), '持有快照的 TracerPid 字节宽度发生变化')
                    require(held_result['flags'] == held_status['flags'], '持有文件的描述符标志发生变化')
                finally:
                    rpc(target, 'close_held_status', held_status['fd'])
                    report['held_closed'] = True
                report['descriptors_after_hold'] = rpc(target, 'descriptor_count')
                require(report['descriptors_before_hold']['count'] == report['descriptors_after_hold']['count'], '持有文件测试出现文件描述符泄露')
                print('跟踪前持有文件通过: 内核非零，持有 fd 仍返回零', flush=True)
            elif not args.baseline:
                production = load_production(target_session)

            report['descriptors_before_cases'] = rpc(target, 'descriptor_count')
            if args.cleanup_close_race:
                race_result = rpc(production, 'cleanup_close_race')
                report['close_race'] = race_result
                report['cases'].append({'path': '/dev/null', 'kind': 'cleanup-close-race', 'result': race_result})
                report['descriptors_after_probe'] = rpc(target, 'descriptor_count')
                require(race_result['initialClose']['value'] == 0, '首个临时文件未实际成功提前关闭')
                require(race_result['error'] is not None and CLOSE_RACE_ERROR.search(race_result['error']), '未准确捕获生产清理产生的 close(status 快照) errno=9 异常')
                require(race_result['firstState']['value'] == -1 and race_result['firstState']['errno'] == 9, '首个临时文件并未保持关闭状态')
                require(race_result['secondState']['value'] == -1 and race_result['secondState']['errno'] == 9, '生产清理在首个 close 失败后仍遗留已打开的第二个文件描述符')
                require(report['descriptors_before_cases']['count'] == report['descriptors_after_probe']['count'], '真实清理回归出现文件描述符泄露')

            variants = [
                ('open', 4096), ('open', 1), ('open', 7), ('openat', 13),
                ('openat-relative', 17), ('dup', 7), ('pread', 3),
                ('fgets', 2), ('fgets', 11), ('fread', 17),
            ]
            for path in ([] if args.cleanup_close_race else paths):
                for kind, chunk in variants:
                    result = rpc(target, 'read_path', path, kind, chunk)
                    case = {'path': path, 'kind': kind, 'chunk': chunk, 'result': result}
                    report['cases'].append(case)
                    expected_fields = expected_stable_fields(baselines[path]['text'], not args.baseline)
                    case['raw_name'] = stable_fields(baselines[path]['text']).get('Name')
                    case['expected_name'] = expected_fields.get('Name')
                    actual, tracer_line = tracer_value(result['text'])
                    baseline_tracer, baseline_line = tracer_value(baselines[path]['text'])
                    require(actual == baseline_tracer if args.baseline else actual == 0,
                            '{} {} 返回 TracerPid={}，期望 {}'.format(path, kind, actual, baseline_tracer if args.baseline else 0))
                    require(result['length'] == len(result['text'].encode('ascii')), '返回的长度不符合实际 ASCII 字节数')
                    require(sum(result['lengths']) == result['length'], '分块长度之和与总长度不一致')
                    require(all(0 < count <= (chunk - 1 if kind == 'fgets' else chunk) for count in result['lengths']), '分块读取长度不符合接口约束')
                    require(stable_fields(result['text']) == expected_fields, '稳定字段不符合仅允许指定 Name 变化的精确期望: ' + path)
                    require(tracer_line.group(1) == baseline_line.group(1), 'TracerPid 字段空白发生变化')
                    require(len(tracer_line.group(2)) == len(baseline_line.group(2)), 'TracerPid 数字字节宽度发生变化')
                    flags = result['flags']
                    require(flags['status'] & 3 == 0, '只读文件的访问模式发生变化')
                    require(flags['descriptor'] & 1 == (0 if kind == 'dup' else 1), 'FD_CLOEXEC 语义发生变化: ' + kind)
                    if kind not in ('fgets', 'fread'):
                        require(flags['status'] & 0x800 == 0x800, 'O_NONBLOCK 标志丢失')
                raw = rpc(target, 'read_path', path, 'syscall', 31)
                raw_value, _ = tracer_value(raw['text'])
                require(raw_value in tracer_tids and raw_value > 0, '直接 syscall 的内核 TracerPid 意外归零')
                require(stable_fields(raw['text']) == stable_fields(baselines[path]['text']), '直接 syscall 的真实 Name 或其他稳定字段发生变化: ' + path)
                report.setdefault('kernel_after', {})[path] = raw
                print('读取路径通过: ' + path, flush=True)

            if not args.cleanup_close_race:
                semantics = rpc(target, 'file_semantics', '/proc/self/status')
                report['file_semantics'] = semantics
                require(semantics['seek'] == 7, 'lseek 返回偏移错误')
                require(semantics['seekCount'] == 19 and semantics['seekText'] == semantics['text'][7:26], 'lseek 后读取内容错误')
                require(semantics['preadCount'] == 19 and semantics['preadText'] == semantics['text'][7:26], 'pread 偏移读取内容错误')
                require(semantics['positionBefore'] == semantics['positionAfter'], 'pread 改变了文件偏移')
                if not args.baseline:
                    require(semantics['rereadText'] == semantics['text'], '同一快照 seek 回零后内容不一致')

                errors = rpc(target, 'errors')
                report['errors'] = errors
                for kind in ('open', 'openat'):
                    require(errors[kind]['value'] == -1 and errors[kind]['errno'] == 2, kind + ' 的失败返回或 ENOENT 发生变化')
                require(errors['fopen']['isNull'] and errors['fopen']['errno'] == 2, 'fopen 的失败返回或 ENOENT 发生变化')
                report['comm_after'] = rpc(target, 'read_path', '/proc/self/comm', 'open', 3)
                require(report['comm_after']['text'] == report['comm_before']['text'], '普通 /proc/self/comm 内容发生变化')
            report['descriptors_after_cases'] = rpc(target, 'descriptor_count')
            validate_logs()
            require(report['descriptors_before_cases']['count'] == report['descriptors_after_cases']['count'], '读取测试出现文件描述符泄露')
            script_errors = [item for item in report['messages'] if item['message'].get('type') == 'error']
            require(not script_errors, '脚本发生运行时异常: ' + json.dumps(script_errors, ensure_ascii=False))
            report['passed'] = True
    except Exception as error:
        report['failure'] = '{}: {}'.format(type(error).__name__, error)
    finally:
        if device is not None:
            for pid in reversed(report['created_pids']):
                try:
                    invoke(args.timeout, device.kill, pid)
                    report['cleanup'].append({'pid': pid, 'killed': True})
                except frida.ProcessNotFoundError:
                    report['cleanup'].append({'pid': pid, 'already_exited': True})
                except Exception as error:
                    report['cleanup'].append({'pid': pid, 'error': '{}: {}'.format(type(error).__name__, error)})
                    report['passed'] = False
        for session in reversed(sessions):
            try:
                invoke(args.timeout, session.detach)
            except (frida.InvalidOperationError, frida.ProcessNotFoundError):
                pass
            except Exception as error:
                report['cleanup'].append({'detach_error': '{}: {}'.format(type(error).__name__, error)})
                report['passed'] = False
        report['finished_unix'] = time.time()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('报告: ' + str(args.output.resolve()), flush=True)
    if report['passed']:
        print('PASS: {}，{} 个真实接口读取案例，测试进程已清理'.format(report['mode'], len(report['cases'])), flush=True)
        return 0
    print('FAIL: ' + report.get('failure', '清理步骤失败'), file=sys.stderr, flush=True)
    if not args.output:
        print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr, flush=True)
    return 1


if __name__ == '__main__':
    sys.exit(run(arguments()))

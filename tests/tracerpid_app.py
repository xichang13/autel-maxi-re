# ABOUTME: 在当前运行的目标应用中验证脚本加载、字节工具与类加载器恢复。
# ABOUTME: 使用真实 Java 环境并保存日志，结束时仅分离会话而不终止应用。
import argparse
import json
import sys
import threading
import time
from pathlib import Path

import frida


PROBE = r'''
// ABOUTME: 在应用真实 Java 运行时检查类加载失败后的状态恢复。
// ABOUTME: 保留并恢复测试触及的目标类、缓存和类加载器状态。
rpc.exports.ready = function () { return Java.available; };
rpc.exports.verify = function () {
    return new Promise(function (resolve, reject) {
        Java.performNow(function () {
            var savedClass = _cachedClass, savedTarget = TARGET_CLASS;
            var savedLoader = Java.classFactory.loader;
            try {
                var hookReady = _cachedClass !== null;
                Java.classFactory.loader = null;
                var before = Java.classFactory.loader;
                _cachedClass = null;
                TARGET_CLASS = 'com.autel.test.AbsentTracerPidClass';
                var absent = resolveClass();
                var after = Java.classFactory.loader;
                var restored = before === null ? after === null : (after !== null && before.equals(after));
                var array = hexToJbyteArray('00 7f 80 ff');
                var converted = [];
                for (var i = 0; i < array.length; i++) converted.push(array[i]);
                resolve({
                    javaAvailable: Java.available,
                    arch: Process.arch,
                    nativeHooks: _tracerPidHooks === null ? 0 : _tracerPidHooks.length,
                    encryptionHookReady: hookReady,
                    absentClass: absent === null,
                    loaderRestored: restored,
                    loaderBefore: before === null ? null : String(before),
                    loaderAfter: after === null ? null : String(after),
                    bytes: converted,
                    dump: dumpHex(array),
                    oracleAvailable: typeof callEnc === 'function'
                });
            } catch (error) {
                reject(String(error));
            } finally {
                TARGET_CLASS = savedTarget;
                _cachedClass = savedClass;
                Java.classFactory.loader = savedLoader;
            }
        });
    });
};
'''


def invoke(operation, *args, **kwargs):
    cancellation = frida.Cancellable()
    timer = threading.Timer(30, cancellation.cancel)
    timer.daemon = True
    timer.start()
    try:
        with cancellation:
            return operation(*args, **kwargs)
    finally:
        timer.cancel()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1:2199')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--spawn', action='store_true')
    parser.add_argument('--java-helper', action='store_true')
    args = parser.parse_args()
    report = {'passed': False, 'logs': [], 'messages': []}
    session = None
    suspended = False
    created = False
    ready = threading.Event()

    def output(pid, descriptor, data):
        text = data.decode('utf-8', errors='replace')
        report.setdefault('output', []).append({'pid': pid, 'descriptor': descriptor, 'text': text})
        if 'TRACERPID_JAVA_READY' in text:
            ready.set()
    try:
        device = invoke(frida.get_device_manager().add_remote_device, args.host)
        processes = [item for item in invoke(device.enumerate_processes) if item.name == 'com.autel.update']
        if args.java_helper:
            device.on('output', output)
            report['pid'] = invoke(device.spawn, ['/system/bin/app_process64',
                '-Djava.class.path=/data/local/tmp/tracerpid-StatusProbe.jar', '/system/bin', 'autel.test.StatusProbe'], stdio='pipe')
            created = True
            invoke(device.resume, report['pid'])
            if not ready.wait(10):
                raise AssertionError('独立 Java 测试进程未到达 main')
        elif args.spawn:
            if processes:
                raise AssertionError('spawn 测试要求主进程未运行，避免重启现有应用')
            report['pid'] = invoke(device.spawn, ['com.autel.update'])
            suspended = True
        else:
            if len(processes) != 1:
                raise AssertionError('需要恰好一个正在运行的 com.autel.update 主进程')
            report['pid'] = processes[0].pid
        session = invoke(device.attach, report['pid'])
        source = (Path(__file__).resolve().parents[1] / 'hook_JniEncryptData.js').read_text(encoding='utf-8-sig')
        script = invoke(session.create_script, source + '\n' + PROBE, name='tracerpid-app-test', runtime='duk')
        script.set_log_handler(lambda level, text: report['logs'].append({'level': level, 'text': text}))
        script.on('message', lambda message, data: report['messages'].append(message))
        invoke(script.load)
        if suspended:
            invoke(device.resume, report['pid'])
            suspended = False
        deadline = time.monotonic() + 30
        while not invoke(script.exports.ready):
            if time.monotonic() >= deadline:
                raise AssertionError('Java 运行时未在期限内就绪')
            time.sleep(0.1)
        result = invoke(script.exports.verify)
        report['result'] = result
        for key in ('javaAvailable', 'absentClass', 'loaderRestored', 'oracleAvailable'):
            if not result[key]:
                raise AssertionError(key + ' 未通过')
        if result['nativeHooks'] == 0:
            raise AssertionError('没有安装原生状态文件 hook')
        if not args.java_helper and not result['encryptionHookReady']:
            raise AssertionError('目标应用的 JniEncryptData hook 未安装')
        if result['bytes'] != [0, 127, -128, -1]:
            raise AssertionError('真实 Java byte[] 转换不符合预期')
        if '00 7f 80 ff' not in result['dump']:
            raise AssertionError('字节预览内容不符合预期')
        if report['messages']:
            raise AssertionError('脚本有未预期消息，详见报告')
        expected_missing = '[x] 所有 classloader 都没有 com.autel.test.AbsentTracerPidClass (类尚未加载/不在本进程)'
        missing_logs = [item['text'] for item in report['logs'] if item['text'].startswith('[x]')]
        if missing_logs != [expected_missing]:
            raise AssertionError('类加载失败的预期诊断不符合预期')
        if any(item['level'] == 'error' or '[!] TracerPid' in item['text'] for item in report['logs']):
            raise AssertionError('脚本报告错误，详见日志')
        if not any(item.pid == report['pid'] for item in invoke(device.enumerate_processes)):
            raise AssertionError('目标进程已退出')
        report['passed'] = True
    except Exception as error:
        report['failure'] = '{}: {}'.format(type(error).__name__, error)
    finally:
        if suspended:
            try:
                invoke(device.resume, report['pid'])
            except Exception as error:
                report['resume_failure'] = str(error)
        if session is not None:
            try:
                invoke(session.detach)
            except Exception as error:
                report['detach_failure'] = '{}: {}'.format(type(error).__name__, error)
                report['passed'] = False
        if created:
            try:
                invoke(device.kill, report['pid'])
                report['helper_killed'] = True
            except Exception as error:
                report['cleanup_failure'] = str(error)
                report['passed'] = False
        report['finished_unix'] = time.time()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

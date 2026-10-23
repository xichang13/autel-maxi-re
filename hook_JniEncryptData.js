// ABOUTME: Hook/主动调用 com.autel.utils.EncryptionJni.JniEncryptData(int, byte[]):byte[]
// ABOUTME: 打印入参/返回值(hex+ascii)与Java调用栈,含SecNeo自定义classloader兜底与oracle主动调用

'use strict';

/* ============================ 配置 ============================ */
var TARGET_CLASS  = 'com.autel.utils.EncryptionJni';
var TARGET_METHOD = 'JniEncryptData';
var PREVIEW_CAP   = 1024;   // 单个 byte[] 预览的最大字节数,防刷屏
var PRINT_STACK   = true;   // 是否打印 Java 调用栈
var HIDE_TRACERPID = true;   // 是否将进程状态中的 TracerPid 归零
/* ============================================================= */

var _cachedClass = null;    // 解析到的目标类(含 classloader 兜底)
var _tracerPidHooks = null;

/* ---------- 进程状态字段与路径 ---------- */
function maskTracerPid(text) {
    return text.replace(/(^|\n)(TracerPid:[\t ]*)([0-9]+)(?=[\t ]*(?:\r?\n|$))/g,
        function (match, start, field, digits) {
            return start + field + digits.replace(/[0-9]/g, '0');
        });
}

function isProcStatusPath(path) {
    return /^\/proc\/(?:self|thread-self|[0-9]+)(?:\/task\/[0-9]+)?\/status$/.test(path);
}

/* ---------- 状态快照的临时文件清理 ---------- */
function closeStatusFiles(close, replacement, temporary) {
    function release(fd, name) {
        if (fd < 0) return;
        var result = close(fd);
        if (result.value < 0) throw new Error(name + ' 失败, errno=' + result.errno);
    }
    try {
        release(replacement, 'close(status 快照)');
    } finally {
        release(temporary, 'close(memfd)');
    }
}

/* ---------- 原生状态文件: 在 Java 就绪前安装 ---------- */
function installTracerPidBypass() {
    if (_tracerPidHooks !== null) return true;
    var listeners = [], busy = {}, reported = {}, addresses = {};
    try {
        if (Process.platform !== 'linux' || (Process.arch !== 'arm64' && Process.arch !== 'arm')) {
            throw new Error('TracerPid 处理需要 Android ARM/ARM64');
        }
        function bind(name, result, args) {
            return new SystemFunction(Module.getExportByName('libc.so', name), result, args);
        }
        function value(result, operation) {
            var n = typeof result.value === 'number' ? result.value : result.value.toNumber();
            if (n < 0) throw new Error(operation + ' 失败, errno=' + result.errno);
            return n;
        }
        var open = bind('open', 'int', ['pointer', 'int']);
        var read = bind('read', 'long', ['int', 'pointer', 'ulong']);
        var write = bind('write', 'long', ['int', 'pointer', 'ulong']);
        var close = bind('close', 'int', ['int']);
        var seek = bind('lseek', 'long', ['int', 'long', 'int']);
        var fcntl = bind('fcntl', 'int', ['int', 'int', 'int']);
        var fileno = bind('fileno', 'int', ['pointer']);
        var readlink = bind('readlink', 'long', ['pointer', 'pointer', 'ulong']);
        var duplicate = bind('dup3', 'int', ['int', 'int', 'int']);
        var memfd = bind('syscall', 'long', ['long', 'pointer', 'uint']);
        var memfdNumber = Process.arch === 'arm64' ? 279 : 385;
        var memfdName = Memory.allocUtf8String('status');

        function replaceStatus(fd) {
            var link = Memory.alloc(4096);
            var linkResult = readlink(Memory.allocUtf8String('/proc/self/fd/' + fd), link, 4096);
            var linkLength = Number(linkResult.value);
            if (linkLength <= 0 || linkLength >= 4096) return;
            var path = Memory.readUtf8String(link, linkLength);
            if (!isProcStatusPath(path)) return;

            var flags = value(fcntl(fd, 3, 0), 'F_GETFL');
            if ((flags & 0x200000) !== 0) return;   // O_PATH 描述符不能读取内容
            var descriptorFlags = value(fcntl(fd, 1, 0), 'F_GETFD');
            var offset = value(seek(fd, 0, 1), 'lseek(SEEK_CUR)');
            var buffer = Memory.alloc(4096), text = '';
            value(seek(fd, 0, 0), 'lseek(SEEK_SET)');
            try {
                for (;;) {
                    var result = read(fd, buffer, 4096);
                    if (Number(result.value) === -1 && result.errno === 4) continue;
                    var count = value(result, 'read(status)');
                    if (count === 0) break;
                    if (text.length + count > 1024 * 1024) throw new Error('status 超过 1 MiB');
                    var bytes = new Uint8Array(Memory.readByteArray(buffer, count));
                    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
                }
            } finally {
                value(seek(fd, offset, 0), 'lseek(恢复偏移)');
            }
            var masked = maskTracerPid(text);
            if (text.length === 0) return;

            var temporary = -1, replacement = -1;
            try {
                temporary = value(memfd(memfdNumber, memfdName, 1), 'memfd_create');
                var data = new Uint8Array(masked.length);
                for (var j = 0; j < masked.length; j++) data[j] = masked.charCodeAt(j);
                var contents = Memory.alloc(data.length);
                Memory.writeByteArray(contents, data.buffer);
                for (var written = 0; written < data.length;) {
                    var output = write(temporary, contents.add(written), data.length - written);
                    if (Number(output.value) === -1 && output.errno === 4) continue;
                    var size = value(output, 'write(status)');
                    if (size === 0) throw new Error('write(status) 未写入数据');
                    written += size;
                }
                // ARM 的 O_NOFOLLOW 为 0x8000; 重开 proc fd 链接需要跟随符号链接。
                replacement = value(open(Memory.allocUtf8String('/proc/self/fd/' + temporary),
                    (flags & ~0x8000) | 0x80000), 'open(status 快照)');
                value(seek(replacement, offset, 0), 'lseek(status 快照)');
                // dup3 原子保留目标编号和 FD_CLOEXEC, 原描述符仅在准备成功后替换。
                value(duplicate(replacement, fd, (descriptorFlags & 1) ? 0x80000 : 0), 'dup3(status)');
                if (masked !== text && !reported[path]) {
                    reported[path] = true;
                    console.log('[*] TracerPid 已归零: ' + path);
                }
            } finally {
                closeStatusFiles(close, replacement, temporary);
            }
        }

        function attach(name, stream) {
            var address = Module.findExportByName('libc.so', name);
            if (address === null || addresses[address.toString()]) return;
            var listener = Interceptor.attach(address, {
                onLeave: function (retval) {
                    var savedErrno = this.errno;
                    if (busy[this.threadId]) return;
                    busy[this.threadId] = true;
                    try {
                        var fd = stream ? (retval.isNull() ? -1 : value(fileno(retval), 'fileno')) : retval.toInt32();
                        if (fd >= 0) replaceStatus(fd);
                    } catch (e) {
                        var key = 'error:' + e;
                        if (!reported[key]) {
                            reported[key] = true;
                            console.log('[!] TracerPid 处理失败: ' + e);
                        }
                    } finally {
                        delete busy[this.threadId];
                        this.errno = savedErrno;
                    }
                }
            });
            addresses[address.toString()] = true;
            listeners.push(listener);
            console.log('[*] TracerPid hook: ' + name);
        }
        ['open', 'open64', '__open_2', 'openat', 'openat64', '__openat_2'].forEach(function (name) {
            attach(name, false);
        });
        ['fopen', 'fopen64'].forEach(function (name) { attach(name, true); });
        if (listeners.length === 0) throw new Error('没有可用的状态文件打开接口');
        _tracerPidHooks = listeners;
        return true;
    } catch (e) {
        listeners.forEach(function (listener) { listener.detach(); });
        console.log('[!] TracerPid hook 安装失败: ' + e);
        return false;
    }
}

/* ---------- byte[] -> hex + ascii ---------- */
function dumpHex(bytes) {
    if (bytes === null || bytes === undefined) return '<null>';
    var len = bytes.length, hex = [], ascii = [];
    var cap = Math.min(len, PREVIEW_CAP);
    for (var i = 0; i < cap; i++) {
        var b = bytes[i] & 0xff;
        hex.push(('0' + b.toString(16)).slice(-2));
        ascii.push((b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.');
    }
    var more = len > cap ? ' ...(共 ' + len + ' 字节, 仅显示前 ' + cap + ')' : '';
    return 'len=' + len + more + '\n    hex  : ' + hex.join(' ') + '\n    ascii: ' + ascii.join('');
}

/* ---------- hex 字符串 -> Java byte[] (供主动调用用) ---------- */
function hexToJbyteArray(hex) {
    hex = (hex || '').replace(/[^0-9a-fA-F]/g, '');
    if (hex.length % 2 !== 0) throw new Error('hex 长度必须为偶数');
    var n = hex.length / 2, js = [];
    for (var i = 0; i < n; i++) {
        var v = parseInt(hex.substr(i * 2, 2), 16);
        js.push(v > 127 ? v - 256 : v);   // Java byte 是有符号的
    }
    return Java.array('byte', js);
}

/* ---------- Java 调用栈 ---------- */
function javaStack() {
    try {
        return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new());
    } catch (e) { return '<stack unavailable: ' + e + '>'; }
}

/* ---------- 解析目标类:默认 loader -> 遍历所有 classloader ---------- */
function resolveClass() {
    if (_cachedClass) return _cachedClass;
    try {
        _cachedClass = Java.use(TARGET_CLASS);
        console.log('[*] 默认 classloader 命中 ' + TARGET_CLASS);
        return _cachedClass;
    } catch (e) {
        console.log('[!] 默认 classloader 未找到, 遍历所有 classloader...');
    }
    var loaders = Java.enumerateClassLoadersSync();
    for (var i = 0; i < loaders.length; i++) {
        var f = Java.classFactory, loader = f.loader;
        try {
            f.loader = loaders[i];
            var c = f.use(TARGET_CLASS);
            _cachedClass = c;
            console.log('[*] 在 classloader[' + i + '] 命中: ' + loaders[i]);
            return _cachedClass;
        } catch (e) { /* 该 loader 没有, 继续 */ }
        finally { f.loader = loader; }
    }
    console.log('[x] 所有 classloader 都没有 ' + TARGET_CLASS + ' (类尚未加载/不在本进程)');
    return null;
}

/* ---------- 安装 hook ---------- */
function installHook() {
    var C = resolveClass();
    if (!C) return false;
    var overloads = C[TARGET_METHOD].overloads;
    console.log('[*] ' + TARGET_CLASS + '.' + TARGET_METHOD + ' overload 数量=' + overloads.length);
    overloads.forEach(function (ov, idx) {
        var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', ');
        console.log('    [overload#' + idx + '] args=(' + sig + ') ret=' + ov.returnType.className);
        ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            console.log('\n================ JniEncryptData 调用 ================');
            for (var i = 0; i < args.length; i++) {
                var cn = ov.argumentTypes[i] ? ov.argumentTypes[i].className : '?';
                if (cn === '[B') console.log('  arg[' + i + '] (byte[]) ' + dumpHex(args[i]));
                else             console.log('  arg[' + i + '] (' + cn + ') = ' + args[i]);
            }
            var ret = ov.apply(this, args);
            console.log('  --> return (' + ov.returnType.className + ') ' +
                (ov.returnType.className === '[B' ? dumpHex(ret) : ret));
            if (PRINT_STACK) console.log('  调用栈:\n' + javaStack());
            console.log('====================================================\n');
            return ret;
        };
    });
    return true;
}

/* ---------- 主动调用(oracle): 在 frida REPL 里直接敲 callEnc(flag, "00112233") ---------- */
function callEnc(flag, hex) {
    Java.perform(function () {
        var C = resolveClass();
        if (!C) { console.log('类未找到, 无法主动调用'); return; }
        try {
            var arr = hexToJbyteArray(hex);
            var r = C[TARGET_METHOD](flag, arr);
            console.log('\n[主动调用] JniEncryptData(' + flag + ', "' + hex + '") =>');
            console.log('  ' + dumpHex(r));
        } catch (e) { console.log('主动调用失败: ' + e); }
    });
}
// 暴露给 REPL。frida 12.11.12 用 Duktape 引擎, 没有 globalThis,
// 用 Function('return this')() 取全局对象(Duktape/V8 通用)。顶层函数名在 REPL 里通常也能直接敲。
try {
    var _g = Function('return this')();
    _g.callEnc = callEnc;
    _g.dumpHex = dumpHex;
} catch (e) { console.log('[!] 暴露全局函数失败(可忽略, REPL 里直接敲 callEnc 即可): ' + e); }

/* ---------- 入口 ---------- */
if (HIDE_TRACERPID) installTracerPidBypass();
if (Java.available) Java.perform(function () {
    var ok = installHook();
    console.log(ok ? '[*] hook 已安装, 等待 JniEncryptData 被调用...'
                   : '[*] hook 未安装(类未加载)。可在相关业务触发后重新运行, 或用 callEnc 主动调用。');
    console.log('[*] 提示: 在 REPL 里可主动调用, 例如  callEnc(1, "0102030405")');
});

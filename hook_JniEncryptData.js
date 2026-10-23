// ABOUTME: Hook/主动调用 com.autel.utils.EncryptionJni.JniEncryptData(int, byte[]):byte[]
// ABOUTME: 打印入参/返回值(hex+ascii)与Java调用栈,含SecNeo自定义classloader兜底与oracle主动调用

'use strict';

/* ============================ 配置 ============================ */
var TARGET_CLASS  = 'com.autel.utils.EncryptionJni';
var TARGET_METHOD = 'JniEncryptData';
var PREVIEW_CAP   = 1024;   // 单个 byte[] 预览的最大字节数,防刷屏
var PRINT_STACK   = true;   // 是否打印 Java 调用栈
/* ============================================================= */

var _cachedClass = null;    // 解析到的目标类(含 classloader 兜底)

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
        try {
            var f = Java.classFactory, old = f.loader;
            f.loader = loaders[i];
            var c = f.use(TARGET_CLASS);
            _cachedClass = c;
            console.log('[*] 在 classloader[' + i + '] 命中: ' + loaders[i]);
            f.loader = old;
            return _cachedClass;
        } catch (e) { /* 该 loader 没有, 继续 */ }
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
Java.perform(function () {
    var ok = installHook();
    console.log(ok ? '[*] hook 已安装, 等待 JniEncryptData 被调用...'
                   : '[*] hook 未安装(类未加载)。可在相关业务触发后重新运行, 或用 callEnc 主动调用。');
    console.log('[*] 提示: 在 REPL 里可主动调用, 例如  callEnc(1, "0102030405")');
});

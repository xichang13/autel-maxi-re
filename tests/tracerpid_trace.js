// ABOUTME: 记录目标应用的状态访问、退出调用和原生异常证据。
// ABOUTME: 保留真实调用和异常处理结果，定位持续附加退出的来源。
'use strict';

var traceListeners = [], traceAddresses = {}, traceBusy = {}, traceCounts = {};

function traceAddress(address) {
    var result = { address: String(address) };
    try {
        var module = Process.findModuleByAddress(address);
        if (module !== null) {
            result.module = module.name;
            result.offset = address.sub(module.base).toString();
        }
        result.symbol = String(DebugSymbol.fromAddress(address));
    } catch (error) { result.error = String(error); }
    return result;
}

function tracePath(pointer) {
    try { return Memory.readUtf8String(pointer).slice(0, 4096); }
    catch (error) { return '<不可读:' + pointer + '>'; }
}

function traceEvent(kind, invocation, fields, withStack) {
    var tid = invocation.threadId;
    if (traceBusy[tid]) return;
    traceBusy[tid] = true;
    try {
        var event = { kind: kind, tid: tid, at: Date.now(), caller: traceAddress(invocation.returnAddress), fields: fields };
        if (withStack) {
            try { event.stack = Thread.backtrace(invocation.context, Backtracer.ACCURATE).map(traceAddress); }
            catch (error) { event.stackError = String(error); }
        }
        send(event);
    } finally { delete traceBusy[tid]; }
}

function traceAttach(name, callback) {
    var address = Module.findExportByName('libc.so', name);
    if (address === null || traceAddresses[address.toString()]) return;
    traceAddresses[address.toString()] = true;
    traceListeners.push(Interceptor.attach(address, { onEnter: callback }));
}

['exit', '_exit', '_Exit', 'quick_exit', 'abort', 'raise', 'kill', 'tgkill', 'pthread_kill', 'ptrace'].forEach(function (name) {
    traceAttach(name, function (args) {
        traceEvent(name, this, { first: args[0].toString(), second: args[1].toString(), third: args[2].toString() }, true);
    });
});

['open', 'open64', '__open_2', 'fopen', 'fopen64', 'opendir', 'readlink'].forEach(function (name) {
    traceAttach(name, function (args) {
        var path = tracePath(args[0]);
        if (path.indexOf('/proc/') !== 0 && !/^(maps|status|comm|stat)$/.test(path)) return;
        var key = name + ':' + path + ':' + this.returnAddress;
        traceCounts[key] = (traceCounts[key] || 0) + 1;
        if (traceCounts[key] <= 3) traceEvent(name, this, { path: path, count: traceCounts[key] }, true);
    });
});

['openat', 'openat64', '__openat_2', 'readlinkat'].forEach(function (name) {
    traceAttach(name, function (args) {
        var path = tracePath(args[1]);
        if (path.indexOf('/proc/') !== 0 && !/^(maps|status|comm|stat)$/.test(path)) return;
        var key = name + ':' + path + ':' + this.returnAddress;
        traceCounts[key] = (traceCounts[key] || 0) + 1;
        if (traceCounts[key] <= 3) traceEvent(name, this, { path: path, dirfd: args[0].toInt32(), count: traceCounts[key] }, true);
    });
});

traceAttach('syscall', function (args) {
    if (Process.arch !== 'arm64') return;
    var number = args[0].toInt32();
    if ([56, 93, 94, 117, 129, 131, 167].indexOf(number) === -1) return;
    var fields = { number: number, first: args[1].toString(), second: args[2].toString(), third: args[3].toString() };
    if (number === 56) {
        fields.path = tracePath(args[2]);
        if (fields.path.indexOf('/proc/') !== 0) return;
    }
    traceEvent('syscall', this, fields, true);
});

Process.setExceptionHandler(function (details) {
    var event = { kind: 'exception', type: details.type, address: traceAddress(details.address), at: Date.now(), tid: Process.getCurrentThreadId(), registers: {} };
    ['pc', 'sp', 'lr', 'x0', 'x1', 'x2', 'x8', 'x19', 'x20', 'x21', 'x22', 'x23', 'fp'].forEach(function (name) {
        if (details.context[name] !== undefined) event.registers[name] = String(details.context[name]);
    });
    if (details.memory) event.memory = { operation: details.memory.operation, address: String(details.memory.address) };
    send(event);
    return false;
});

send({ kind: 'trace-ready', pid: Process.id, version: Frida.version, modules: Process.enumerateModulesSync().map(function (module) {
    return { name: module.name, base: String(module.base), size: module.size, path: module.path };
}) });

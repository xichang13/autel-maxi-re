// ABOUTME: 通过真实 libc 和内核调用检查受控进程的 TracerPid 读取行为。
// ABOUTME: 为真机测试提供线程跟踪、文件读取和文件描述符语义的 RPC 接口。
'use strict';

var MAX_BYTES = 1024 * 1024;
var MAX_READS = MAX_BYTES + 1;
var AT_FDCWD = -100;
var OPEN_FLAGS = 0x80000 | 0x800;
var O_DIRECTORY = 0x4000;
var F_GETFD = 1;
var F_GETFL = 3;
var SYS_OPENAT = 56;
var SYS_READ = 63;
var bindings = {};
var heldDescriptors = {};

function native(name, result, args) {
    var address = Module.findExportByName('libc.so', name);
    if (address === null) throw new Error('缺少 libc 导出: ' + name);
    bindings[name] = address.toString();
    return new SystemFunction(address, result, args);
}

var libc = {
    open: native('open', 'int', ['pointer', 'int']),
    openat: native('openat', 'int', ['int', 'pointer', 'int']),
    close: native('close', 'int', ['int']),
    read: native('read', 'long', ['int', 'pointer', 'ulong']),
    pread: native('pread', 'long', ['int', 'pointer', 'ulong', 'long']),
    lseek: native('lseek', 'long', ['int', 'long', 'int']),
    dup: native('dup', 'int', ['int']),
    fcntl: native('fcntl', 'int', ['int', 'int', 'int']),
    fopen: native('fopen', 'pointer', ['pointer', 'pointer']),
    fclose: native('fclose', 'int', ['pointer']),
    fileno: native('fileno', 'int', ['pointer']),
    fgets: native('fgets', 'pointer', ['pointer', 'int', 'pointer']),
    fread: native('fread', 'ulong', ['pointer', 'ulong', 'ulong', 'pointer']),
    ferror: native('ferror', 'int', ['pointer']),
    ptrace: native('ptrace', 'long', ['int', 'int', 'pointer', 'pointer']),
    opendir: native('opendir', 'pointer', ['pointer']),
    readdir: native('readdir', 'pointer', ['pointer']),
    closedir: native('closedir', 'int', ['pointer']),
    errno: native('__errno', 'pointer', [])
};
var syscallAddress = Module.findExportByName('libc.so', 'syscall');
if (syscallAddress === null) throw new Error('缺少 libc 导出: syscall');
var syscallOpen = new SystemFunction(syscallAddress, 'long', ['long', 'int', 'pointer', 'int', 'int']);
var syscallRead = new SystemFunction(syscallAddress, 'long', ['long', 'int', 'pointer', 'ulong']);

function number(value) {
    return typeof value === 'number' ? value : value.toNumber();
}

function checked(result, operation) {
    var value = number(result.value);
    if (value < 0) throw new Error(operation + ' 失败: errno=' + result.errno + ', result=' + value);
    return value;
}

function checkedPointer(result, operation) {
    if (result.value.isNull()) throw new Error(operation + ' 失败: errno=' + result.errno);
    return result.value;
}

function bytes(buffer, length) {
    var data = new Uint8Array(Memory.readByteArray(buffer, length));
    var text = '';
    for (var i = 0; i < data.length; i++) text += String.fromCharCode(data[i]);
    return text;
}

function descriptorFlags(fd) {
    return {
        descriptor: checked(libc.fcntl(fd, F_GETFD, 0), 'fcntl(F_GETFD)'),
        status: checked(libc.fcntl(fd, F_GETFL, 0), 'fcntl(F_GETFL)')
    };
}

function readDescriptor(fd, chunk, useSyscall, positioned) {
    var buffer = Memory.alloc(chunk);
    var text = '';
    var lengths = [];
    for (var i = 0; i < MAX_READS; i++) {
        var result;
        if (useSyscall) result = syscallRead(SYS_READ, fd, buffer, chunk);
        else if (positioned) result = libc.pread(fd, buffer, chunk, text.length);
        else result = libc.read(fd, buffer, chunk);
        var count = checked(result, positioned ? 'pread' : 'read');
        if (count > chunk) throw new Error('读取返回长度超过缓冲区');
        if (count === 0) return { text: text, length: text.length, reads: lengths.length, lengths: lengths };
        text += bytes(buffer, count);
        lengths.push(count);
        if (text.length > MAX_BYTES) throw new Error('读取内容超过测试上限');
    }
    throw new Error('读取次数超过测试上限');
}

function openDescriptor(path, kind) {
    var pathPointer = Memory.allocUtf8String(path);
    if (kind === 'syscall') return checked(syscallOpen(SYS_OPENAT, AT_FDCWD, pathPointer, OPEN_FLAGS, 0), 'syscall(openat)');
    if (kind === 'openat') return checked(libc.openat(AT_FDCWD, pathPointer, OPEN_FLAGS), 'openat');
    if (kind === 'openat-relative') {
        var slash = path.lastIndexOf('/');
        var directory = Memory.allocUtf8String(path.slice(0, slash));
        var filename = Memory.allocUtf8String(path.slice(slash + 1));
        var dirfd = checked(libc.open(directory, O_DIRECTORY | 0x80000), 'open(directory)');
        try {
            return checked(libc.openat(dirfd, filename, OPEN_FLAGS), 'openat(relative)');
        } finally {
            checked(libc.close(dirfd), 'close(directory)');
        }
    }
    return checked(libc.open(pathPointer, OPEN_FLAGS), 'open');
}

function readStream(path, kind, chunk) {
    var stream = checkedPointer(libc.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('re')), 'fopen');
    try {
        var fd = checked(libc.fileno(stream), 'fileno');
        var flags = descriptorFlags(fd);
        var buffer = Memory.alloc(chunk);
        var text = '';
        var lengths = [];
        for (var i = 0; i < MAX_READS; i++) {
            var count;
            if (kind === 'fgets') {
                var result = libc.fgets(buffer, chunk, stream);
                if (result.value.isNull()) count = 0;
                else count = Memory.readUtf8String(buffer).length;
            } else {
                count = checked(libc.fread(buffer, 1, chunk, stream), 'fread');
            }
            if (count === 0) {
                if (checked(libc.ferror(stream), 'ferror') !== 0) throw new Error(kind + ' 遇到流错误');
                return { text: text, length: text.length, reads: lengths.length, lengths: lengths, flags: flags };
            }
            if (count > (kind === 'fgets' ? chunk - 1 : chunk)) throw new Error('流读取超过缓冲区');
            text += bytes(buffer, count);
            lengths.push(count);
            if (text.length > MAX_BYTES) throw new Error('流内容超过测试上限');
        }
        throw new Error('流读取次数超过测试上限');
    } finally {
        checked(libc.fclose(stream), 'fclose');
    }
}

function readPath(path, kind, chunk) {
    if (chunk < 1 || chunk > MAX_BYTES) throw new Error('无效的读取分块大小');
    if (kind === 'fgets') {
        if (chunk < 2) throw new Error('fgets 缓冲区至少为两个字节');
        return readStream(path, kind, chunk);
    }
    if (kind === 'fread') return readStream(path, kind, chunk);
    var fd = openDescriptor(path, kind);
    try {
        var originalFlags = descriptorFlags(fd);
        if (kind === 'dup') {
            var duplicate = checked(libc.dup(fd), 'dup');
            checked(libc.close(fd), 'close(original)');
            fd = duplicate;
        }
        var result = readDescriptor(fd, chunk, kind === 'syscall', kind === 'pread');
        result.flags = descriptorFlags(fd);
        result.originalFlags = originalFlags;
        return result;
    } finally {
        checked(libc.close(fd), 'close');
    }
}

function fileSemantics(path) {
    var fd = openDescriptor(path, 'open');
    try {
        var content = readDescriptor(fd, 4096, false, false);
        var buffer = Memory.alloc(19);
        var seek = checked(libc.lseek(fd, 7, 0), 'lseek(SEEK_SET)');
        var count = checked(libc.read(fd, buffer, 19), 'read(after seek)');
        var seekText = bytes(buffer, count);
        var positionBefore = checked(libc.lseek(fd, 0, 1), 'lseek(SEEK_CUR)');
        var preadCount = checked(libc.pread(fd, buffer, 19, 7), 'pread(offset)');
        var preadText = bytes(buffer, preadCount);
        var positionAfter = checked(libc.lseek(fd, 0, 1), 'lseek(after pread)');
        checked(libc.lseek(fd, 0, 0), 'lseek(rewind)');
        var reread = readDescriptor(fd, 7, false, false);
        return {
            text: content.text,
            length: content.length,
            seek: seek,
            seekText: seekText,
            seekCount: count,
            preadText: preadText,
            preadCount: preadCount,
            positionBefore: positionBefore,
            positionAfter: positionAfter,
            rereadText: reread.text,
            flags: descriptorFlags(fd)
        };
    } finally {
        checked(libc.close(fd), 'close(semantics)');
    }
}

function descriptorCount() {
    var directory = checkedPointer(libc.opendir(Memory.allocUtf8String('/proc/self/fd')), 'opendir(fd)');
    var descriptors = [];
    try {
        var errnoPointer = libc.errno().value;
        for (var i = 0; i < MAX_READS; i++) {
            Memory.writeS32(errnoPointer, 0);
            var result = libc.readdir(directory);
            if (result.value.isNull()) {
                if (result.errno !== 0) throw new Error('readdir(fd) 失败: errno=' + result.errno);
                descriptors.sort(function (a, b) { return a - b; });
                return { count: descriptors.length, descriptors: descriptors };
            }
            var name = Memory.readUtf8String(result.value.add(19));
            if (/^[0-9]+$/.test(name)) descriptors.push(parseInt(name, 10));
        }
        throw new Error('文件描述符目录条目超过测试上限');
    } finally {
        checked(libc.closedir(directory), 'closedir(fd)');
    }
}

rpc.exports = {
    info: function () {
        if (Process.arch !== 'arm64') throw new Error('该真机测试仅支持当前 arm64 设备，实际为 ' + Process.arch);
        return { pid: Process.id, tid: Process.getCurrentThreadId(), arch: Process.arch, pointerSize: Process.pointerSize, exports: bindings };
    },
    seize: function (threadIds) {
        var results = [];
        for (var i = 0; i < threadIds.length; i++) {
            var result = libc.ptrace(0x4206, threadIds[i], ptr(0), ptr(0));
            results.push({ target: threadIds[i], value: number(result.value), errno: result.errno, tracerTid: Process.getCurrentThreadId() });
            if (number(result.value) !== 0) break;
        }
        return results;
    },
    readPath: readPath,
    fileSemantics: fileSemantics,
    descriptorCount: descriptorCount,
    holdStatus: function (path) {
        var fd = openDescriptor(path, 'open');
        heldDescriptors[fd] = true;
        return { fd: fd, flags: descriptorFlags(fd) };
    },
    readHeldStatus: function (fd, chunk) {
        if (!heldDescriptors[fd]) throw new Error('不是本次测试持有的文件描述符: ' + fd);
        var result = readDescriptor(fd, chunk, false, false);
        result.flags = descriptorFlags(fd);
        return result;
    },
    closeHeldStatus: function (fd) {
        if (!heldDescriptors[fd]) throw new Error('不是本次测试持有的文件描述符: ' + fd);
        checked(libc.close(fd), 'close(held status)');
        delete heldDescriptors[fd];
        return true;
    },
    errors: function () {
        var missing = Memory.allocUtf8String('/proc/self/tracerpid-test-missing/status');
        var openResult = libc.open(missing, OPEN_FLAGS);
        var openatResult = libc.openat(AT_FDCWD, missing, OPEN_FLAGS);
        var fopenResult = libc.fopen(missing, Memory.allocUtf8String('re'));
        return {
            open: { value: openResult.value, errno: openResult.errno },
            openat: { value: openatResult.value, errno: openatResult.errno },
            fopen: { isNull: fopenResult.value.isNull(), errno: fopenResult.errno }
        };
    }
};

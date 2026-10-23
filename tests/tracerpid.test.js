// ABOUTME: 验证生产脚本的进程状态文本处理和路径识别。
// ABOUTME: 直接执行真实纯函数，覆盖字段边界和等长字节保持。

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '..', 'hook_JniEncryptData.js'), 'utf8');

function loadFunction(name) {
    const definition = source.match(new RegExp('^function ' + name + '\\([^\\n]*\\) \\{[\\s\\S]*?^\\}', 'm'));
    assert.ok(definition, '生产脚本应提供 ' + name);
    return vm.runInNewContext('(' + definition[0] + ')');
}

test('进程状态中的非零追踪者归零并保持字节长度及相邻字段', function () {
    const mask = loadFunction('maskTracerPid');
    const input = 'Name:\tcom.autel.update\nState:\tt (tracing stop)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\nTracerPid:\t98765\nUid:\t1000\t1000\t1000\t1000\n';
    const expected = input.replace('TracerPid:\t98765', 'TracerPid:\t00000');
    assert.equal(mask(input), expected);
    assert.equal(Buffer.byteLength(mask(input)), Buffer.byteLength(input));
    assert.equal(mask(mask(input)), expected);
});

test('处理单行、首尾字段、空格及不同数字宽度', function () {
    const mask = loadFunction('maskTracerPid');
    const cases = [
        ['TracerPid:\t1', 'TracerPid:\t0'],
        ['TracerPid: 1234567890\n', 'TracerPid: 0000000000\n'],
        ['TracerPid:\t0\n', 'TracerPid:\t0\n'],
        ['TracerPid:42\r\n', 'TracerPid:00\r\n'],
        ['Pid:\t1\nTracerPid: \t 23 \t\nName:\tx\n', 'Pid:\t1\nTracerPid: \t 00 \t\nName:\tx\n'],
        ['TracerPid:1\nTracerPid:22\n', 'TracerPid:0\nTracerPid:00\n']
    ];
    cases.forEach(function (pair) { assert.equal(mask(pair[0]), pair[1]); });
});

test('不改动非字段、无效字段及任意其他字节', function () {
    const mask = loadFunction('maskTracerPid');
    const cases = ['', 'Name:\tTracerPid: 123\n', 'OtherTracerPid: 123\n', ' TracerPid: 123\n',
        'tracerpid: 123\n', 'TracerPid: -123\n', 'TracerPid: abc\n', 'TracerPid: 123x\n',
        'TracerPid:\n', 'TracerPid: 123\x00\n', '\xff\x80\x00\nName:\t\xe4\xb8\xad\n'];
    cases.forEach(function (input) { assert.equal(mask(input), input); });
    assert.equal(mask('\xff\x80\x00\nTracerPid:\t123\n'), '\xff\x80\x00\nTracerPid:\t000\n');
});

test('识别进程及线程状态文件', function () {
    const isStatus = loadFunction('isProcStatusPath');
    ['/proc/self/status', '/proc/thread-self/status', '/proc/1234/status',
        '/proc/self/task/5678/status', '/proc/1234/task/5678/status'].forEach(function (file) {
        assert.equal(isStatus(file), true, file);
    });
});

test('拒绝无关文件及伪造的状态文件路径', function () {
    const isStatus = loadFunction('isProcStatusPath');
    ['', '/data/local/tmp/status', '/proc/self/maps', '/proc/self/comm', '/proc/stat',
        '/proc/self/status.bak', '/proc/self/status/extra', '/proc/abc/status',
        '/proc/123/task/abc/status', '/proc/123/task/456/comm', '/tmp/proc/123/status'].forEach(function (file) {
        assert.equal(isStatus(file), false, file);
    });
});

// ABOUTME: 提供仅加载脚本而不安装 hook 的真机注入对照。
// ABOUTME: 输出实际进程与运行时版本，供退出时序比较。
'use strict';
send({ kind: 'empty-script-control-ready', pid: Process.id, version: Frida.version });

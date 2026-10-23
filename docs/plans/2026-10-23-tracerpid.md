# TracerPid Implementation Plan

> **For Codex:** 按系统化调试和 TDD 顺序执行，在当前已授权的 WIP 分支完成并审查。

**Goal:** 在 `com.autel.update` 读取进程状态时将 `TracerPid` 数值归零，保留加密函数 hook 和主动调用功能。

**Architecture:** 在 Java 就绪前拦截 libc 的状态文件打开接口。对实际成功打开的 `/proc/.../status` 描述符读取完整内容，仅将 `TracerPid` 十进制数字替换为等长的零；用匿名内存文件替换该描述符，使分块读取、stdio、pread、seek 和 dup 都读取同一份内容。保留访问模式、描述符标志和 errno。使用实际部署的 Frida 12.11.12/Duktape API。

**Tech Stack:** ES5、Frida 12.11.12、Android 10/Bionic、Node 原生测试、Python 3.8 真机测试。

## 调查证据

- 原脚本没有任何原生状态文件处理，Java.perform 内才安装加密 hook。
- `libDexHelper.so` 导入 open/read/fopen/fgets/ptrace，但没有实际 TracerPid 命中记录；历史 SIGSEGV 的具体机制仍未确认。
- 设备 5657d281 在线，Linux 4.14.163、Android 10、arm64，Frida 服务监听自定义端口 2199。
- Java.classFactory.loader 在失败分支存在状态泄漏，须在 finally 恢复，并用实际 Java 环境验证可行性。

## Task 1：失败测试

**Files:** `tests/tracerpid.test.js`、`tests/tracerpid_device.py`、`tests/tracerpid_device.js`。

1. 对生产脚本的真实纯函数测试完整状态文件、数字宽度、换行、字段边界、无关内容和路径分类；不模拟 Frida API。
2. 运行 `node --test tests/tracerpid.test.js`，确认因缺失状态处理而失败。
3. 真机创建两只隔离的 sleep，通过真实 PTRACE_SEIZE 制造非零 TracerPid。先记录原始值，再对生产脚本进行实际 libc 读取验证。清理范围仅限测试创建的进程。

## Task 2：原生状态处理

**Files:** `hook_JniEncryptData.js`。

1. 添加 `maskTracerPid(text)` 与 `isProcStatusPath(path)`；保留长度、其他字段与任意字节。
2. 安装 open/openat 与 fopen 的实际导出 hook，同地址别名只安装一次；通过 readlink 识别成功打开的真实文件。
3. 保存原始偏移和标志，完整读取原文件；失败时恢复偏移并报告，不替换。
4. 通过 Android 对应架构的 memfd_create syscall 创建匿名文件，完整写入等长内容，以原访问模式重开后替换描述符，并恢复标志与 errno；关闭所有临时描述符。
5. 在 Java.perform 之前同步安装；在 Java.available 为假时仍可独立验证原生功能。
6. 通过 finally 恢复临时 classloader 状态。

## Task 3：验证与交付

1. 运行 Node 测试和 `node --check hook_JniEncryptData.js`。
2. 运行真机测试，检查 read/fgets/pread/seek/dup、相对 openat、多个进程/线程路径和文件标志。
3. 在实际应用上验证可行范围；如崩溃，记录具体证据，不将纯函数或隔离进程测试冒充应用验证。
4. 独立审查差异，修正有证据的问题并重复相关测试。
5. 更新清单/日志，显式 git add 相关文件并提交。

## 验证边界

直接内联 syscall 的 openat 会绕过 libc hook；脚本无法改变脚本注入前内核观察到的 ptrace 状态，也不能自动处理外部未注入监控进程。匿名文件是在打开时形成的状态快照，反映该次打开时的内容。以上边界须随实际验证结果报告。

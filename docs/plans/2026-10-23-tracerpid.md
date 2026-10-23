# TracerPid Implementation Plan

> **For Codex:** 按系统化调试和 TDD 顺序执行，在当前已授权的 WIP 分支完成并审查。

**Goal:** 在 `com.autel.update` 读取进程状态时将 `TracerPid` 数值归零，保留加密函数 hook 和主动调用功能。

**Architecture:** 在 Java 就绪前拦截 libc 的状态文件打开接口。对实际成功打开的 `/proc/.../status` 描述符读取完整内容，将 `TracerPid` 十进制数字替换为等长的零；用匿名内存文件替换该描述符，使分块读取、stdio、pread、seek 和 dup 都读取同一份内容。保留访问模式、描述符标志和 errno。使用部署环境的 Frida 12 系列/Duktape API。

状态处理还按已确认的防护条件，等长替换 Name 行的 gum-js-loop/gmain/gdbus。对 `/proc/.../fd/<数字>` 的 readlink/readlinkat 有效返回字节，将 linjector 等长处理为 cachefile；其他链接、返回长度、errno 与终止方式保持原样。服务端实际为 12.11.1，客户端为 12.11.12。

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

## 复现命令

当前设备服务端实际为 Frida 12.11.1，客户端为 12.11.12，设备端口为 9527。

```powershell
adb -s 5657d281 forward tcp:2199 tcp:9527
node --test tests/tracerpid.test.js
node --check hook_JniEncryptData.js
python tests/tracerpid_device.py --expect-bypass --output logs/tracerpid-device-green.json
python tests/tracerpid_device.py --open-before-trace --output logs/tracerpid-device-open-before-green.json
python tests/tracerpid_device.py --cleanup-close-race --output logs/tracerpid-device-close-race-green.json
python tests/tracerpid_app.py --output logs/tracerpid-app-green.json
```

应用检查要求 `com.autel.update` 主进程已经运行，只附加该进程并在结束时分离。`--spawn` 为 Frida 的包启动诊断选项；该包没有 LAUNCHER 入口，当前环境的默认启动会报告 front-door activity 不存在，不作为通过条件。

独立 Java 运行时检查可按以下方式复现；必须等待 Java main 的实际就绪信号后再附加，避免在虚拟机初始化过程中调用 JNI。

```powershell
New-Item -ItemType Directory -Path tests/build/java -Force
javac --release 17 -d tests/build/java tests/StatusProbe.java
C:\AndroidSDK\build-tools\36.0.0\d8.bat --min-api 29 --output tests/build/StatusProbe.jar tests/build/java/autel/test/StatusProbe.class
adb -s 5657d281 push tests/build/StatusProbe.jar /data/local/tmp/tracerpid-StatusProbe.jar
python tests/tracerpid_app.py --java-helper --output logs/tracerpid-java-green.json
```

专用 native/Java 测试均清理自己创建的进程。`--cleanup-close-race` 使用真实关闭后的 FD 和真实 fcntl/close 返回值，验证首个关闭失败时仍释放第二个 FD；不模拟系统调用结果。ARM32 分支尚未真机验证。实际加密业务调用不属于本次已执行的检查。

## 持续附加及描述符回归

```powershell
python tests/tracerpid_device.py --host 127.0.0.1:9527 --descriptor-links --output logs/tracerpid-descriptor-links-scope-green.json
python tests/tracerpid_watch.py --mode full --duration 60 --output logs/tracerpid-watch-full-green.json
frida -H 127.0.0.1:9527 -n com.autel.update -l hook_JniEncryptData.js
```

watch 默认连接主机 9527，要求应用主进程已运行，仅附加一次，不在退出后重附加。通过要求同一 PID 持续存活、原生/Java hook 就绪、无崩溃和非主动分离。诊断可附加 `--diagnostic tests/tracerpid_trace.js`，只记录真实访问、退出调用和异常，不阻止退出；正式通过记录不加载诊断脚本。

本轮正式 watch 已通过 60.063 秒，原 CLI 命令另通过同 PID 202.327 秒。描述符测试 111 项包含 105 个 proc-fd 正常案例、3 个 ENOENT 和 3 个普通链接范围外负例；状态回归仍要求其他稳定字段不变，仅允许定义好的线程名称映射。

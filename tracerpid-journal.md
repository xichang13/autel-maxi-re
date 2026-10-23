# TracerPid 工作日志

## 2026-10-23：授权与基线

- Chang 授权初始化 Git、建立 WIP 分支，并仅跟踪本次相关文件；允许用本地文件代替不可用的 TodoWrite/journal 工具。
- 当前分支为 `wip/tracerpid`。其他 APK、DEX、反编译目录和历史工具不纳入本次提交。
- `hook_JniEncryptData.js` 原始内容仅安装 Java 加密方法 hook，没有处理 `/proc/.../status` 或 `TracerPid`。
- 原脚本明确面向 Frida 12.11.12/Duktape，新增代码须遵循该实际运行约束。
- 全局 Git 没有提交身份；本任务通过每次提交的 `-c user.name=Codex -c user.email=codex@local` 标明代理身份，不修改用户全局配置。
- 正在并行只读检查检测证据与可用测试环境；尚未修改生产脚本。

## 文本处理的 TDD

- 新增测试后，`node --test tests/tracerpid.test.js` 首次运行 5 项全部按预期失败，原因是生产脚本没有状态字段处理与路径识别。
- 实现真实纯函数后，相同命令 5/5 通过，`node --check hook_JniEncryptData.js` 通过。
- 测试覆盖严格字段边界、任意其他字节、不同数字宽度、重复处理、进程/线程路径与无关路径，未模拟 Frida API。
- 设备调查确认 Frida 12.11.12、Android 10、arm64/Linux 4.14.163；主应用当前未运行，现有服务进程的 TracerPid 为 0，不能以该数值证明归零效果。
- 真实非零测试将使用本次独立创建的 sleep 进程及 PTRACE_SEIZE，不追踪或终止现有服务进程。

## 原生接口的失败证据与实现

- 历史文档中的设备端口已过时。读取现有服务 `/proc/27923/cmdline` 与监听表后确认设备端实际为 9527；本次临时转发为主机 2199 → 设备 9527，Frida 枚举成功。
- 真机测试已创建隔离 sleep target/tracer，并通过真实 PTRACE_SEIZE 使目标主线程和 JS 线程的 TracerPid 非零。所有五种状态路径的内核基线均已证实。
- 首次基线发现测试中的 O_DIRECTORY 使用了通用 Linux 数值；依据 ARM64 头文件修正为 0x4000。目标 F_GETFL 实测为 0x20800，包含 ARM 的 O_LARGEFILE。
- `logs/tracerpid-device-red.json` 记录原脚本 open 读到 TracerPid=4823，期望 0，测试按预期失败。它同时记录了 native helper 无 Java 环境时原入口抛出 Java API not available，因此入口增加 Java.available 判断。
- 原生实现将成功打开的真实 status FD 替换为等长匿名快照；保留只读模式、O_NONBLOCK、FD_CLOEXEC 和原偏移。按函数地址去重，并在 onLeave 恢复 errno。
- 第一轮原生验证开始前，设备从 adb devices 消失，测试报告 ServerNotRunningError，尚未执行原生实现；已请求 Chang 恢复连接。此环境错误不能算作实现通过或失败。

## 独立审查与真实回归

- 普通模式：真实 PTRACE_SEIZE 下，五种进程/线程路径 × 十种读取方式共 50 案例通过；内联 syscall 对照仍返回真实非零 TracerPid。文件访问模式、O_NONBLOCK、FD_CLOEXEC、相对 openat、seek/pread、ENOENT 与普通文件均通过。
- 审查发现“打开时为零而跳过替换”会在同一 FD 后续被跟踪时泄露数值。真机先复现 TracerPid=8512 的失败，再改为对非空 status 始终建立快照，持有 FD 及原 50 案例全部通过。
- 临时资源清理的顺序 close 在第一项失败时会跳过第二项。最初尝试监听嵌套 dup3 未触发，不能用作失败证据；改用生产 closeStatusFiles 和真实已关闭 FD，确证第二项残留后，再以嵌套 finally 修复。真实 close/fcntl 回归通过。
- Java loader 泄漏在独立 Android Java 进程中确证：失败查类后 loader 从 null 变为 BootClassLoader；加入 finally 后恢复为 null，真实 byte[] 转换、预览和主动调用入口检查通过。
- 独立 Java helper 首次在 ART 初始化阶段过早调用 JNI 触发运行时断言。核对设备 crash 日志后，改为等待 Java main 输出就绪信号再附加；该问题属于测试时序，不据此修改业务脚本。
- Chang 确认此前实际应用测试期间曾手动关闭或重启应用，因此该次超时/退出不能作为反调试触发证据。
- Chang 重启设备并重新启动 9527 服务后，实际 `com.autel.update` PID 6330 附加检查通过：5 个原生 hook，默认 classloader 找到 EncryptionJni，安装一个 `(int, [B) -> [B]` 重载；loader 恢复、真实 byte[] 和全局主动调用入口均通过。
- 服务端可执行文件实际输出版本为 12.11.1，客户端 Python Frida 为 12.11.12。实际运行证据优先于文件名或历史文档。
- 独立审查确认无阻塞错误；最终仍需执行一轮完整检查并提交。

## 最终验收

- 最终完整检查全部通过：Node 5/5、JS/Python 语法、git diff --check、普通真实非零 TracerPid 50/50、先打开后跟踪 50/50、关闭失败资源清理，以及独立真实 Java 进程检查。
- 实际应用最终检查 PID 10173，`nativeHooks=5`、`encryptionHookReady=true`、`loaderRestored=true`，成功安装加密 hook；无未预期运行时消息。该检查已对加密 hook 安装状态作强制断言。
- 所有本次专用 native/Java 测试进程均由 finally 清理。设备重启已结束此前本次创建的 9528 专用服务；当前 9527 服务由 Chang 启动，保留使用。
- 最终证据保存在 `logs/tracerpid-*-green.json` 和 `logs/tracerpid-unit-green.txt`；先失败的回归证据另有 red 报告。测试构建输出通过 tests/.gitignore 排除，仅跟踪本任务源文件、计划、日志和清单。
- 提交阶段首次将日志纳入 Git 后发现 Windows CRLF 被 git diff --check 报为尾随空白；命令序列未在该错误处停止，已生成 d5eb874。通过只针对本任务日志的 .gitattributes 和 Git renormalize 修正索引中的文本格式，不手工更改内容；随后重新执行提交检查并核对 JSON 语义一致性。
- 归一化后的 staged diff 与相对基线 ada48e6 的完整 diff 检查均通过；13 份 JSON 的索引内容与工作区解析结果全部一致。源脚本、测试和诊断内容未受格式修正影响。
- 本任务交付位于 wip/tracerpid；现有其他代码、逆向数据库、DEX 与历史工具仍未纳入提交。

## 实际边界

- 仅对经 libc 打开接口取得的 `/proc/.../status` 建立快照；脚本安装前已打开的 FD、直接内联 syscall 打开、外部未注入进程与注入前检查不在已覆盖范围。
- 替换后 fd 的 readlink/fstat 元数据可见匿名内存文件，快照保留打开时的其他字段，不宣称完全透明。
- 真机覆盖 ARM64；ARM32 分支未验证。已验证加密 hook 安装和工具函数，没有主动执行未给定输入的加密业务。

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

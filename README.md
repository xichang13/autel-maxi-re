# com.Autel.maxi 逆向工具集

针对道通诊断 App(`com.Autel.maxi`,SecNeo 加壳)的 **so dump / 反调试绕过 / JNI 加密分析** 工具集。
面向已 root 的 Android 设备 + frida。

## 对抗背景

壳(SecNeo)有三道针对动态分析的防线,工具据此设计:

| 防线 | 现象 | 应对 |
|---|---|---|
| hook 进程内 `open`/`read`,过滤 `/proc/self/maps` | `Process.enumerateModules` 看不到 `libDiag.so` 等 | 用 **raw syscall** 直读 maps 绕过 |
| TracerPid 反调试 | 读 `/proc/*/status` 发现被 trace 即自毁 | hook open/read 族,把 `TracerPid` 掩成 0 |
| SIGSEGV 守护页 | 进程内读壳内存触发自毁 | 从 **进程外** 读 `/proc/pid/mem` |

两条铁律贯穿全部工具:**枚举/定位用 raw syscall 读 maps,不信进程内 API;dump/读内存尽量从进程外做,并输出加载基址供修复。**

## 脚本清单

### dump 脚本

| 脚本 | 作用 |
|---|---|
| [`dump_so.js`](dump_so.js) | 按名 dump 指定 so。raw-syscall 读 maps 定位(替代被过滤的 `enumerateModules`),带 ELF 头扫描与区间 dump 兜底 |
| [`dump_all_so.js`](dump_all_so.js) | 一次 dump 全部命名 so + 匿名 ELF 区间,出 `_manifest.txt` 汇总基址 |
| [`mem_dumper/`](mem_dumper/README.md) | **进程外** `/proc/pid/mem` dumper(C 版 + NDK 构建/推送脚本 + 纯 shell 兜底)。绕守护页 SIGSEGV 与 in-process hook,最硬的兜底 |

每个 dump 旁生成 `<name>.dump.info.txt`,记 **base / end / size**。dump 出来是**内存镜像**(段按 vaddr 对齐、已重定位),修复时按 base 把 program/section header 的 file offset 对齐回 vaddr(`p_offset = p_vaddr`)。

```bash
# 按名(进程内)
frida -U -f com.Autel.maxi -l dump_so.js
# 全量(进程内)
frida -U -f com.Autel.maxi -l dump_all_so.js
# 进程外兜底(设备 root)
cd mem_dumper && ./build.sh && ./run.sh com.Autel.maxi module libDiag.so
```

RPC(进程内脚本):`dump("libDiag.so")`、`dumpall()`、`list()`/`listall()`、`scan()`、`diff()`(列出被进程内过滤掉的 so)。

### 反调试脚本

| 脚本 | 作用 |
|---|---|
| [`hook_JniEncryptData.js`](hook_JniEncryptData.js) | 主力。**TracerPid 绕过**(`installTracerPidBypass`:hook `open/open64/openat/__openat_2/fopen` + `read`,匹配 `/proc/*/status` 与其 fd 描述符链接,掩盖 `TracerPid`/`Name`,memfd 快照 + `dup3` 换 status fd)+ hook/主动调用 `com.autel.utils.EncryptionJni.JniEncryptData` 做加密 oracle,打印入参/返回/Java 栈 |
| [`hook_dlopen.js`](hook_dlopen.js) | 轻量:hook `android_dlopen_ext` 打印所有被加载的 so 路径 |
| [`my_hook_dlopen.js`](my_hook_dlopen.js) | 按名匹配 dlopen,命中后触发后续 hook(配合定点 hook 的时机控制) |

```bash
# 反调试绕过 + JNI 加密分析(含 TracerPid 掩盖,脚本顶部 HIDE_TRACERPID 开关)
frida -U -f com.Autel.maxi -l hook_JniEncryptData.js
# 观察 so 加载顺序
frida -U -f com.Autel.maxi -l hook_dlopen.js
```

## 排查流程

1. `hook_dlopen.js` 看 so 加载顺序,确认目标名
2. `dump_all_so.js` 的 `diff()` 对比 frida/maps 视角,确认哪些被进程内过滤
3. 进程内 `dump_so.js` 先试;残缺或触发自毁 → 换 `mem_dumper/` 进程外读
4. 按 `.info.txt` 的 base 修 ELF,送 IDA 分析
5. 加密逻辑用 `hook_JniEncryptData.js` 做 oracle

## 其它

- `docs/plans/`、`tests/`、`logs/`:TracerPid 绕过方案与验证记录
- `.gitignore` 已挡掉 APK / dump / IDA 库 / 解包目录等大二进制产物,它们不入库

> 仅用于授权范围内的安全研究与兼容性分析。

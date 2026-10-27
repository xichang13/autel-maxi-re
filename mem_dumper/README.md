# mem_dumper — 外部 /proc/pid/mem 兜底 dumper

进程**外**的 root dumper，读 `/proc/<目标pid>/mem`，用来对付 `dump_so.js` 搞不定的情况。

## 为什么比进程内 frida 硬

| 对抗手段 | 进程内 frida (`dump_so.js`) | 外部 mem_dumper |
|---|---|---|
| hook `open`/`read` 过滤 maps | 受影响(需 raw syscall 绕) | **完全够不着**(读 maps/mem 在本进程上下文) |
| SIGSEGV 守护页自毁 | frida 线程可能触发 | **不触发**,内核返回 EIO,逐页零填充继续 |
| 名字被抹/匿名化 | 需 ELF 扫描 | `scan`/`allexec` 扫 ELF 头 |

读 `/proc/pid/mem` 的 syscall 发生在 dumper 自己进程里，目标的 inline hook 只能拦目标进程内执行的代码，管不到别的进程 —— 这正是"调试器(外部)看得到、进程自己看不到"的同一个原理。

## 两种用法

### A. C 版(推荐,稳)

```bash
# 1. 编译(需 Android NDK)
export ANDROID_NDK_HOME=/path/to/ndk
cd mem_dumper
./build.sh                      # 默认 aarch64 / API 29,可用 API= ARCH= 覆盖

# 2. 推送 + 运行 + 回拉(默认 com.Autel.maxi / libdiag.so)
./run.sh                        # = ./run.sh com.Autel.maxi module libdiag.so
./run.sh com.Autel.maxi scan    # 名字被抹时,先扫 ELF 头拿 base
./run.sh com.Autel.maxi list    # 列 maps 里的 .so
```

设备侧直接调(已 push 后):

```bash
ssu -c 'OUT_DIR=/data/local/tmp /data/local/tmp/mem_dumper com.Autel.maxi module libdiag.so'
ssu -c '/data/local/tmp/mem_dumper com.Autel.maxi scan'
# scan 拿到 base 后手动区间 dump:
ssu -c '/data/local/tmp/mem_dumper com.Autel.maxi range 0x7xxxxxxxxx 0x300000'
```

> 道通平板用 `ssu` 提权;若标准 `su` 可用,`export SU="su -c"` 再跑 run.sh。
> 多设备 `export SERIAL=<设备号>`。

### B. shell 版(不能交叉编译时)

无需编译,推上去直接跑(依赖设备的 toybox `dd`):

```bash
adb push mem_dumper.sh /data/local/tmp/
adb shell "ssu -c 'sh /data/local/tmp/mem_dumper.sh com.Autel.maxi module libdiag.so'"
adb pull /data/local/tmp/libdiag.so.dump
```

shell 版靠 `dd conv=noerror,sync` 在守护页零填充,精度不如 C 版逐页 pread,但零依赖。

## 模式

| 模式 | 作用 |
|---|---|
| `module <so>` | 按名找所有 VMA,取 min~max 整段 dump(保留 vaddr 布局,段间隙零填充) |
| `range <base> <size>` | 手动区间 dump,配合 `scan` 或外部定位到的地址 |
| `scan` | 列出所有带 `\x7fELF` 头的区间(名字被抹时用) |
| `allexec` | 把所有 ELF 头区间全 dump 出来 |
| `list` | 列 maps 中的 `.so` 区间 |

## 排查流程

1. `list` / `scan` 先确认目标到底在不在、在哪、叫什么
2. 有名字 → `module libdiag.so`
3. 名字被抹 → `scan` 拿 base → `range <base> <size>`
4. dump 回来后用 IDA/脚本修 section header(段按 vaddr 布局已对齐),重建导入

> dump 出来的是**内存镜像**(段按虚拟地址对齐、已重定位),不是磁盘原始 ELF。
> 后续修复按内存镜像处理:sh_offset 对齐到 sh_addr、p_offset=p_vaddr。

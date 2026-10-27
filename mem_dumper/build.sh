#!/usr/bin/env bash
# ABOUTME: 用 Android NDK 的 clang 把 mem_dumper.c 交叉编译为 aarch64 Android 可执行文件
# ABOUTME: 需要先设好 ANDROID_NDK_HOME(或 NDK),输出 ./mem_dumper
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NDK="${ANDROID_NDK_HOME:-${NDK:-}}"
API="${API:-29}"            # 目标 Android API,道通平板按实际调,21~34 都行
ARCH="${ARCH:-aarch64}"     # aarch64 / armv7a / x86_64 / i686

if [[ -z "$NDK" ]]; then
    echo "[-] 请先设置 ANDROID_NDK_HOME 或 NDK 指向 NDK 根目录" >&2
    exit 1
fi

# 探测 host 工具链目录
case "$(uname -s)" in
    Linux*)  HOST=linux-x86_64 ;;
    Darwin*) HOST=darwin-x86_64 ;;
    MINGW*|MSYS*|CYGWIN*) HOST=windows-x86_64 ;;
    *) echo "[-] 未知 host: $(uname -s)" >&2; exit 1 ;;
esac

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST/bin"
case "$ARCH" in
    aarch64) TRIPLE=aarch64-linux-android ;;
    armv7a)  TRIPLE=armv7a-linux-androideabi ;;
    x86_64)  TRIPLE=x86_64-linux-android ;;
    i686)    TRIPLE=i686-linux-android ;;
    *) echo "[-] 未知 ARCH: $ARCH" >&2; exit 1 ;;
esac

CC="$TOOLCHAIN/${TRIPLE}${API}-clang"
if [[ ! -x "$CC" ]]; then
    echo "[-] 找不到编译器: $CC" >&2
    echo "    检查 NDK 路径 / API($API) / ARCH($ARCH) / HOST($HOST)" >&2
    exit 1
fi

echo "[*] CC=$CC"
"$CC" -O2 -Wall -o "$HERE/mem_dumper" "$HERE/mem_dumper.c"
echo "[+] 产物: $HERE/mem_dumper"
file "$HERE/mem_dumper" 2>/dev/null || true

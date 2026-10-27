#!/usr/bin/env bash
# ABOUTME: 把 mem_dumper 推到设备、以 root 运行并把 dump 拉回本地
# ABOUTME: 默认目标 com.Autel.maxi / 模块 libdiag.so,可用参数覆盖
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/mem_dumper"
SERIAL="${SERIAL:-}"                       # 多设备时 export SERIAL=xxxx
PKG="${1:-com.Autel.maxi}"
MODE="${2:-module}"
ARG3="${3:-libdiag.so}"
ARG4="${4:-}"
DEV_DIR=/data/local/tmp
# 道通平板用 ssu 提权;若标准 su 可用改成 SU="su -c"
SU="${SU:-ssu -c}"

adb_() { if [[ -n "$SERIAL" ]]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi; }

[[ -f "$BIN" ]] || { echo "[-] 先 ./build.sh 生成 mem_dumper" >&2; exit 1; }

echo "[*] 推送 mem_dumper -> $DEV_DIR"
adb_ push "$BIN" "$DEV_DIR/mem_dumper" >/dev/null
adb_ shell "$SU 'chmod 755 $DEV_DIR/mem_dumper'"

CMD="OUT_DIR=$DEV_DIR $DEV_DIR/mem_dumper $PKG $MODE $ARG3 $ARG4"
echo "[*] 运行: $CMD"
adb_ shell "$SU '$CMD'"

# 只有真正产出 dump 的模式才回拉
if [[ "$MODE" == "module" || "$MODE" == "range" || "$MODE" == "allexec" ]]; then
    echo "[*] 拉取 *.dump 到 $HERE"
    # 列出设备上的 dump 再逐个 pull
    for f in $(adb_ shell "$SU 'ls $DEV_DIR/*.dump 2>/dev/null'" | tr -d '\r'); do
        adb_ pull "$f" "$HERE/" >/dev/null && echo "    <- $f"
    done
fi
echo "[+] done"

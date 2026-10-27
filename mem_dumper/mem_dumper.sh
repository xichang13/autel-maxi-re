#!/system/bin/sh
# ABOUTME: 纯 shell 兜底 dumper,在设备 root shell 内直接跑,无需交叉编译
# ABOUTME: 用 toybox dd 读 /proc/pid/mem,conv=noerror,sync 在守护页处零填充继续
#
# 用法(设备 root shell 内):
#   sh mem_dumper.sh <pid|包名> module <soName>
#   sh mem_dumper.sh <pid|包名> range  <hexBase> <hexSize>
#   sh mem_dumper.sh <pid|包名> list
# 输出到 $OUT_DIR(默认 /data/local/tmp)

PKG="$1"; MODE="$2"; A3="$3"; A4="$4"
OUT_DIR="${OUT_DIR:-/data/local/tmp}"
PAGE=4096

[ -z "$MODE" ] && { echo "用法: $0 <pid|包名> module <so> | range <base> <size> | list"; exit 1; }

# 解析 pid
case "$PKG" in
    *[!0-9]*)
        PID=""
        for p in /proc/[0-9]*; do
            cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | awk '{print $1}')
            [ "$cmd" = "$PKG" ] && { PID=${p#/proc/}; break; }
        done
        [ -z "$PID" ] && { echo "[-] 找不到进程: $PKG"; exit 1; }
        echo "[*] $PKG -> pid $PID" ;;
    *) PID="$PKG" ;;
esac

MAPS="/proc/$PID/maps"
MEM="/proc/$PID/mem"
[ -r "$MAPS" ] || { echo "[-] 读不了 $MAPS (需要 root)"; exit 1; }

dump_range() {  # base_hex end_hex name
    base=$((0x$1)); end=$((0x$2)); name="$3"
    size=$((end - base))
    skip=$((base / PAGE))
    count=$(( (size + PAGE - 1) / PAGE ))
    out="$OUT_DIR/$name.dump"
    echo "[+] dump 0x$1-0x$2 (size=$size) -> $out"
    # skip/count 以 PAGE 为块;noerror,sync 在 EIO 页零填充并继续
    dd if="$MEM" of="$out" bs=$PAGE skip=$skip count=$count conv=noerror,sync 2>/dev/null
    echo "    实际大小: $(wc -c < "$out" 2>/dev/null) 字节"
}

case "$MODE" in
    list)
        grep '\.so' "$MAPS" ;;
    range)
        [ -z "$A4" ] && { echo "range 需要 <hexBase> <hexSize>"; exit 1; }
        # A3=base(hex), A4=size(hex) -> 算 end
        b=$((0x$A3)); sz=$((0x$A4)); e=$((b + sz))
        dump_range "$A3" "$(printf '%x' $e)" "manual_$A3" ;;
    module)
        [ -z "$A3" ] && { echo "module 需要 <soName>"; exit 1; }
        # 取该 so 所有行,算 min(start)~max(end)
        lines=$(awk -v n="$A3" '$NF ~ ("/" n "$") || $NF ~ ("/" n " ") || $NF == n || index($NF, n){print}' "$MAPS" \
                | grep -F "$A3")
        [ -z "$lines" ] && { echo "[-] maps 里没有 $A3,试试 list"; exit 1; }
        echo "$lines"
        minb=$(echo "$lines" | awk -F'[- ]' '{print $1}' | sort | head -1)
        maxe=$(echo "$lines" | awk -F'[- ]' '{print $2}' | sort | tail -1)
        dump_range "$minb" "$maxe" "$A3" ;;
    *)
        echo "未知模式: $MODE"; exit 1 ;;
esac
echo "[+] done"

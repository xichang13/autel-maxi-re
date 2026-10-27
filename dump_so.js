// ABOUTME: 从目标进程 dump 指定 SO 到文件,用 raw syscall 读 maps 绕过壳的 in-process 过滤
// ABOUTME: 定位模块不依赖 Process.enumerateModules(会被 hook 抹掉),改为直读 /proc/self/maps
//
// 用法: frida -U -f com.Autel.maxi -l dump_so.js
//   或 RPC: rpc.exports.dump("libdiag.so") / rpc.exports.list() / rpc.exports.scan()
//           rpc.exports.dumprange("0x7xxxxxxxxx", "0x300000", "libdiag.so")
//
// 背景:壳(SecNeo)hook 了进程内的 open/read/fopen,过滤 /proc/self/maps,
// 使 Process.findModuleByName("libdiag.so") 返回 null —— 看不到自然 dump 不到。
// 外部调试器能看到说明 so 是真实 file-backed,只是进程内读取路径被过滤。
// 这里用 raw syscall(openat/read/close)直读 maps,syscall 入口通常不在壳的
// 命名函数 hook 列表里,从而拿到内核原始 VMA 区间。

var PAGE_SIZE = 0x1000;

// 目标列表:一次执行内全部 dump,赶在反调试自杀校验之前。libdiag.so 放最前
var TARGET_SOS = [
    "libdiag.so",
    "libDexHelper.so",
    "libPlatformEnDecrypt.so",
    "libcrypto_at.so",
    "libssl_at.so"
];

// ---------- raw syscall:绕过 libc 的 open/read hook ----------

function getSyscallNrs() {
    switch (Process.arch) {
        case "arm64": return { openat: 56,  read: 63, close: 57 };
        case "arm":   return { openat: 322, read: 3,  close: 6  };
        case "ia32":  return { openat: 295, read: 3,  close: 6  };
        case "x64":   return { openat: 257, read: 0,  close: 3  };
        default:      return null;
    }
}

var AT_FDCWD = -2;
var O_RDONLY = 0;

var _nrs = getSyscallNrs();
var _sysAddr = Module.findExportByName(null, "syscall");

// 针对每种调用用固定签名绑定同一个 syscall 入口(整型参数走寄存器,变参 ABI 一致)
var _sys_openat = (_sysAddr && _nrs) ? new NativeFunction(_sysAddr, "int",  ["long", "int", "pointer", "int"])  : null;
var _sys_read   = (_sysAddr && _nrs) ? new NativeFunction(_sysAddr, "long", ["long", "int", "pointer", "long"]) : null;
var _sys_close  = (_sysAddr && _nrs) ? new NativeFunction(_sysAddr, "int",  ["long", "int"])                    : null;

function toNum(v) {
    return (v && typeof v.toNumber === "function") ? v.toNumber() : Number(v);
}

// 用 raw syscall 把整个文件读成字符串(maps 是纯 ASCII,无 NUL)
function readFileRaw(path) {
    if (!_sys_openat) {
        console.log("[!] syscall 入口未找到,无法 raw 读文件:" + path);
        return null;
    }
    var pathPtr = Memory.allocUtf8String(path);
    var fd = _sys_openat(_nrs.openat, AT_FDCWD, pathPtr, O_RDONLY);
    if (fd < 0) {
        console.log("[!] raw openat 失败 fd=" + fd + " path=" + path);
        return null;
    }

    var bufSize = 0x10000;
    var buf = Memory.alloc(bufSize);
    var out = "";
    try {
        while (true) {
            var n = toNum(_sys_read(_nrs.read, fd, buf, bufSize));
            if (n <= 0) break;
            out += buf.readUtf8String(n);
        }
    } finally {
        _sys_close(_nrs.close, fd);
    }
    return out;
}

// 解析 /proc/self/maps → [{start, end, perms, offset, path}]
function parseMaps(text) {
    var entries = [];
    if (!text) return entries;
    var lines = text.split("\n");
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line) continue;
        // start-end perms offset dev inode  path
        var m = line.match(/^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$/);
        if (!m) continue;
        entries.push({
            start: ptr("0x" + m[1]),
            end: ptr("0x" + m[2]),
            perms: m[3],
            offset: parseInt(m[4], 16),
            path: m[5] || ""
        });
    }
    return entries;
}

function basenameOf(path) {
    var slash = path.lastIndexOf("/");
    return slash >= 0 ? path.substring(slash + 1) : path;
}

// 从 raw maps 里按名字找模块完整区间(可能跨 text/rodata/data 多个 VMA)
function findModuleByMaps(soName) {
    var entries = parseMaps(readFileRaw("/proc/self/maps"));
    var hit = entries.filter(function (e) {
        var b = basenameOf(e.path);
        // 兼容 "libdiag.so" 与 "libdiag.so (deleted)"
        return b === soName || b.indexOf(soName) === 0;
    });
    if (hit.length === 0) return null;

    var base = hit[0].start;
    var end = hit[0].end;
    for (var i = 1; i < hit.length; i++) {
        if (hit[i].start.compare(base) < 0) base = hit[i].start;
        if (hit[i].end.compare(end) > 0) end = hit[i].end;
    }
    return { base: base, size: toNum(end.sub(base)), segments: hit };
}

// 兜底:名字被抹时,扫描所有区间找 ELF 头(\x7fELF),列出候选
function scanElfRegions() {
    var entries = parseMaps(readFileRaw("/proc/self/maps"));
    var found = [];
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        if (e.perms.indexOf("r") !== 0) continue; // 不可读跳过
        if (e.offset !== 0) continue;             // ELF 头在映射起点,offset 必为 0
        try {
            var hdr = e.start.readByteArray(4);
            var u = new Uint8Array(hdr);
            if (u[0] === 0x7f && u[1] === 0x45 && u[2] === 0x4c && u[3] === 0x46) {
                found.push({
                    base: e.start.toString(),
                    perms: e.perms,
                    path: e.path || "[anon]"
                });
            }
        } catch (err) { /* 守护页/不可读,跳过 */ }
    }
    return found;
}

// 定位模块:先试 frida 自带(可能被过滤),再 raw maps 兜底
function resolveModule(soName) {
    var mod = Process.findModuleByName(soName);
    if (mod) return { base: mod.base, size: mod.size, src: "frida" };

    var r = findModuleByMaps(soName);
    if (r) return { base: r.base, size: r.size, src: "maps(raw)", segments: r.segments };

    return null;
}

// ---------- dump:分页读,不可读页零填充(对应 BSS/段间隙/守护页) ----------

function dumpRange(base, size, soName) {
    var outPath = "/sdcard/" + soName + ".dump";
    console.log("[+] Dumping " + soName);
    console.log("    base: " + base);
    console.log("    size: 0x" + size.toString(16) + " (" + (size / 1024).toFixed(1) + " KB)");
    console.log("    output: " + outPath);

    var f = new File(outPath, "w");
    var bytesRead = 0;
    var pagesSkipped = 0;
    var offset = 0;

    while (offset < size) {
        var chunkSize = Math.min(PAGE_SIZE, size - offset);
        var addr = base.add(offset);
        try {
            var data = addr.readByteArray(chunkSize);
            if (data) {
                f.write(data);
                bytesRead += chunkSize;
            } else {
                f.write(new ArrayBuffer(chunkSize));
                pagesSkipped++;
            }
        } catch (e) {
            // 该页不可读:守护页/BSS/段间隙,零填充保持偏移对齐
            f.write(new ArrayBuffer(chunkSize));
            pagesSkipped++;
        }

        offset += PAGE_SIZE;

        if (offset % (2048 * 1024) === 0) {
            var pct = (offset / size * 100).toFixed(1);
            console.log("    progress: " + pct + "% (" + (offset / 1024).toFixed(0) + "/" + (size / 1024).toFixed(0) + " KB, " + pagesSkipped + " pages skipped)");
        }
    }

    f.flush();
    f.close();

    var pct2 = (bytesRead / size * 100).toFixed(1);
    console.log("[+] Dump complete: " + outPath);
    console.log("    readable: " + (bytesRead / 1024).toFixed(0) + " KB (" + pct2 + "%)");
    console.log("    skipped: " + pagesSkipped + " pages (zero-filled)");
    return outPath;
}

// 把基址等修复所需信息写到 sidecar,供后续修 ELF(段偏移对齐回 vaddr)用
function writeInfo(soName, base, size, src, segments) {
    var p = "/sdcard/" + soName + ".dump.info.txt";
    var f = new File(p, "w");
    f.write("name: " + soName + "\n");
    f.write("base: " + base + "\n");
    f.write("size: 0x" + size.toString(16) + " (" + size + ")\n");
    f.write("end:  " + base.add(size) + "\n");
    f.write("arch: " + Process.arch + "\n");
    f.write("located_via: " + src + "\n");
    f.write("dump: /sdcard/" + soName + ".dump\n");
    if (segments && segments.length) {
        f.write("segments:\n");
        segments.forEach(function (s) {
            f.write("  " + s.start + "-" + s.end + " " + s.perms + " " + s.path + "\n");
        });
    }
    f.flush();
    f.close();
    console.log("    info: " + p + "  (base=" + base + ")");
    return p;
}

function dumpSo(soName) {
    var m = resolveModule(soName);
    if (!m) {
        var msg = "[-] Module " + soName + " not found(frida 与 raw maps 均未命中)。\n";
        var elf = scanElfRegions();
        if (elf.length) {
            msg += "    maps 中带 ELF 头的候选区间(名字可能被抹,按 base 用 dumprange 手动 dump):\n";
            msg += elf.map(function (x) { return "      " + x.base + " " + x.perms + " " + x.path; }).join("\n");
        } else {
            msg += "    未扫到任何 ELF 头区间(可能被匿名化或读取被更深层拦截,建议走外部 /proc/pid/mem)。";
        }
        return msg;
    }
    console.log("    located via: " + m.src);
    if (m.segments) {
        console.log("    segments:");
        m.segments.forEach(function (s) {
            console.log("      " + s.start + "-" + s.end + " " + s.perms + " " + s.path);
        });
    }
    var out = dumpRange(m.base, m.size, soName);
    writeInfo(soName, m.base, m.size, m.src, m.segments);
    return out;
}

// 自动 dump:立即执行、全量循环、单个失败不中断后续
setTimeout(function () {
    console.log("[*] arch=" + Process.arch + " syscall@" + _sysAddr);
    for (var i = 0; i < TARGET_SOS.length; i++) {
        var name = TARGET_SOS[i];
        try {
            console.log(dumpSo(name));
        } catch (e) {
            console.log("[!] dump " + name + " failed: " + e + "\n" + (e.stack || ""));
        }
    }
    console.log("[*] ALL DONE");
}, 0);

// RPC 导出
rpc.exports = {
    // 按名 dump(自动 raw maps 兜底)
    dump: function (soName) {
        return dumpSo(soName);
    },
    // 手动指定区间 dump(配合外部定位到的地址;base/size 可为 "0x..." 字符串)
    dumprange: function (baseStr, sizeStr, soName) {
        var base = ptr(baseStr);
        var size = (typeof sizeStr === "string") ? parseInt(sizeStr, 16) : sizeStr;
        return dumpRange(base, size, soName || "manual_" + baseStr);
    },
    // raw maps 视角的模块列表(绕过 hook)
    list: function () {
        var entries = parseMaps(readFileRaw("/proc/self/maps"));
        var seen = {};
        var mods = [];
        entries.forEach(function (e) {
            var b = basenameOf(e.path);
            if (!b || b[0] === "[" || seen[e.path]) return;
            seen[e.path] = true;
            mods.push({ name: b, base: e.start.toString(), path: e.path });
        });
        return mods;
    },
    // 对比:frida 视角 vs raw maps 视角,差集即进程内被过滤掉的模块
    diff: function () {
        var fridaNames = {};
        Process.enumerateModules().forEach(function (m) { fridaNames[m.name] = true; });
        var rawNames = {};
        parseMaps(readFileRaw("/proc/self/maps")).forEach(function (e) {
            var b = basenameOf(e.path);
            if (b && b.indexOf(".so") !== -1) rawNames[b] = true;
        });
        var hiddenFromFrida = Object.keys(rawNames).filter(function (n) { return !fridaNames[n]; });
        return { hiddenFromFrida: hiddenFromFrida };
    },
    // ELF 头扫描兜底
    scan: function () {
        return scanElfRegions();
    }
};

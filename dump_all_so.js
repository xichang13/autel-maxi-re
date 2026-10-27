// ABOUTME: frida 脚本,dump com.Autel.maxi 进程内全部 so(含壳加载的无名 ELF)
// ABOUTME: 枚举用 raw syscall 直读 /proc/self/maps 绕过壳对 open/read 的过滤,而非 Process.enumerateModules
//
// 用法: frida -U -f com.Autel.maxi -l dump_all_so.js
//   或 RPC: rpc.exports.dumpall() / rpc.exports.listall() / rpc.exports.dumpanon()
// 输出目录: 改 DUMP_DIR,默认 /sdcard/so_dump
//
// 注意:这是进程内 dump,受守护页/反 frida 影响。若某个 so 在这里 dump 失败或残缺,
// 改用进程外的 mem_dumper(mem_dumper/ 目录)从 /proc/pid/mem 读,那是更硬的兜底。

var DUMP_DIR = "/sdcard/so_dump";
var PAGE_SIZE = 0x1000;

// ---------- raw syscall:绕过 libc 的 open/read hook ----------

function getSyscallNrs() {
    switch (Process.arch) {
        case "arm64": return { openat: 56,  read: 63, close: 57, mkdirat: 34  };
        case "arm":   return { openat: 322, read: 3,  close: 6,  mkdirat: 323 };
        case "ia32":  return { openat: 295, read: 3,  close: 6,  mkdirat: 296 };
        case "x64":   return { openat: 257, read: 0,  close: 3,  mkdirat: 258 };
        default:      return null;
    }
}

var AT_FDCWD = -2;
var O_RDONLY = 0;

var _nrs = getSyscallNrs();
var _sysAddr = Module.findExportByName(null, "syscall");

var _sys_openat  = (_sysAddr && _nrs) ? new NativeFunction(_sysAddr, "int",  ["long", "int", "pointer", "int"])  : null;
var _sys_read    = (_sysAddr && _nrs) ? new NativeFunction(_sysAddr, "long", ["long", "int", "pointer", "long"]) : null;
var _sys_close   = (_sysAddr && _nrs) ? new NativeFunction(_sysAddr, "int",  ["long", "int"])                    : null;
var _sys_mkdirat = (_sysAddr && _nrs) ? new NativeFunction(_sysAddr, "int",  ["long", "int", "pointer", "int"])  : null;

function toNum(v) {
    return (v && typeof v.toNumber === "function") ? v.toNumber() : Number(v);
}

function readFileRaw(path) {
    if (!_sys_openat) { console.log("[!] 无 syscall 入口,raw 读失败: " + path); return null; }
    var pathPtr = Memory.allocUtf8String(path);
    var fd = _sys_openat(_nrs.openat, AT_FDCWD, pathPtr, O_RDONLY);
    if (fd < 0) { console.log("[!] raw openat 失败 fd=" + fd + " " + path); return null; }
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

function mkdirRaw(path) {
    if (!_sys_mkdirat) return;
    var p = Memory.allocUtf8String(path);
    _sys_mkdirat(_nrs.mkdirat, AT_FDCWD, p, 0x1ff); // 0777
}

function parseMaps(text) {
    var entries = [];
    if (!text) return entries;
    var lines = text.split("\n");
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line) continue;
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

function isElfAt(addr) {
    try {
        var hdr = addr.readByteArray(4);
        var u = new Uint8Array(hdr);
        return u[0] === 0x7f && u[1] === 0x45 && u[2] === 0x4c && u[3] === 0x46;
    } catch (e) { return false; }
}

// ---------- dump 一段 [base, base+size) ----------

function dumpRange(base, size, outPath) {
    var f = new File(outPath, "w");
    var zeroPage = new ArrayBuffer(PAGE_SIZE);
    var bytesRead = 0, pagesSkipped = 0, offset = 0;

    while (offset < size) {
        var chunk = Math.min(PAGE_SIZE, size - offset);
        var addr = base.add(offset);
        try {
            var data = addr.readByteArray(chunk);
            if (data) { f.write(data); bytesRead += chunk; }
            else { f.write(chunk === PAGE_SIZE ? zeroPage : new ArrayBuffer(chunk)); pagesSkipped++; }
        } catch (e) {
            f.write(chunk === PAGE_SIZE ? zeroPage : new ArrayBuffer(chunk));
            pagesSkipped++;
        }
        offset += PAGE_SIZE;
    }
    f.flush();
    f.close();
    return { bytesRead: bytesRead, pagesSkipped: pagesSkipped, size: size };
}

// 把基址等修复所需信息写到 <dump>.info.txt,供后续修 ELF(段偏移对齐回 vaddr)用
function writeInfo(dumpPath, mod, r, pct) {
    var p = dumpPath + ".info.txt";
    var f = new File(p, "w");
    f.write("name: " + mod.name + "\n");
    f.write("base: " + mod.base + "\n");
    f.write("size: 0x" + mod.size.toString(16) + " (" + mod.size + ")\n");
    f.write("end:  " + mod.base.add(mod.size) + "\n");
    f.write("arch: " + Process.arch + "\n");
    f.write("path: " + mod.path + "\n");
    f.write("dump: " + dumpPath + "\n");
    if (r) f.write("readable: " + pct + "%  skipped_pages: " + r.pagesSkipped + "\n");
    f.flush();
    f.close();
    return p;
}

// 同名 so 不同路径时,输出名去重
var _usedNames = {};
function uniqueOutName(name) {
    var n = name, i = 1;
    while (_usedNames[n]) { n = name + "." + (i++); }
    _usedNames[n] = true;
    return n;
}

// ---------- 从 raw maps 收集全部 .so(按路径聚合区间) ----------

function collectSoModules() {
    var entries = parseMaps(readFileRaw("/proc/self/maps"));
    var byPath = {};   // path -> {base, end}
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        if (basenameOf(e.path).indexOf(".so") === -1) continue;
        if (!byPath[e.path]) byPath[e.path] = { base: e.start, end: e.end, path: e.path };
        else {
            if (e.start.compare(byPath[e.path].base) < 0) byPath[e.path].base = e.start;
            if (e.end.compare(byPath[e.path].end) > 0) byPath[e.path].end = e.end;
        }
    }
    var mods = [];
    for (var p in byPath) {
        if (!byPath.hasOwnProperty(p)) continue;
        var r = byPath[p];
        mods.push({ name: basenameOf(p), path: p, base: r.base, size: toNum(r.end.sub(r.base)) });
    }
    return mods;
}

// ---------- 匿名 ELF 区间(壳加载的无名 so):offset=0 且头是 \x7fELF ----------

function collectAnonElf() {
    var entries = parseMaps(readFileRaw("/proc/self/maps"));
    var mods = [];
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        if (e.perms[0] !== "r") continue;
        if (e.offset !== 0) continue;
        if (basenameOf(e.path).indexOf(".so") !== -1) continue; // 已归入命名 so
        if (!isElfAt(e.start)) continue;
        // 从 ELF 头起,把紧邻的后续段并进来(同一镜像常连续映射)
        var base = e.start, end = e.end;
        for (var j = i + 1; j < entries.length; j++) {
            if (entries[j].start.equals(end) && entries[j].path === e.path) { end = entries[j].end; }
            else break;
        }
        mods.push({
            name: (e.path ? basenameOf(e.path) : "anon_" + base.toString()),
            path: e.path || "[anon]",
            base: base,
            size: toNum(end.sub(base))
        });
    }
    return mods;
}

// ---------- 主流程 ----------

function dumpAll() {
    mkdirRaw(DUMP_DIR);
    var named = collectSoModules();
    var anon = collectAnonElf();
    var all = named.concat(anon);

    console.log("[*] arch=" + Process.arch + "  命名so=" + named.length + "  匿名ELF=" + anon.length + "  合计=" + all.length);
    console.log("[*] 输出目录: " + DUMP_DIR);

    var results = [];
    var manifest = "# name  base  size  path  (dump 为内存镜像,修复时按 base 把段偏移对齐回 vaddr)\n";
    for (var i = 0; i < all.length; i++) {
        var mod = all[i];
        var outName = uniqueOutName(mod.name);
        var outPath = DUMP_DIR + "/" + outName + ".dump";
        try {
            var r = dumpRange(mod.base, mod.size, outPath);
            var pct = (r.bytesRead * 100 / (r.size || 1)).toFixed(1);
            console.log("[+] " + outName +
                "  base=" + mod.base +
                "  size=0x" + mod.size.toString(16) +
                "  ok=" + (r.bytesRead / 1024).toFixed(0) + "KB(" + pct + "%)" +
                "  skip=" + r.pagesSkipped + "p");
            // 每个 dump 配 sidecar,持久化基址供后续修 ELF 用
            writeInfo(outPath, mod, r, pct);
            manifest += outName + "  " + mod.base + "  0x" + mod.size.toString(16) + "  " + mod.path + "\n";
            results.push({ name: outName, path: mod.path, out: outPath, base: mod.base.toString(), readablePct: pct });
        } catch (e) {
            console.log("[!] dump " + outName + " 失败: " + e);
            results.push({ name: outName, path: mod.path, out: outPath, error: String(e) });
        }
    }
    // 汇总清单:一眼看全部 so 的基址
    var mf = new File(DUMP_DIR + "/_manifest.txt", "w");
    mf.write(manifest);
    mf.flush();
    mf.close();
    console.log("[*] ALL DONE  共 " + results.length + " 个 -> " + DUMP_DIR + "  (清单: " + DUMP_DIR + "/_manifest.txt)");
    return results;
}

setTimeout(dumpAll, 0);

rpc.exports = {
    dumpall: function () { return dumpAll(); },
    listall: function () {
        return collectSoModules().concat(collectAnonElf()).map(function (m) {
            return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
        });
    },
    dumpanon: function () {
        mkdirRaw(DUMP_DIR);
        var anon = collectAnonElf();
        var out = [];
        anon.forEach(function (m) {
            var outName = uniqueOutName(m.name);
            var p = DUMP_DIR + "/" + outName + ".dump";
            out.push(Object.assign({ out: p }, dumpRange(m.base, m.size, p)));
        });
        return out;
    },
    // frida 视角 vs raw maps 视角差集:被进程内过滤掉的 so
    diff: function () {
        var fridaNames = {};
        try { Process.enumerateModules().forEach(function (m) { fridaNames[m.name] = true; }); } catch (e) {}
        var hidden = collectSoModules().filter(function (m) { return !fridaNames[m.name]; })
            .map(function (m) { return m.name; });
        return { hiddenFromFrida: hidden };
    }
};

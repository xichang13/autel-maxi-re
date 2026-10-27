// ABOUTME: 外部 root 进程从 /proc/<pid>/mem dump SO,绕过目标进程内的 maps 读取 hook 与 SIGSEGV 守护页
// ABOUTME: 读 maps 与读 mem 都发生在本进程上下文,目标的 inline hook 够不着;守护页 EIO 逐页零填充继续
//
// 构建: 见 build.sh (NDK clang 交叉编译到 aarch64-linux-android)
// 用法(设备上以 root 运行):
//   mem_dumper <pid|包名> module <soName>        按名 dump 整个模块区间
//   mem_dumper <pid|包名> range  <hexBase> <hexSize>  手动区间 dump
//   mem_dumper <pid|包名> scan                   列出所有带 ELF 头的区间(名字被抹时用)
//   mem_dumper <pid|包名> allexec                dump 所有 ELF 头的可读区间
//   mem_dumper <pid|包名> list                   列出 maps 中的 .so 区间
// 输出目录: 环境变量 OUT_DIR,默认 /data/local/tmp

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define PAGE_SIZE   0x1000ULL
#define MAX_REGIONS 8192
#define PATH_MAX_   512

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t off;
    char perm[8];
    char path[PATH_MAX_];
} region_t;

static region_t g_regions[MAX_REGIONS];
static int g_nregion = 0;

// ---- 包名 → pid:遍历 /proc,比对 cmdline(cmdline 以 NUL 分隔,首段即进程名)----
static int find_pid_by_name(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char p[256];
        snprintf(p, sizeof(p), "/proc/%s/cmdline", e->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        char buf[512] = {0};
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        if (n == 0) continue;
        // cmdline 首段(到第一个 NUL)为进程名
        if (strcmp(buf, name) == 0) {
            found = atoi(e->d_name);
            break;
        }
    }
    closedir(d);
    return found;
}

static const char *basename_of(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

// ---- 读 /proc/<pid>/maps,填充 g_regions ----
static int read_maps(int pid) {
    char p[256];
    snprintf(p, sizeof(p), "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) {
        fprintf(stderr, "[!] 打不开 %s: %s\n", p, strerror(errno));
        return -1;
    }
    char line[1024];
    g_nregion = 0;
    while (fgets(line, sizeof(line), f) && g_nregion < MAX_REGIONS) {
        uint64_t start, end, off, inode;
        char perm[8], dev[32];
        int pos = 0;
        int got = sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %31s %" SCNu64 " %n",
                         &start, &end, perm, &off, dev, &inode, &pos);
        if (got < 6) continue;
        region_t *r = &g_regions[g_nregion++];
        r->start = start; r->end = end; r->off = off;
        strncpy(r->perm, perm, sizeof(r->perm) - 1);
        r->perm[sizeof(r->perm) - 1] = 0;
        // path 从 pos 起,跳过前导空格,去掉尾部换行
        const char *path = line + pos;
        while (*path == ' ' || *path == '\t') path++;
        strncpy(r->path, path, sizeof(r->path) - 1);
        r->path[sizeof(r->path) - 1] = 0;
        size_t L = strlen(r->path);
        while (L > 0 && (r->path[L - 1] == '\n' || r->path[L - 1] == '\r')) r->path[--L] = 0;
    }
    fclose(f);
    return 0;
}

static int open_mem(int pid) {
    char p[256];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY | O_LARGEFILE);
    if (fd < 0) fprintf(stderr, "[!] 打不开 %s: %s\n", p, strerror(errno));
    return fd;
}

// ---- 分页 dump [start,end):pread64 读取,失败零填充继续(守护页/BSS/段间隙)----
static int dump_range(int memfd, uint64_t start, uint64_t end, const char *outpath) {
    FILE *out = fopen(outpath, "wb");
    if (!out) {
        fprintf(stderr, "[!] 打不开输出 %s: %s\n", outpath, strerror(errno));
        return -1;
    }
    uint64_t size = end - start;
    uint8_t  page[PAGE_SIZE];
    uint8_t  zero[PAGE_SIZE];
    memset(zero, 0, PAGE_SIZE);

    // sidecar:持久化基址等信息,供后续修 ELF(段偏移对齐回 vaddr)用
    char infop[640];
    snprintf(infop, sizeof(infop), "%s.info.txt", outpath);
    FILE *inf = fopen(infop, "w");
    if (inf) {
        fprintf(inf, "base: 0x%" PRIx64 "\n", start);
        fprintf(inf, "end:  0x%" PRIx64 "\n", end);
        fprintf(inf, "size: 0x%" PRIx64 " (%" PRIu64 ")\n", size, size);
        fprintf(inf, "dump: %s\n", outpath);
        fprintf(inf, "note: 内存镜像,修复时 p_offset=p_vaddr、section 对齐到 vaddr\n");
        fclose(inf);
    }

    uint64_t read_ok = 0, read_fail = 0, off = 0;
    printf("[+] dump 0x%" PRIx64 " - 0x%" PRIx64 "  (0x%" PRIx64 " / %.1f KB)\n",
           start, end, size, size / 1024.0);

    while (off < size) {
        uint64_t chunk = (size - off < PAGE_SIZE) ? (size - off) : PAGE_SIZE;
        ssize_t n = pread64(memfd, page, chunk, (off64_t)(start + off));
        if (n == (ssize_t)chunk) {
            fwrite(page, 1, chunk, out);
            read_ok += chunk;
        } else {
            // EIO/短读:守护页或不可达,零填充保持偏移对齐
            fwrite(zero, 1, chunk, out);
            read_fail += chunk;
        }
        off += PAGE_SIZE;

        if (off % (2 * 1024 * 1024) == 0) {
            printf("    %.1f%%  (ok=%" PRIu64 "KB fail=%" PRIu64 "KB)\n",
                   off * 100.0 / size, read_ok / 1024, read_fail / 1024);
        }
    }
    fclose(out);
    printf("[+] 完成 -> %s\n", outpath);
    printf("    可读 %" PRIu64 " KB (%.1f%%), 零填充 %" PRIu64 " KB\n",
           read_ok / 1024, read_ok * 100.0 / (size ? size : 1), read_fail / 1024);
    return 0;
}

// 读某地址前 4 字节判断 ELF 魔数
static int is_elf_at(int memfd, uint64_t addr) {
    uint8_t m[4];
    ssize_t n = pread64(memfd, m, 4, (off64_t)addr);
    return (n == 4 && m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F');
}

static void out_path_for(const char *soName, char *buf, size_t n) {
    const char *dir = getenv("OUT_DIR");
    if (!dir || !*dir) dir = "/data/local/tmp";
    snprintf(buf, n, "%s/%s.dump", dir, soName);
}

// ---- 模式:按名 dump。收集所有 basename 匹配的 VMA,取 min(start)~max(end) 整段 ----
static int mode_module(int pid, int memfd, const char *soName) {
    uint64_t base = 0, end = 0;
    int hits = 0;
    printf("[*] 匹配 maps 中的 %s:\n", soName);
    for (int i = 0; i < g_nregion; i++) {
        const char *b = basename_of(g_regions[i].path);
        if (strcmp(b, soName) == 0 || strncmp(b, soName, strlen(soName)) == 0) {
            if (b[0] == 0) continue;
            printf("    0x%" PRIx64 "-0x%" PRIx64 " %s %s\n",
                   g_regions[i].start, g_regions[i].end, g_regions[i].perm, g_regions[i].path);
            if (hits == 0 || g_regions[i].start < base) base = g_regions[i].start;
            if (hits == 0 || g_regions[i].end > end) end = g_regions[i].end;
            hits++;
        }
    }
    if (hits == 0) {
        fprintf(stderr, "[-] maps 里没有 %s。试试 'scan' 列 ELF 头区间,或 'range' 手动指定。\n", soName);
        return -1;
    }
    char outp[PATH_MAX_];
    out_path_for(soName, outp, sizeof(outp));
    return dump_range(memfd, base, end, outp);
}

static int mode_range(int pid, int memfd, uint64_t base, uint64_t size) {
    char outp[PATH_MAX_];
    char name[64];
    snprintf(name, sizeof(name), "manual_%" PRIx64, base);
    out_path_for(name, outp, sizeof(outp));
    return dump_range(memfd, base, base + size, outp);
}

static int mode_scan(int pid, int memfd) {
    int found = 0;
    printf("[*] 带 ELF 头(\\x7fELF)的区间:\n");
    for (int i = 0; i < g_nregion; i++) {
        region_t *r = &g_regions[i];
        if (r->perm[0] != 'r') continue;   // 不可读跳过
        if (r->off != 0) continue;          // ELF 头在映射起点,off 必为 0
        if (is_elf_at(memfd, r->start)) {
            printf("    0x%" PRIx64 "-0x%" PRIx64 " %s %s\n",
                   r->start, r->end, r->perm, r->path[0] ? r->path : "[anon]");
            found++;
        }
    }
    if (!found) printf("    (无;可能被匿名化或分块加载)\n");
    return 0;
}

static int mode_allexec(int pid, int memfd) {
    int cnt = 0;
    for (int i = 0; i < g_nregion; i++) {
        region_t *r = &g_regions[i];
        if (r->perm[0] != 'r') continue;
        if (r->off != 0) continue;
        if (!is_elf_at(memfd, r->start)) continue;
        const char *b = r->path[0] ? basename_of(r->path) : NULL;
        char name[96];
        if (b && *b) snprintf(name, sizeof(name), "%s", b);
        else snprintf(name, sizeof(name), "elf_%" PRIx64, r->start);
        char outp[PATH_MAX_];
        out_path_for(name, outp, sizeof(outp));
        dump_range(memfd, r->start, r->end, outp);
        cnt++;
    }
    printf("[*] allexec: dump 了 %d 个 ELF 区间\n", cnt);
    return 0;
}

static int mode_list(int pid) {
    printf("[*] maps 中的 .so 区间:\n");
    for (int i = 0; i < g_nregion; i++) {
        if (strstr(g_regions[i].path, ".so")) {
            printf("    0x%" PRIx64 "-0x%" PRIx64 " %s %s\n",
                   g_regions[i].start, g_regions[i].end, g_regions[i].perm, g_regions[i].path);
        }
    }
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "用法:\n"
        "  %s <pid|包名> module  <soName>\n"
        "  %s <pid|包名> range   <hexBase> <hexSize>\n"
        "  %s <pid|包名> scan\n"
        "  %s <pid|包名> allexec\n"
        "  %s <pid|包名> list\n"
        "输出目录: 环境变量 OUT_DIR,默认 /data/local/tmp\n",
        argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc < 3) { usage(argv[0]); return 1; }

    // 解析 pid:纯数字当 pid,否则当包名查
    int pid;
    const char *target = argv[1];
    int all_digit = 1;
    for (const char *p = target; *p; p++) if (!isdigit((unsigned char)*p)) { all_digit = 0; break; }
    if (all_digit) {
        pid = atoi(target);
    } else {
        pid = find_pid_by_name(target);
        if (pid < 0) { fprintf(stderr, "[-] 找不到进程: %s\n", target); return 1; }
        printf("[*] %s -> pid %d\n", target, pid);
    }

    if (read_maps(pid) != 0) return 1;
    printf("[*] 读到 %d 个 maps 区间\n", g_nregion);

    const char *mode = argv[2];

    if (strcmp(mode, "list") == 0) {
        return mode_list(pid);
    }

    int memfd = open_mem(pid);
    if (memfd < 0) return 1;

    int rc = 0;
    if (strcmp(mode, "module") == 0) {
        if (argc < 4) { usage(argv[0]); rc = 1; }
        else rc = mode_module(pid, memfd, argv[3]);
    } else if (strcmp(mode, "range") == 0) {
        if (argc < 5) { usage(argv[0]); rc = 1; }
        else {
            uint64_t base = strtoull(argv[3], NULL, 16);
            uint64_t size = strtoull(argv[4], NULL, 16);
            rc = mode_range(pid, memfd, base, size);
        }
    } else if (strcmp(mode, "scan") == 0) {
        rc = mode_scan(pid, memfd);
    } else if (strcmp(mode, "allexec") == 0) {
        rc = mode_allexec(pid, memfd);
    } else {
        usage(argv[0]); rc = 1;
    }

    close(memfd);
    return rc;
}

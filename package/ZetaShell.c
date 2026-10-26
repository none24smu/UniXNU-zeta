// SPDX-License-Identifier: BSD-2-Clause-Patent
// A command shell in the kernel on the USB log (zeta-shell=1, the default; zeta-shell=0 leaves it out). The host writes
// "<id> <command> [arguments]\n" to the log's OUT endpoint (scripts/zeta-shell.py through capture-usb-log.py's send file);
// UniXNU native-dwc3-console.c keeps the bytes for unixnu_dwc3_read. Every reply line is "@z<id>|<text>" and the reply
// ends with "@z<id>.<status>", so the host can pick its reply out of the interleaved log. It runs in its own kernel thread,
// so it works while userland is stuck, and needs nothing signed: processes, files of the root and Data volumes, sysctls,
// physical memory, MMIO and the I/O Registry (ZetaShellIo.cpp) can be read, and changed, without a rebuild or a reboot.
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/signal.h>
#include <mach/mach_types.h>
#include <pexpert/pexpert.h>
#include <stdarg.h>
#include <string.h>

// sys/systm.h's: it needs the BSD prefix header for its lock configuration, which these units are built without.
extern int printf(const char *, ...) __attribute__((format(printf, 1, 2)));
extern int snprintf(char *, size_t, const char *, ...) __attribute__((format(printf, 3, 4)));
extern int vsnprintf(char *, size_t, const char *, va_list) __attribute__((format(printf, 3, 0)));
extern kern_return_t kernel_thread_start(thread_continue_t, void *, thread_t *);
extern void thread_deallocate(thread_t);
extern void IOSleep(unsigned int milliseconds);
extern uint64_t mach_absolute_time(void);
extern task_t proc_task(proc_t);
// xnu-12377 kern_proc.c (proc.h declares it only outside XNU_KERNEL_PRIVATE).
extern const char *proc_best_name(proc_t);
extern int kernel_sysctlbyname(const char *, void *, size_t *, void *, size_t);
extern uint64_t get_task_phys_footprint(task_t);
extern int unlink1(vfs_context_t, vnode_t, user_addr_t, enum uio_seg, int);
extern unsigned long long ml_phys_read_double_64(unsigned long long paddr);
extern vm_offset_t ml_io_map(vm_offset_t phys_addr, vm_size_t size);
extern void ml_io_unmap(vm_offset_t addr, vm_size_t sz);
// xnu-12377 proc_internal.h.
extern void proc_iterate(unsigned int, int (*)(proc_t, void *), void *, int (*)(proc_t, void *), void *);
#define SHELL_PROC_RETURNED 0
#define SHELL_PROC_ALLPROCLIST (1U << 0)
#define SHELL_PROC_NOWAITTRANS (1U << 2)
// UniXNU native-dwc3-console.c; absent from a kernel without the USB console.
extern unsigned int unixnu_dwc3_read(uint8_t *, unsigned int) __attribute__((weak_import));
extern unsigned int unixnu_dwc3_backlog(void) __attribute__((weak_import));
extern volatile uint64_t unixnu_dwc3_received_dropped __attribute__((weak_import));
// ZetaShellIo.cpp.
extern int zeta_shell_ioreg(const char *root, unsigned depth);
extern int zeta_shell_props(const char *name, unsigned index);

static unsigned reply_id;

// Wait while the USB output ring is over half full: a long reply then slows down instead of dropping log text.
static void wait_for_room(void) {
    if (!unixnu_dwc3_backlog) return;
    for (unsigned i = 0; i < 1000 && unixnu_dwc3_backlog() > 16384; ++i) IOSleep(2);
}

__attribute__((format(printf, 1, 2))) void zeta_shell_line(const char *format, ...) {
    char line[512];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(line, sizeof line, format, arguments);
    va_end(arguments);
    wait_for_room();
    printf("@z%u|%s\n", reply_id, line);
}

static unsigned long long number(const char *text, int *ok) {
    unsigned long long value = 0;
    unsigned base = 10;
    *ok = text && *text;
    if (!*ok) return 0;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) base = 16, text += 2;
    else if (text[0] == '0' && text[1]) base = 8, ++text;
    for (; *text; ++text) {
        unsigned digit = (*text >= '0' && *text <= '9') ? (unsigned)(*text - '0') :
            (*text >= 'a' && *text <= 'f') ? (unsigned)(*text - 'a' + 10) : (*text >= 'A' && *text <= 'F') ? (unsigned)(*text - 'A' + 10) : 99;
        if (digit >= base) {*ok = 0; return 0;}
        value = value * base + digit;
    }
    return value;
}

// ---- processes ----
static int every_process(proc_t p, void *arg) {(void)p; (void)arg; return 1;}
static int process_row(proc_t p, void *arg) {
    (void)arg;
    task_t task = proc_task(p);
    zeta_shell_line("%6d %6d %8llu %s", proc_pid(p), proc_ppid(p), task ? get_task_phys_footprint(task) / 1024 : 0ULL, proc_best_name(p));
    return SHELL_PROC_RETURNED;
}
static int ps(void) {
    zeta_shell_line("   pid   ppid  foot-KB name");
    proc_iterate(SHELL_PROC_ALLPROCLIST | SHELL_PROC_NOWAITTRANS, process_row, NULL, every_process, NULL);
    return 0;
}

// ---- files ----
// VNOP_READDIR without VNODE_READDIR_EXTENDED: the 32-bit inode dirent of bsd/sys/dirent.h.
struct shell_dirent {
    uint32_t d_ino;
    uint16_t d_reclen;
    uint8_t d_type;
    uint8_t d_namlen;
    char d_name[256];
};

static const char *base_name(const char *path) {
    const char *name = path;
    for (const char *p = path; *p; ++p) if (*p == '/') name = p + 1;
    return name;
}

static int file_stat(const char *path, vfs_context_t context, int quiet_name) {
    vnode_t vp = NULLVP;
    int error = vnode_lookup(path, 0, &vp, context);
    if (error) {zeta_shell_line("%s: error %d", path, error); return error;}
    struct vnode_attr va;
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_data_size);
    VATTR_WANTED(&va, va_mode);
    VATTR_WANTED(&va, va_uid);
    VATTR_WANTED(&va, va_gid);
    error = vnode_getattr(vp, &va, context);
    const char type = vnode_isdir(vp) ? 'd' : vnode_islnk(vp) ? 'l' : vnode_isreg(vp) ? '-' : '?';
    if (error) zeta_shell_line("%s: getattr error %d", path, error);
    else zeta_shell_line("%c%04o %4u %4u %10llu %s", type, (unsigned)(va.va_mode & 07777), va.va_uid, va.va_gid,
                         (unsigned long long)va.va_data_size, quiet_name ? base_name(path) : path);
    vnode_put(vp);
    return error;
}

static int list(const char *path, int detail) {
    vfs_context_t context = vfs_context_create(NULL);
    vnode_t vp = NULLVP;
    int error = vnode_lookup(path, 0, &vp, context);
    if (error) {zeta_shell_line("%s: error %d", path, error); vfs_context_rele(context); return error;}
    if (!vnode_isdir(vp)) {
        vnode_put(vp);
        error = file_stat(path, context, 0);
        vfs_context_rele(context);
        return error;
    }
    static char buffer[8192];
    static char child[1024];
    off_t offset = 0;
    int eof = 0;
    unsigned entries = 0;
    while (!eof && !error) {
        uio_t uio = uio_create(1, offset, UIO_SYSSPACE, UIO_READ);
        uio_addiov(uio, (user_addr_t)(uintptr_t)buffer, sizeof buffer);
        int count = 0;
        error = VNOP_READDIR(vp, uio, 0, &eof, &count, context);
        const size_t got = sizeof buffer - (size_t)uio_resid(uio);
        offset = uio_offset(uio);
        uio_free(uio);
        if (error || !got) break;
        for (size_t at = 0; at + 8 <= got;) {
            const struct shell_dirent *entry = (const struct shell_dirent *)(void *)(buffer + at);
            if (!entry->d_reclen) break;
            at += entry->d_reclen;
            char name[256];
            const unsigned length = entry->d_namlen < 255 ? entry->d_namlen : 255;
            memcpy(name, entry->d_name, length);
            name[length] = 0;
            if (!entry->d_ino || !strcmp(name, ".") || !strcmp(name, "..")) continue;
            ++entries;
            if (detail) {
                snprintf(child, sizeof child, "%s%s%s", path, path[strlen(path) - 1] == '/' ? "" : "/", name);
                file_stat(child, context, 1);
            } else zeta_shell_line("%c %s", entry->d_type == 4 ? 'd' : entry->d_type == 10 ? 'l' : entry->d_type == 8 ? '-' : '?', name);
        }
    }
    zeta_shell_line("%u entries%s", entries, error ? " (readdir error)" : "");
    vnode_put(vp);
    vfs_context_rele(context);
    return error;
}

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// cat: text, non-printing bytes as '.'; hex: 16 bytes a line; get: base64, 288 bytes a line, for the host to reassemble.
enum dump_kind {kText, kHex, kBase64};
static int dump(const char *path, unsigned long long offset, unsigned long long length, enum dump_kind kind) {
    vfs_context_t context = vfs_context_create(NULL);
    vnode_t vp = NULLVP;
    int error = vnode_open(path, FREAD, 0, 0, &vp, context);
    if (error) {zeta_shell_line("%s: open error %d", path, error); vfs_context_rele(context); return error;}
    static char buffer[4096];
    char line[400];
    unsigned used = 0;
    unsigned long long done = 0;
    while (done < length) {
        const int want = (int)((length - done) < (kind == kBase64 ? 288 * 14 : sizeof buffer) ? (length - done) : (kind == kBase64 ? 288 * 14 : sizeof buffer));
        int resid = 0;
        error = vn_rdwr(UIO_READ, vp, buffer, want, (off_t)(offset + done), UIO_SYSSPACE, IO_NOAUTH, vfs_context_ucred(context), &resid,
                        vfs_context_proc(context));
        const int got = want - resid;
        if (error || got <= 0) break;
        if (kind == kHex) {
            for (int at = 0; at < got; at += 16) {
                int n = snprintf(line, sizeof line, "%08llx ", offset + done + (unsigned long long)at);
                for (int i = 0; i < 16; ++i) n += at + i < got ? snprintf(line + n, sizeof line - (size_t)n, " %02x", (uint8_t)buffer[at + i]) : snprintf(line + n, sizeof line - (size_t)n, "   ");
                n += snprintf(line + n, sizeof line - (size_t)n, "  ");
                for (int i = 0; i < 16 && at + i < got; ++i) line[n++] = (buffer[at + i] >= 32 && buffer[at + i] < 127) ? buffer[at + i] : '.';
                line[n] = 0;
                zeta_shell_line("%s", line);
            }
        } else if (kind == kBase64) {
            for (int at = 0; at < got; at += 288) {
                const int chunk = got - at < 288 ? got - at : 288;
                int n = 0;
                for (int i = 0; i < chunk; i += 3) {
                    const uint32_t v = ((uint32_t)(uint8_t)buffer[at + i] << 16) | (i + 1 < chunk ? (uint32_t)(uint8_t)buffer[at + i + 1] << 8 : 0) |
                                       (i + 2 < chunk ? (uint8_t)buffer[at + i + 2] : 0);
                    line[n++] = base64[(v >> 18) & 63];
                    line[n++] = base64[(v >> 12) & 63];
                    line[n++] = i + 1 < chunk ? base64[(v >> 6) & 63] : '=';
                    line[n++] = i + 2 < chunk ? base64[v & 63] : '=';
                }
                line[n] = 0;
                zeta_shell_line("%s", line);
            }
        } else {
            for (int i = 0; i < got; ++i) {
                const char c = buffer[i];
                if (c == '\n' || used == 200) {line[used] = 0; zeta_shell_line("%s", line); used = 0; if (c == '\n') continue;}
                line[used++] = (c >= 32 && c < 127) || c == '\t' ? c : '.';
            }
        }
        done += (unsigned long long)got;
        if (got < want) break;
    }
    if (kind == kText && used) {line[used] = 0; zeta_shell_line("%s", line);}
    if (kind == kBase64) zeta_shell_line("bytes %llu", done);
    vnode_close(vp, FREAD, context);
    vfs_context_rele(context);
    return error;
}

static int decode_base64(const char *text, uint8_t *out, size_t capacity, size_t *length) {
    uint32_t value = 0;
    unsigned bits = 0;
    size_t n = 0;
    for (; *text && *text != '='; ++text) {
        const char c = *text;
        const int digit = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26 : c >= '0' && c <= '9' ? c - '0' + 52 :
                          c == '+' ? 62 : c == '/' ? 63 : -1;
        if (digit < 0) return EINVAL;
        value = (value << 6) | (uint32_t)digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n == capacity) return E2BIG;
            out[n++] = (uint8_t)(value >> bits);
        }
    }
    *length = n;
    return 0;
}

// put <path> <offset> <base64>: offset 0 creates or truncates the file (mode 0644, owner root), later chunks write at offset.
static int put(const char *path, const char *offset_text, const char *data) {
    int ok;
    const unsigned long long offset = number(offset_text, &ok);
    if (!ok || !data) {zeta_shell_line("usage: put <path> <offset> <base64>"); return EINVAL;}
    static uint8_t bytes[3072];
    size_t length = 0;
    int error = decode_base64(data, bytes, sizeof bytes, &length);
    if (error) {zeta_shell_line("bad base64 (%d)", error); return error;}
    vfs_context_t context = vfs_context_create(NULL);
    vnode_t vp = NULLVP;
    const int mode = FWRITE | (offset ? 0 : (O_CREAT | O_TRUNC));
    error = vnode_open(path, mode, 0644, 0, &vp, context);
    if (error) {zeta_shell_line("%s: open error %d", path, error); vfs_context_rele(context); return error;}
    int resid = 0;
    error = vn_rdwr(UIO_WRITE, vp, (caddr_t)bytes, (int)length, (off_t)offset, UIO_SYSSPACE, IO_NOAUTH | IO_SYNC, vfs_context_ucred(context), &resid,
                    vfs_context_proc(context));
    vnode_close(vp, FWRITE, context);
    vfs_context_rele(context);
    zeta_shell_line("wrote %zu at %llu%s", length - (size_t)resid, offset, error ? " (error)" : "");
    return error;
}

static int set_owner_or_mode(const char *path, const char *first, const char *second, int mode_only) {
    int ok1, ok2 = 1;
    const unsigned long long a = number(first, &ok1), b = mode_only ? 0 : number(second, &ok2);
    if (!ok1 || !ok2) {zeta_shell_line(mode_only ? "usage: chmod <path> <octal mode>" : "usage: chown <path> <uid> <gid>"); return EINVAL;}
    vfs_context_t context = vfs_context_create(NULL);
    vnode_t vp = NULLVP;
    int error = vnode_lookup(path, 0, &vp, context);
    if (!error) {
        struct vnode_attr va;
        VATTR_INIT(&va);
        if (mode_only) VATTR_SET(&va, va_mode, (mode_t)a);
        else {VATTR_SET(&va, va_uid, (uid_t)a); VATTR_SET(&va, va_gid, (gid_t)b);}
        error = vnode_setattr(vp, &va, context);
        vnode_put(vp);
    }
    vfs_context_rele(context);
    if (!error) file_stat(path, vfs_context_current(), 0);
    else zeta_shell_line("%s: error %d", path, error);
    return error;
}

static int remove_file(const char *path) {
    vfs_context_t context = vfs_context_create(NULL);
    const int error = unlink1(context, NULLVP, (user_addr_t)(uintptr_t)path, UIO_SYSSPACE, 0);
    vfs_context_rele(context);
    zeta_shell_line("%s: %s %d", path, error ? "error" : "removed", error);
    return error;
}

// ---- kernel state ----
static int sysctl_command(const char *name, const char *value_text) {
    static uint8_t value[1024];
    size_t length = sizeof value;
    int error;
    if (value_text) {
        int ok;
        const unsigned long long wanted = number(value_text, &ok);
        int as_int = (int)wanted;
        if (!ok) {zeta_shell_line("value must be a number"); return EINVAL;}
        error = kernel_sysctlbyname(name, value, &length, &as_int, sizeof as_int);
    } else error = kernel_sysctlbyname(name, value, &length, NULL, 0);
    if (error) {zeta_shell_line("%s: error %d", name, error); return error;}
    int printable = length > 0;
    for (size_t i = 0; i < length; ++i) if ((value[i] < 32 || value[i] > 126) && !(value[i] == 0 && i == length - 1)) printable = 0;
    if (length == 4 && !printable) zeta_shell_line("%s = %d (%#x)", name, *(int32_t *)(void *)value, *(uint32_t *)(void *)value);
    else if (length == 8 && !printable) zeta_shell_line("%s = %lld (%#llx)", name, *(long long *)(void *)value, *(unsigned long long *)(void *)value);
    else if (printable) {value[length < sizeof value ? length : sizeof value - 1] = 0; zeta_shell_line("%s = %s", name, (const char *)value);}
    else for (size_t at = 0; at < length; at += 32) {
        char line[100];
        int n = 0;
        for (size_t i = at; i < length && i < at + 32; ++i) n += snprintf(line + n, sizeof line - (size_t)n, "%02x", value[i]);
        zeta_shell_line("%s[%zu] %s", name, at, line);
    }
    return 0;
}

// phys: DRAM through the physical aperture. mmio: a device page mapped for the read; an address the hypervisor or TZ owns
// (the APSS watchdog at 0x17c10000) stalls the CPU, so only read registers whose owner is known.
static int memory(const char *address_text, const char *count_text, int device) {
    int ok, ok2 = 1;
    const unsigned long long address = number(address_text, &ok);
    unsigned long long count = count_text ? number(count_text, &ok2) : 1;
    if (!ok || !ok2 || (address & 3)) {zeta_shell_line("usage: %s <address, 4-byte aligned> [words]", device ? "mmio" : "phys"); return EINVAL;}
    if (count > 256) count = 256;
    if (!device) {
        for (unsigned long long i = 0; i < count; i += 2)
            zeta_shell_line("%010llx %016llx", address + i * 4, ml_phys_read_double_64((address + i * 4) & ~7ULL));
        return 0;
    }
    const unsigned long long page = address & ~0xfffULL, end = (address + count * 4 + 0xfff) & ~0xfffULL;
    const vm_offset_t mapped = ml_io_map((vm_offset_t)page, (vm_size_t)(end - page));
    if (!mapped) {zeta_shell_line("map failed"); return ENOMEM;}
    for (unsigned long long i = 0; i < count; i += 4) {
        char line[100];
        int n = snprintf(line, sizeof line, "%010llx", address + i * 4);
        for (unsigned long long j = i; j < count && j < i + 4; ++j)
            n += snprintf(line + n, sizeof line - (size_t)n, " %08x", *(volatile uint32_t *)(mapped + (address - page) + j * 4));
        zeta_shell_line("%s", line);
    }
    ml_io_unmap(mapped, (vm_size_t)(end - page));
    return 0;
}

static int mmio_write(const char *address_text, const char *value_text) {
    int ok, ok2;
    const unsigned long long address = number(address_text, &ok), value = number(value_text, &ok2);
    if (!ok || !ok2 || (address & 3)) {zeta_shell_line("usage: mmiow <address, 4-byte aligned> <value>"); return EINVAL;}
    const vm_offset_t mapped = ml_io_map((vm_offset_t)(address & ~0xfffULL), 0x1000);
    if (!mapped) {zeta_shell_line("map failed"); return ENOMEM;}
    volatile uint32_t *word = (volatile uint32_t *)(mapped + (address & 0xfff));
    *word = (uint32_t)value;
    __asm__ volatile("dsb sy" ::: "memory");
    zeta_shell_line("%010llx <- %08x, reads %08x", address, (uint32_t)value, *word);
    ml_io_unmap(mapped, 0x1000);
    return 0;
}

static void reboot_to_bootloader(void) {
    // PSCI SYSTEM_RESET; the firmware set the bootloader reason before handoff (as the console's ZETA:REBOOT-BOOTLOADER).
    register uint64_t x0 __asm__("x0") = 0x84000009;
    __asm__ volatile("smc #0" : "+r"(x0) :: "x1", "x2", "x3", "memory");
}

static void help(void) {
    static const char *const lines[] = {
        "ps                         processes: pid ppid footprint name",
        "kill <pid> [signal]        signal a process (default 15; launchd restarts a daemon it keeps alive)",
        "ls <path> | ll <path>      directory names | mode uid gid size of each entry",
        "stat <path>                mode uid gid size",
        "cat <path> [off] [len]     text (64 KiB by default)",
        "hex <path> [off] [len]     hex dump (4 KiB by default)",
        "get <path> [off] [len]     base64 for the host (zeta-shell.py get/plist)",
        "put <path> <off> <b64>     write; offset 0 creates/truncates (zeta-shell.py put)",
        "rm <path>                  unlink",
        "chown <path> <uid> <gid> | chmod <path> <mode>",
        "sysctl <name> [int]        read, or set an integer",
        "phys <pa> [words] | mmio <pa> [words] | mmiow <pa> <value>",
        "ioreg [name|class] [depth] I/O Registry service plane",
        "props <name|class> [index] properties of a registry entry",
        "uptime | echo <text> | reboot (to the bootloader)",
    };
    for (unsigned i = 0; i < sizeof lines / sizeof lines[0]; ++i) zeta_shell_line("%s", lines[i]);
}

static int run(char *text) {
    char *argv[8] = {0};
    int argc = 0;
    for (char *p = text; *p && argc < 8;) {
        while (*p == ' ') *p++ = 0;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ') ++p;
    }
    if (!argc) return 0;
    const char *c = argv[0];
    int ok;
    if (!strcmp(c, "help")) {help(); return 0;}
    if (!strcmp(c, "echo")) {zeta_shell_line("%s", argc > 1 ? argv[1] : ""); return 0;}
    if (!strcmp(c, "uptime")) {
        zeta_shell_line("%llu s, received bytes dropped %llu", mach_absolute_time() / 19200000ULL, &unixnu_dwc3_received_dropped ? unixnu_dwc3_received_dropped : 0ULL);
        return 0;
    }
    if (!strcmp(c, "ps")) return ps();
    if (!strcmp(c, "kill") && argc >= 2) {
        const int pid = (int)number(argv[1], &ok);
        int ok2 = 1;
        const int signal = argc > 2 ? (int)number(argv[2], &ok2) : SIGTERM;
        if (!ok || !ok2 || pid <= 1) {zeta_shell_line("usage: kill <pid > 1> [signal]"); return EINVAL;}
        proc_signal(pid, signal);
        zeta_shell_line("signal %d -> %d", signal, pid);
        return 0;
    }
    if ((!strcmp(c, "ls") || !strcmp(c, "ll")) && argc >= 2) return list(argv[1], c[1] == 'l');
    if (!strcmp(c, "stat") && argc >= 2) {
        vfs_context_t context = vfs_context_create(NULL);
        const int error = file_stat(argv[1], context, 0);
        vfs_context_rele(context);
        return error;
    }
    if ((!strcmp(c, "cat") || !strcmp(c, "hex") || !strcmp(c, "get")) && argc >= 2) {
        int ok1 = 1, ok2 = 1;
        const unsigned long long offset = argc > 2 ? number(argv[2], &ok1) : 0;
        const enum dump_kind kind = c[0] == 'c' ? kText : c[0] == 'h' ? kHex : kBase64;
        const unsigned long long length = argc > 3 ? number(argv[3], &ok2) : kind == kText ? 65536 : kind == kHex ? 4096 : ~0ULL;
        if (!ok1 || !ok2) {zeta_shell_line("usage: %s <path> [offset] [length]", c); return EINVAL;}
        return dump(argv[1], offset, length, kind);
    }
    if (!strcmp(c, "put") && argc >= 4) return put(argv[1], argv[2], argv[3]);
    if (!strcmp(c, "rm") && argc >= 2) return remove_file(argv[1]);
    if (!strcmp(c, "chown") && argc >= 4) return set_owner_or_mode(argv[1], argv[2], argv[3], 0);
    if (!strcmp(c, "chmod") && argc >= 3) return set_owner_or_mode(argv[1], argv[2], NULL, 1);
    if (!strcmp(c, "sysctl") && argc >= 2) return sysctl_command(argv[1], argc > 2 ? argv[2] : NULL);
    if ((!strcmp(c, "phys") || !strcmp(c, "mmio")) && argc >= 2) return memory(argv[1], argc > 2 ? argv[2] : NULL, c[0] == 'm');
    if (!strcmp(c, "mmiow") && argc >= 3) return mmio_write(argv[1], argv[2]);
    if (!strcmp(c, "ioreg")) {
        int ok2 = 1;
        const unsigned depth = argc > 2 ? (unsigned)number(argv[2], &ok2) : argc > 1 ? 2 : 3;
        return zeta_shell_ioreg(argc > 1 && strcmp(argv[1], "-") ? argv[1] : NULL, ok2 ? depth : 2);
    }
    if (!strcmp(c, "props") && argc >= 2) {
        int ok2 = 1;
        const unsigned index = argc > 2 ? (unsigned)number(argv[2], &ok2) : 0;
        return zeta_shell_props(argv[1], ok2 ? index : 0);
    }
    if (!strcmp(c, "reboot")) {zeta_shell_line("returning to the bootloader"); IOSleep(200); reboot_to_bootloader(); return EIO;}
    zeta_shell_line("unknown command or missing arguments: %s (try help)", c);
    return EINVAL;
}

static void shell_thread(void *parameter, wait_result_t result) {
    (void)parameter;
    (void)result;
    static char line[4096];
    unsigned length = 0;
    int overflow = 0;
    printf("zeta-shell: ready (scripts/zeta-shell.py)\n");
    for (;;) {
        uint8_t chunk[256];
        const unsigned count = unixnu_dwc3_read(chunk, sizeof chunk);
        if (!count) {IOSleep(20); continue;}
        for (unsigned i = 0; i < count; ++i) {
            const char c = (char)chunk[i];
            if (c == '\r' || c == 0) continue;
            if (c != '\n') {
                if (length < sizeof line - 1) line[length++] = c;
                else overflow = 1;
                continue;
            }
            line[length] = 0;
            // "\0ZETA:..." console frames end up here too; they are the console's, not the shell's.
            char *text = line;
            reply_id = 0;
            if (*text >= '0' && *text <= '9') {
                while (*text >= '0' && *text <= '9') reply_id = reply_id * 10 + (unsigned)(*text++ - '0');
                while (*text == ' ') ++text;
            }
            if (!strncmp(line, "ZETA:", 5)) {length = 0; continue;}
            int status;
            if (overflow) {zeta_shell_line("line longer than %zu bytes", sizeof line - 1); status = E2BIG;}
            else status = run(text);
            wait_for_room();
            printf("@z%u.%d\n", reply_id, status);
            length = 0;
            overflow = 0;
        }
    }
}

void zeta_shell_start(void) {
    unsigned enabled = 1;
    PE_parse_boot_argn("zeta-shell", &enabled, sizeof enabled);
    if (!enabled || !unixnu_dwc3_read) return;
    thread_t thread = THREAD_NULL;
    if (kernel_thread_start(shell_thread, NULL, &thread) == KERN_SUCCESS) thread_deallocate(thread);
}

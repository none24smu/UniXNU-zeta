/* SPDX-License-Identifier: MIT
 * Native EL0 instruction experiment. Baseline arm64 build; faults are results.
 */
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

typedef uint64_t (*instruction_fn)(uint64_t, uint64_t, uint64_t *);
typedef struct {
    const char *name, *operation;
    unsigned bits, destination;
    int immediate;
    uint32_t instruction;
    instruction_fn function;
} Test;
#include "cases.h"
static sigjmp_buf jump;
static volatile sig_atomic_t armed, caught;
static void fault(int signal_number) {
    if (!armed) _exit(128 + signal_number);
    caught = signal_number;
    armed = 0;
    siglongjmp(jump, 1);
}
static uint64_t expected(const Test *t, uint64_t a, uint64_t b) {
    uint64_t mask = t->bits == 64 ? UINT64_MAX : UINT32_MAX;
    a &= mask; b &= mask;
    if (t->immediate != -999) b = (uint64_t)(int64_t)t->immediate & mask;
    uint64_t result = 0;
    if (!strcmp(t->operation, "umin")) result = a < b ? a : b;
    else if (!strcmp(t->operation, "umax")) result = a > b ? a : b;
    else if (!strcmp(t->operation, "smin") || !strcmp(t->operation, "smax")) {
        int64_t sa = t->bits == 64 ? (int64_t)a : (int32_t)a;
        int64_t sb = t->bits == 64 ? (int64_t)b : (int32_t)b;
        result = (uint64_t)(!strcmp(t->operation, "smin") ? (sa < sb ? sa : sb) : (sa > sb ? sa : sb));
    } else if (!strcmp(t->operation, "ctz")) result = a ? (unsigned)__builtin_ctzll(a) : t->bits;
    else if (!strcmp(t->operation, "cnt")) result = (unsigned)__builtin_popcountll(a);
    else if (!strcmp(t->operation, "abs")) {
        uint64_t sign = UINT64_C(1) << (t->bits - 1);
        result = a & sign ? (uint64_t)(0 - a) : a;
    }
    return result & mask;
}
static void feature(const char *name) {
    int64_t value = 0;
    size_t size = sizeof(value);
    errno = 0;
    int status = sysctlbyname(name, &value, &size, NULL, 0);
    printf("{\"kind\":\"sysctl\",\"name\":\"%s\",\"status\":%d,\"errno\":%d,\"size\":%zu,\"value\":%" PRId64 "}\n",
           name, status, errno, size, value);
}
static void capability(const char *name, instruction_fn fn, uint64_t input, uint64_t operand,
                       int exact, uint64_t want) {
    uint64_t flags = 0;
    volatile uint64_t output = 0;
    caught = 0;
    if (!sigsetjmp(jump, 1)) { armed = 1; output = fn(input, operand, &flags); armed = 0; }
    int semantic = !caught && (!exact || output == want);
    printf("{\"kind\":\"capability\",\"name\":\"%s\",\"signal\":%d,\"result\":\"0x%016" PRIx64 "\",\"semantic_pass\":%s}\n",
           name, caught, output, semantic ? "true" : "false");
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = fault;
    sigemptyset(&action.sa_mask);
    for (unsigned i = 0; i < 3; ++i) {
        int signals[] = {SIGILL, SIGSEGV, SIGBUS};
        if (sigaction(signals[i], &action, NULL)) return 126;
    }
    printf("{\"kind\":\"start\",\"pid\":%d,\"time\":%lld,\"target\":\"baseline-arm64\",\"tchange_executed\":false}\n", getpid(), (long long)time(NULL));
    typedef int (*csops_fn)(pid_t, unsigned int, void *, size_t);
    csops_fn csops_call = (csops_fn)dlsym(RTLD_DEFAULT, "csops");
    uint32_t csflags = 0;
    errno = 0;
    int csstatus = csops_call ? csops_call(getpid(), 0, &csflags, sizeof(csflags)) : -1;
    printf("{\"kind\":\"code-signing\",\"csops_present\":%s,\"status\":%d,\"errno\":%d,\"flags\":\"0x%08x\",\"platform_binary\":%s}\n",
           csops_call ? "true" : "false", csstatus, errno, csflags,
           !csstatus && (csflags & UINT32_C(0x04000000)) ? "true" : "false");
    unsigned char cdhash[20] = {0};
    int hashstatus = csops_call ? csops_call(getpid(), 5, cdhash, sizeof(cdhash)) : -1;
    printf("{\"kind\":\"code-directory\",\"status\":%d,\"cdhash\":\"", hashstatus);
    for (unsigned i = 0; i < sizeof(cdhash); ++i) printf("%02x", cdhash[i]);
    puts("\"}");
    const char *features[] = {
        "hw.cpufamily", "hw.cpusubfamily",
        "hw.optional.arm.FEAT_CSSC", "hw.optional.arm.FEAT_CPA", "hw.optional.arm.FEAT_CPA2",
        "hw.optional.arm.FEAT_PAuth", "hw.optional.arm.FEAT_PAuth_LR", "hw.optional.arm.FEAT_MTE",
        "hw.optional.arm.FEAT_SHA512", "hw.optional.arm.FEAT_LRCPC", "hw.optional.arm.FEAT_LRCPC2",
        "hw.optional.arm.FEAT_JSCVT",
        "hw.optional.arm.FEAT_GCS", "hw.optional.arm.FEAT_SVE", "hw.optional.arm.FEAT_SVE2",
        "hw.optional.arm.FEAT_SME", "hw.optional.arm.FEAT_SME2",
        "hw.optional.arm.FEAT_TME", "hw.optional.arm.FEAT_TPRO", NULL
    };
    for (unsigned i = 0; features[i]; ++i) feature(features[i]);
    caught = 0;
    volatile uint64_t capabilities = 0;
    if (!sigsetjmp(jump, 1)) {
        armed = 1;
        capabilities = *(volatile const uint64_t *)(uintptr_t)UINT64_C(0x0000000fffffc010);
        armed = 0;
    }
    printf("{\"kind\":\"commpage-capabilities64\",\"signal\":%d,\"value\":\"0x%016" PRIx64 "\"}\n", caught, capabilities);
    uint64_t edges[] = {0, 1, 16, UINT32_MAX, UINT64_MAX, UINT64_C(0x8000000000000000),
                        UINT64_C(0x80000000), UINT64_C(0xffffffff00000001), UINT64_C(0x55555555aaaaaaaa)};
    unsigned passed = 0, trapped = 0, failures = 0, completed = 0;
    for (unsigned i = 0; i < sizeof(tests) / sizeof(*tests); ++i) {
        const Test *t = &tests[i];
        unsigned case_pass = 0, case_fail = 0;
        caught = 0;
        for (volatile unsigned e = 0; e < sizeof(edges) / sizeof(*edges); ++e) {
            uint64_t a = edges[e], b = edges[(e + 3) % (sizeof(edges) / sizeof(*edges))];
            uint64_t flags = 0, output = 0;
            if (!sigsetjmp(jump, 1)) { armed = 1; output = t->function(a, b, &flags); armed = 0; }
            if (caught) break;
            uint64_t want = t->destination == 31 ? a : expected(t, a, b);
            if (output == want && flags == UINT64_C(0xa0000000)) ++case_pass;
            else { ++case_fail; printf("{\"kind\":\"mismatch\",\"name\":\"%s\",\"edge\":%u,\"output\":\"0x%016" PRIx64 "\",\"expected\":\"0x%016" PRIx64 "\",\"nzcv\":\"0x%016" PRIx64 "\"}\n", t->name, e, output, want, flags); }
        }
        if (caught) ++trapped;
        if (case_fail) ++failures;
        if (!caught && !case_fail) ++passed;
        printf("{\"kind\":\"cssc\",\"name\":\"%s\",\"instruction\":\"0x%08x\",\"signal\":%d,\"passed\":%u,\"failed\":%u}\n", t->name, t->instruction, caught, case_pass, case_fail);
        ++completed;
    }
    uint64_t load_value = UINT64_C(0x193427abcdef0123);
    capability("baseline-add", zeta_cap_add, 17, 25, 1, 42);
    capability("addpt", zeta_cap_addpt, 17, 25, 1, 42);
    capability("maddpt", zeta_cap_maddpt, 6, 7, 1, 42);
    capability("ldapur", zeta_cap_ldapur, (uintptr_t)&load_value, 0, 1, load_value);
    capability("mte-irg", zeta_cap_irg, (uintptr_t)&load_value, 0, 0, 0);
    capability("sha512h-zero", zeta_cap_sha512, 0, 0, 1, 0);
    capability("fjcvtzs-zero", zeta_cap_fjcvtzs, 0, 0, 1, 0);
    capability("fjcvtzs-positive-fraction", zeta_cap_fjcvtzs, UINT64_C(0x400e000000000000), 0, 1, 3);
    capability("fjcvtzs-negative-fraction", zeta_cap_fjcvtzs, UINT64_C(0xc006000000000000), 0, 1, UINT32_C(0xfffffffe));
    capability("fjcvtzs-modulo32", zeta_cap_fjcvtzs, UINT64_C(0x41f0000000100000), 0, 1, 1);
    capability("fjcvtzs-qnan", zeta_cap_fjcvtzs, UINT64_C(0x7ff8000000000000), 0, 1, 0);
    capability("fjcvtzs-infinity", zeta_cap_fjcvtzs, UINT64_C(0x7ff0000000000000), 0, 1, 0);
    capability("pauth-pacia-autia", zeta_cap_pauth, 17, 25, 1, 17);
    capability("pauth-lr-paired-leaf", zeta_cap_pauth_lr, 17, 0, 1, 17);
    capability("unallocated", zeta_cap_unallocated, 0, 0, 0, 0);
    caught = 0;
    volatile unsigned tpro_version = 0;
    if (!sigsetjmp(jump, 1)) {
        armed = 1;
        tpro_version = *(volatile const uint8_t *)(uintptr_t)UINT64_C(0x0000000fffffc10c);
        armed = 0;
    }
    printf("{\"kind\":\"commpage-tpro\",\"address\":\"0xfffffc10c\",\"signal\":%d,\"version\":%u}\n", caught, tpro_version);
    printf("{\"kind\":\"complete\",\"cssc_cases\":%u,\"passed\":%u,\"trapped\":%u,\"failures\":%u}\n", completed, passed, trapped, failures);
    return failures ? 1 : 0;
}

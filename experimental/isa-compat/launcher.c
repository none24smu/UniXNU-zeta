/* SPDX-License-Identifier: MIT */
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <spawn.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#ifndef ZETA_ISA_GATE
#define ZETA_ISA_GATE "/private/var/tmp/zeta-isa-go"
#endif
#ifndef ZETA_ISA_PROBE
#define ZETA_ISA_PROBE "/private/var/ngpu/addons/zeta-isa-probe/zeta-isa-probe"
#endif
#ifndef ZETA_GATE_UID
#define ZETA_GATE_UID 0
#endif
#ifndef ZETA_GATE_SECONDS
#define ZETA_GATE_SECONDS 900
#endif
#ifndef ZETA_GATE_ATTEMPTS
#define ZETA_GATE_ATTEMPTS 10
#endif
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    const char *gate = ZETA_ISA_GATE;
    char *const probe[] = {ZETA_ISA_PROBE, NULL};
    char *const platform[] = {"/private/var/ngpu/addons/zeta-isa-probe/zeta-isa-test", NULL};
    char *const gpu[] = {"/private/var/ngpu/addons/duo-air-probe/duo-air-shader-probe",
        "--backend", "/private/var/ngpu/addons/duo-air-probe/libduoair.dylib",
        "--library", "/private/var/ngpu/addons/duo-air-probe/duo-air-probe.metallib", NULL};
    time_t previous = 0;
    struct stat initial;
    if (!lstat(gate, &initial)) previous = initial.st_mtime;
    for (unsigned attempt = 0; attempt < ZETA_GATE_ATTEMPTS; ++attempt) {
        puts("zeta-isa-launcher: waiting for fresh /private/var/tmp/zeta-isa-go");
        unsigned seconds;
        char selection = 0;
        for (seconds = 0; seconds < ZETA_GATE_SECONDS; ++seconds) {
            struct stat s;
            if (!lstat(gate, &s) && S_ISREG(s.st_mode) && s.st_uid == ZETA_GATE_UID &&
                s.st_size == 2 && !(s.st_mode & 0022) && s.st_mtime != previous) {
                int fd = open(gate, O_RDONLY | O_NOFOLLOW);
                struct stat opened;
                char content[2] = {0};
                if (fd >= 0) {
                    if (!fstat(fd, &opened) && opened.st_dev == s.st_dev && opened.st_ino == s.st_ino &&
                        read(fd, content, sizeof(content)) == 2 && content[1] == '\n' &&
                        (content[0] == 'i' || content[0] == 'p' || content[0] == 'g')) selection = content[0];
                    close(fd);
                }
                if (selection) {
                    /* One approval token cannot replay after a launcher crash,
                     * timeout, job restart or failed child. Consume before spawn. */
                    if (unlink(gate)) return 126;
                    previous = s.st_mtime;
                    break;
                }
            }
            sleep(1);
        }
        if (seconds == ZETA_GATE_SECONDS) return 124;
        char *const *args = selection == 'g' ? gpu : selection == 'p' ? platform : probe;
        printf("zeta-isa-launcher: selection %c\n", selection);
        pid_t child;
        int error = posix_spawn(&child, args[0], NULL, NULL, args, environ);
        if (error) { fprintf(stderr, "zeta-isa-launcher: spawn error %d\n", error); return 127; }
        int status;
        if (waitpid(child, &status, 0) != child) return 127;
        printf("zeta-isa-launcher: child status %d\n", status);
        if (!WIFEXITED(status) || WEXITSTATUS(status) >= 124) return 125;
    }
    return 0;
}

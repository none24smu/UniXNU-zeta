/* SPDX-License-Identifier: MIT */
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <spawn.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    const char *gate = "/private/var/tmp/zeta-isa-go";
    char *const args[] = {"/private/var/ngpu/addons/zeta-isa-probe/zeta-isa-probe", NULL};
    time_t previous = 0;
    for (unsigned attempt = 0; attempt < 10; ++attempt) {
        puts("zeta-isa-launcher: waiting for fresh /private/var/tmp/zeta-isa-go");
        unsigned seconds;
        for (seconds = 0; seconds < 900; ++seconds) {
            struct stat s;
            if (!lstat(gate, &s) && S_ISREG(s.st_mode) && s.st_uid == 0 &&
                s.st_size == 2 && !(s.st_mode & 0022) && s.st_mtime != previous) {
                previous = s.st_mtime;
                break;
            }
            sleep(1);
        }
        if (seconds == 900) return 124;
        pid_t child;
        int error = posix_spawn(&child, args[0], NULL, NULL, args, environ);
        if (error) { fprintf(stderr, "zeta-isa-launcher: spawn error %d\n", error); return 127; }
        int status;
        if (waitpid(child, &status, 0) != child) return 127;
        printf("zeta-isa-launcher: child status %d\n", status);
        if (!WIFEXITED(status)) return 125;
    }
    return 0;
}

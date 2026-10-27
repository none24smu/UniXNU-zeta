/* SPDX-License-Identifier: MIT
 * Owner diagnostic launcher; opens no GPU before a fresh host gate.
 */
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;

int main(void) {
    const char *gate = "/private/var/tmp/duo-metal-go";
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    /* This is the same AGX tunnel used by the existing renderer and the
     * previously proven AIR probe. The service's type-0 path is unsupported
     * by the selected diagnostic kernel. */
    if (setenv("TU_DARWIN_SERVICE", "IOAcceleratorES", 1) ||
        setenv("TU_DARWIN_OPEN_TYPE", "0x4147", 1)) return 126;
    char *const args[] = {
        "/private/var/ngpu/addons/duo-metal-probe/duo-metal-probe",
        "--driver",
        "/private/var/ngpu/addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib",
        NULL
    };
    time_t previous = 0;
    for (unsigned attempt = 0; attempt < 10; ++attempt) {
        puts("duo-metal-launcher: waiting for /private/var/tmp/duo-metal-go; GPU unopened");
        unsigned seconds;
        for (seconds = 0; seconds < 600; ++seconds) {
            struct stat info;
            if (!lstat(gate, &info) && S_ISREG(info.st_mode) && info.st_uid == 0 &&
                info.st_size == 2 && !(info.st_mode & 0022) && info.st_mtime != previous) {
                previous = info.st_mtime;
                break;
            }
            sleep(1);
        }
        if (seconds == 600) {
            fputs("duo-metal-launcher: fresh gate expired\n", stderr);
            return 124;
        }
        puts("duo-metal-launcher: starting hardware clear/resolve/readback");
        pid_t child;
        int error = posix_spawn(&child, args[0], NULL, NULL, args, environ);
        if (error) {
            fprintf(stderr, "duo-metal-launcher: spawn error %d\n", error);
            return 127;
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child) return 127;
        fprintf(stdout, "duo-metal-launcher: child status %d\n", status);
        /* An uncertain GPU exit requires recovery before any further work. */
        if (!WIFEXITED(status) || WEXITSTATUS(status) >= 124) return 125;
    }
    return 0;
}

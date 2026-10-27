/* SPDX-License-Identifier: MIT
 * One-shot owner diagnostic launcher; opens no GPU before the host gate.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    const char *gate = "/private/var/tmp/duo-metal-go";
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    puts("duo-metal-launcher: waiting for /private/var/tmp/duo-metal-go; GPU unopened");
    unsigned seconds;
    for (seconds = 0; seconds < 600; ++seconds) {
        struct stat info;
        if (!lstat(gate, &info) && S_ISREG(info.st_mode) && info.st_uid == 0 &&
            info.st_size == 2 && !(info.st_mode & 0022)) break;
        sleep(1);
    }
    if (seconds == 600) {
        fputs("duo-metal-launcher: gate expired; no GPU test ran\n", stderr);
        return 124;
    }
    /* Root-owned, isolated diagnostic job: use the direct native service.
     * The driver path itself is explicit and the probe verifies A660 identity.
     */
    if (setenv("TU_DARWIN_SERVICE", "NativeAdrenoGpuPublished", 1) ||
        setenv("TU_DARWIN_OPEN_TYPE", "0", 1)) return 126;
    alarm(30);
    char *const args[] = {
        "/private/var/ngpu/addons/duo-metal-probe/duo-metal-probe",
        "--driver",
        "/private/var/ngpu/addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib",
        NULL
    };
    puts("duo-metal-launcher: starting hardware clear/resolve/readback");
    execv(args[0], args);
    perror("duo-metal-launcher execv");
    return 127;
}

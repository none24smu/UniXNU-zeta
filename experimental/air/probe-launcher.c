// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);setvbuf(stderr,NULL,_IONBF,0);
    puts("zeta-air: waiting for /private/var/tmp/zeta-air-go; GPU stays unopened until graphics clients are paused");
    unsigned i;
    for(i=0;i<600;i++) {
        if(access("/private/var/tmp/zeta-air-go",F_OK)==0)break;
        sleep(1);
    }
    if(i==600){fputs("zeta-air: gate expired; no GPU test executed\n",stderr);return 124;}
    setenv("RWA_SOFTWARE","0",1);
    setenv("FD_MESA_DEBUG","msgs",1);
    alarm(120);
    puts("zeta-air: starting real Adreno AIR/Gallium pixel/binding tests");
    char *args[]={"/private/var/ngpu/addons/air-probe/air_metal_test","--draw-argbuf",
        "/private/var/ngpu/addons/air-probe/argbuf_set.bc",
        "/private/var/ngpu/addons/air-probe/argbuf_direct.bc",NULL};
    execv(args[0],args);perror("zeta-air execv");return 127;
}

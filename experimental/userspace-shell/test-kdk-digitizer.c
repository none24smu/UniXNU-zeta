#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "input-kdk-digitizer.h"
int main(int argc,char **argv){assert(argc==3);unsigned checks=0;for(int file=1;file<3;file++){FILE *f=fopen(argv[file],"rb");assert(f);uint8_t bytes[512];size_t n=fread(bytes,1,sizeof bytes,f);fclose(f);assert(n==376);KdkTouch t;assert(decode_kdk_touch(bytes,n,&t));printf("fixture=%d ts=%llu count=%u id=%u x=%.9f y=%.9f down=%d mask=%x\n",file,(unsigned long long)t.timestamp,t.count,t.fingers[0].index,t.fingers[0].x,t.fingers[0].y,t.fingers[0].down,t.fingers[0].mask);assert(t.count==1&&t.fingers[0].index==4);assert(t.fingers[0].x>0.84&&t.fingers[0].x<0.85);assert(t.fingers[0].y>0.41&&t.fingers[0].y<0.43);assert(t.fingers[0].down==(file==1));checks++;
for(size_t cut=0;cut<n;cut++){assert(!decode_kdk_touch(bytes,cut,&t));checks++;}
const size_t offsets[]={20,24,28,32,40,208,212,216,220,228};for(size_t i=0;i<sizeof offsets/sizeof offsets[0];i++){size_t o=offsets[i];uint8_t old=bytes[o];bytes[o]^=0x80;assert(!decode_kdk_touch(bytes,n,&t));checks++;bytes[o]=old;}}
printf("decoder checks=%u\n",checks);return 0;}

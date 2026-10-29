/* The loaded macOS26 KDK serializes double coordinates and a queue header
 * before each child. iOS27 expects fixed coordinates and contiguous child
 * data. Never pass these digitizer bytes to IOHIDEventCreateWithBytes.
 * Decode the bounded, observed KDK layout before using native constructors. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <math.h>
typedef struct {uint32_t index,mask;int down;double x,y;} KdkFinger;
typedef struct {uint64_t timestamp;unsigned count;KdkFinger fingers[16];} KdkTouch;
static uint32_t kdk_u32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t kdk_u64(const uint8_t *p){return (uint64_t)kdk_u32(p)|(uint64_t)kdk_u32(p+4)<<32;}
static double kdk_double(const uint8_t *p){uint64_t bits=kdk_u64(p);double value;memcpy(&value,&bits,8);return value;}
static int decode_kdk_touch(const uint8_t *bytes,size_t length,KdkTouch *out){
 if(!bytes||!out||length<188)return 0;
 memset(out,0,sizeof *out);
 unsigned nodes=kdk_u32(bytes+24);
 if(nodes<2||nodes>17)return 0;
 size_t at=0;
 for(unsigned n=0;n<nodes;n++){
  if(length-at<28)return 0;
  const uint8_t *header=bytes+at;
  if(kdk_u32(header+20)!=0||kdk_u32(header+24)!=(n?1:nodes))return 0;
  if(!n)out->timestamp=kdk_u64(header);
  at+=28;
  if(length-at<160)return 0;
  const uint8_t *data=bytes+at;
  if(kdk_u32(data)!=160||kdk_u32(data+4)!=11||data[12]!=(n?1:0))return 0;
  if(n){
   KdkFinger *f=&out->fingers[out->count++];
   f->x=kdk_double(data+16);f->y=kdk_double(data+24);
   f->index=kdk_u32(data+40);f->mask=kdk_u32(data+52);
   f->down=(kdk_u32(data+8)&0x20000)!=0;
   if(kdk_u32(data+44)!=2||f->index>255||!isfinite(f->x)||!isfinite(f->y)||f->x<0||f->x>1||f->y<0||f->y>1)return 0;
  }
  at+=160;
 }
 return at==length&&out->count>0;
}

// SPDX-License-Identifier: MIT
// The board retains this actual scanout mapping for the rest of the boot.
// Ownership operations try once, without allocation, register I/O or waiting.
#ifndef SHENG_BOOT_PROGRESS_PULSE_H
#define SHENG_BOOT_PROGRESS_PULSE_H
struct bp_pulse { struct bp_display screen; unsigned busy,ready,closed; };
// Exact prefix consumed by the freestanding panic renderer. The kernel build
// checks these offsets against its real vc_info definition.
struct bp_panic_info { unsigned height,width,depth,stride; uintptr_t frame; };
static void bp_panic_bind(struct bp_panic_info *p,uintptr_t base,unsigned w,unsigned h,unsigned rb) {
  p->height=h;p->width=w;p->depth=32;p->stride=rb;
  __atomic_store_n(&p->frame,base,__ATOMIC_RELEASE);
}
static int bp_pulse_enter(struct bp_pulse *p) {
  return !__atomic_exchange_n(&p->busy,1,__ATOMIC_ACQUIRE);
}
static void bp_pulse_leave(struct bp_pulse *p) {
  __atomic_store_n(&p->busy,0,__ATOMIC_RELEASE);
}
static int bp_pulse_register(struct bp_pulse *p,uintptr_t base,uint64_t bytes,
                             unsigned w,unsigned h,unsigned rb) {
  if(!base || (base&3) || w<720 || w>4096 || h<560 || h>4096 ||
     rb<w*4 || (rb&3) || rb>65536 || bytes<(uint64_t)h*rb ||
     base>UINTPTR_MAX-(uint64_t)h*rb || !bp_pulse_enter(p))return 0;
  int accepted=!p->ready && !p->closed;
  if(accepted) {
    p->screen.frame=base+(uintptr_t)(h-32)*rb;
    p->screen.width=w;p->screen.height=32;p->screen.stride=rb;
    p->screen.scale=2;p->screen.bound=1;
    memset(p->screen.previous,0xff,sizeof(p->screen.previous));
    for(unsigned i=0;i<48;++i)p->screen.previous[i][BP_COLS-1]=0;
    __atomic_store_n(&p->ready,1,__ATOMIC_RELEASE);
  }
  bp_pulse_leave(p);return accepted;
}
// Caller owns busy. Close permanently before any system-frame stores.
static void bp_pulse_close(struct bp_pulse *p) {
  p->closed=1;__atomic_store_n(&p->ready,0,__ATOMIC_RELEASE);p->screen.bound=0;
}
#endif

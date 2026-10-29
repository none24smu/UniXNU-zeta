/* Read-only, short native sampling. USB round trips miss UITouchesEvent's
 * transient dispatch contents; sample in userspace without injecting input. */
static uint64_t touch_trace_q(const unsigned char *p){uint64_t n;memcpy(&n,p,8);return n;}
static int touch_trace_read(mach_port_t task,uint64_t address,void *out,size_t size){
 vm_size_t n=0;return vm_read_overwrite(task,(vm_address_t)address,(vm_size_t)size,(vm_address_t)out,&n)==KERN_SUCCESS&&n==size;
}
static int trace_native_touches(int argc,char **argv){
 if(argc!=6)return 2;pid_t pid=(pid_t)strtol(argv[2],NULL,10);uint64_t events[2]={strtoull(argv[3],NULL,0),strtoull(argv[4],NULL,0)};
 unsigned seconds=(unsigned)strtoul(argv[5],NULL,10);if(pid<2||seconds<1||seconds>60||!events[0]||!events[1])return 2;
 mach_port_t task=0;kern_return_t kr=task_for_pid(mach_task_self(),pid,&task);if(kr)return 1;
 const uint64_t mask=0x007ffffffffffff8ULL;unsigned char header[32];
 for(unsigned i=0;i<2;i++)if(!touch_trace_read(task,events[i],header,8)||(touch_trace_q(header)&mask)!=0x1e70cfd20ULL){puts("exact iOS27 UITouchesEvent class guard failed; no trace");mach_port_deallocate(mach_task_self(),task);return 1;}
 mach_timebase_info_data_t tb;mach_timebase_info(&tb);uint64_t deadline=mach_continuous_time()+(uint64_t)seconds*1000000000ULL*tb.denom/tb.numer;
 unsigned samples=0,active=0,errors=0;alarm(seconds+10);
 while(mach_continuous_time()<deadline){
  for(unsigned e=0;e<2;e++){
   uint64_t set=0;if(!touch_trace_read(task,events[e]+0x80,&set,8)||!set||!touch_trace_read(task,set,header,sizeof header)){errors++;continue;}
   if((touch_trace_q(header)&mask)!=0x1e707c990ULL){errors++;continue;}
   uint32_t state=0;memcpy(&state,header+0x1c,4);unsigned used=state&0x3ffffffU;if(!used)continue;
   if((state>>26)!=1||used>3){errors++;continue;}uint64_t slots[3];
   if(!touch_trace_read(task,touch_trace_q(header+0x10),slots,sizeof slots)){errors++;continue;}
   for(unsigned i=0;i<3;i++){
    uint64_t t=slots[i];if(!t||t==0x1e8f41ad0ULL)continue;unsigned char b[0x1a0];
    if(!touch_trace_read(task,t,b,sizeof b)){errors++;continue;}
    double x=0,y=0,timestamp=0;memcpy(&x,b+0x70,8);memcpy(&y,b+0x78,8);memcpy(&timestamp,b+0x110,8);
    printf("touch event=%u object=%#llx isa=%#llx phase=%llu window=%#llx responder=%#llx x=%.4f y=%.4f timestamp=%.9f server_window=%#llx\n",e,(unsigned long long)t,(unsigned long long)touch_trace_q(b),(unsigned long long)touch_trace_q(b+0x10),(unsigned long long)touch_trace_q(b+0x40),(unsigned long long)touch_trace_q(b+0x48),x,y,timestamp,(unsigned long long)touch_trace_q(b+0x170));active++;
   }
  }
  samples++;usleep(2000);
 }
 alarm(0);printf("native touch trace samples=%u active_records=%u read_errors=%u; no input injected\n",samples,active,errors);mach_port_deallocate(mach_task_self(),task);return 0;
}

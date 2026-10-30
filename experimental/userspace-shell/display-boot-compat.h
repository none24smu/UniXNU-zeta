/* Owner iOS27 startup adapter for the pinned, unslid boot74 cache family.
 * Uses the same guarded EDR initializer as the qualified live diagnostic.
 * Each BackBoard generation gets at most one initializer attempt. No wake,
 * unlock, watchdog suppression, or connection cancellation is performed. */
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;
static int boot_edr_watch(const char *executable){
 void *proc=dlopen("/usr/lib/libproc.dylib",RTLD_NOW|RTLD_LOCAL);
 int(*list)(uint32_t,uint32_t,void*,int)=proc?(int(*)(uint32_t,uint32_t,void*,int))dlsym(proc,"proc_listpids"):NULL;
 int(*name)(int,void*,uint32_t)=proc?(int(*)(int,void*,uint32_t))dlsym(proc,"proc_name"):NULL;
 if(getuid()!=0||!list||!name||executable[0]!='/'){puts("boot EDR process discovery unavailable; no call");return 1;}
 pid_t attempted=0;
 for(;;){
  int pids[4096];int bytes=list(1,0,pids,sizeof pids);
  if(bytes<=0||bytes>=(int)sizeof pids){sleep(5);continue;}
  for(int i=0;i<bytes/(int)sizeof pids[0];i++){
   char comm[64]={0};if(pids[i]<=1||name(pids[i],comm,sizeof comm)<=0||strcmp(comm,"backboardd"))continue;
   if(pids[i]==attempted)continue;
   mach_port_t target=MACH_PORT_NULL;kern_return_t kr=task_for_pid(mach_task_self(),pids[i],&target);
   if(kr)continue;
   uint64_t queue=0;vm_size_t n=0;
   kr=vm_read_overwrite(target,0x2ce9e6228ULL,8,(vm_address_t)&queue,&n);
   unsigned char code[8]={0};vm_size_t code_n=0;
   kern_return_t code_kr=vm_read_overwrite(target,0x2b7ef04fcULL,8,(vm_address_t)code,&code_n);
   mach_port_deallocate(mach_task_self(),target);
   const unsigned char expected[]={0x1f,0x20,0x03,0xd5,0xff,0x83,0x03,0xd1};
   if(kr||n!=8||code_kr||code_n!=8||memcmp(code,expected,8))continue;
   attempted=pids[i];
   if(queue){printf("boot EDR already initialized pid=%d queue=%#llx\n",attempted,(unsigned long long)queue);continue;}
   char pid[24];snprintf(pid,sizeof pid,"%d",attempted);
   char *args[]={(char*)executable,"edr-start",pid,NULL};pid_t child=0;
   int error=posix_spawn(&child,executable,NULL,NULL,args,environ);
   printf("boot EDR guarded attempt pid=%d spawn=%d child=%d\n",attempted,error,child);
   if(!error){int status=0;while(waitpid(child,&status,0)<0&&errno==EINTR){}printf("boot EDR controller status=%#x; queue readback is separate evidence\n",status);}
  }
  sleep(5);
 }
}

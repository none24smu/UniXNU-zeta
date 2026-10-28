#define _DARWIN_C_SOURCE 1
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(mach_port_t,const char*,mach_port_t*);
static int control(int argc,char **argv){
 setvbuf(stdout,NULL,_IONBF,0);printf("live-display uid=%u pid=%d\n",getuid(),getpid());
 if(argc==2&&!strcmp(argv[1],"probe")){const char *names[]={"com.apple.CARenderServer","com.apple.libEDR.Notification","com.apple.backboard.display.services"};for(unsigned i=0;i<3;i++){mach_port_t port=0;kern_return_t kr=bootstrap_look_up(bootstrap_port,names[i],&port);printf("lookup %s kr=%d port=%#x\n",names[i],kr,port);if(port)mach_port_deallocate(mach_task_self(),port);}return 0;}
 if(argc<3){fprintf(stderr,"usage: display-control probe | threads PID | abort PID TID | read32 PID ADDRESS | write32 PID ADDRESS EXPECTED VALUE\n");return 2;}
 pid_t pid=(pid_t)strtol(argv[2],0,0);if(pid<=1)return 2;mach_port_t task=0;kern_return_t kr=task_for_pid(mach_task_self(),pid,&task);printf("task_for_pid %d kr=%d task=%#x\n",pid,kr,task);if(kr)return 1;
 int result=0;
 if((!strcmp(argv[1],"read32")&&argc==4)||(!strcmp(argv[1],"write32")&&argc==6)){vm_address_t address=strtoull(argv[3],0,0);uint32_t value=0;vm_size_t count=0;kr=vm_read_overwrite(task,address,sizeof value,(vm_address_t)&value,&count);printf("read32 %#llx kr=%d bytes=%llu value=%#x\n",(unsigned long long)address,kr,(unsigned long long)count,value);if(kr||count!=4){result=1;goto finish;}if(argc==6){uint32_t expected=(uint32_t)strtoul(argv[4],0,0),next=(uint32_t)strtoul(argv[5],0,0);if(value!=expected){puts("preflight mismatch; no write");result=1;goto finish;}kr=vm_write(task,address,(vm_offset_t)&next,4);printf("write32 kr=%d\n",kr);uint32_t after=0;count=0;kern_return_t check=vm_read_overwrite(task,address,4,(vm_address_t)&after,&count);printf("readback kr=%d bytes=%llu value=%#x\n",check,(unsigned long long)count,after);result=kr||check||count!=4||after!=next;}}
 else if(!strcmp(argv[1],"threads")||(!strcmp(argv[1],"abort")&&argc==4)){thread_act_array_t threads=NULL;mach_msg_type_number_t n=0;kr=task_threads(task,&threads,&n);printf("task_threads kr=%d count=%u\n",kr,n);if(kr){result=1;goto finish;}uint64_t target=argc==4?strtoull(argv[3],0,0):0;int found=0;for(unsigned i=0;i<n;i++){thread_identifier_info_data_t ident={0};mach_msg_type_number_t len=THREAD_IDENTIFIER_INFO_COUNT;kr=thread_info(threads[i],THREAD_IDENTIFIER_INFO,(thread_info_t)&ident,&len);if(!kr&&(!target||ident.thread_id==target)){arm_thread_state64_t state={0};len=ARM_THREAD_STATE64_COUNT;kern_return_t sk=thread_get_state(threads[i],ARM_THREAD_STATE64,(thread_state_t)&state,&len);printf("thread tid=%llu port=%#x state_kr=%d pc=%#llx lr=%#llx sp=%#llx\n",(unsigned long long)ident.thread_id,threads[i],sk,(unsigned long long)arm_thread_state64_get_pc(state),(unsigned long long)arm_thread_state64_get_lr(state),(unsigned long long)arm_thread_state64_get_sp(state));if(target){found=1;kr=thread_abort_safely(threads[i]);printf("thread_abort_safely tid=%llu kr=%d\n",(unsigned long long)target,kr);result=kr!=0;}}mach_port_deallocate(mach_task_self(),threads[i]);}if(target&&!found){puts("target thread absent; no mutation");result=1;}vm_deallocate(mach_task_self(),(vm_address_t)threads,n*sizeof *threads);}
 else result=2;
finish:mach_port_deallocate(mach_task_self(),task);return result;
}
#ifdef ZETA_DISPLAY_DYLIB
__attribute__((constructor)) static void injected_control(void){const char *request=getenv("ZETA_DISPLAY_ARGS");if(!request)return;char*copy=strdup(request);if(!copy)_exit(1);char *args[12]={"display-control"};int n=1;char *save=NULL;for(char*p=strtok_r(copy," ",&save);p&&n<11;p=strtok_r(NULL," ",&save))args[n++]=p;args[n]=NULL;int status=control(n,args);free(copy);_exit(status);}
#else
int main(int argc,char**argv){return control(argc,argv);}
#endif

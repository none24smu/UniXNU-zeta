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
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/mount.h>
#include <objc/runtime.h>
#include <objc/message.h>
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(mach_port_t,const char*,mach_port_t*);
#include "display-remote-call.h"
#include "display-framebuffer.h"
#include "display-capture.h"
#include "display-hid.h"
#include "display-input-bridge.h"
#include "display-apps.h"
#include "display-stage-restore.h"
#include "display-metrics.h"
static int control(int argc,char **argv){
 setvbuf(stdout,NULL,_IONBF,0);printf("live-display uid=%u pid=%d\n",getuid(),getpid());
 if(argc==4&&!strcmp(argv[1],"set-display-scale"))return set_display_scale(argv[2],argv[3]);
 if(argc==2&&!strcmp(argv[1],"ui-metrics"))return ui_metrics();
 if(argc>=3&&!strcmp(argv[1],"perf-sample"))return perf_sample(argc,argv);
 if(argc==9&&!strcmp(argv[1],"restore-staged-file"))return restore_staged_file(argc,argv);
 if((argc==2&&(!strcmp(argv[1],"apps-api")||!strcmp(argv[1],"apps-list")))||(argc==3&&(!strcmp(argv[1],"app-install-staged")||!strcmp(argv[1],"app-open")||!strcmp(argv[1],"app-info")||!strcmp(argv[1],"app-open-error"))))return apps_control(argc,argv);
 if(argc==3&&(!strcmp(argv[1],"input-bridge")||!strcmp(argv[1],"input-bridge-native")))return run_input_bridge((unsigned)strtoul(argv[2],NULL,0),!strcmp(argv[1],"input-bridge-native"));
 if((argc==2||argc==3)&&(!strcmp(argv[1],"hid")||!strcmp(argv[1],"hid-refresh")))return probe_hid(argc==3?(unsigned)strtoul(argv[2],NULL,0):0,!strcmp(argv[1],"hid-refresh"));
 if((argc==2&&(!strcmp(argv[1],"lock-service-info")||!strcmp(argv[1],"lock-status")))||(argc==3&&!strcmp(argv[1],"request-unlock"))){
  void *sbs=dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices",RTLD_NOW|RTLD_LOCAL);if(!sbs)return 1;
  alarm(10);
  if(!strcmp(argv[1],"lock-status")){unsigned char passcode=0;unsigned char(*status)(unsigned char*)=(unsigned char(*)(unsigned char*))dlsym(sbs,"SBSGetScreenLockStatus");if(!status)return 1;unsigned char locked=status(&passcode);printf("SpringBoard locked=%u passcode_enabled=%u\n",locked,passcode);alarm(0);return 0;}
  Class service_class=objc_getClass("SBSLockScreenService"),options_class=objc_getClass("SBSUnlockOptions");if(!service_class||!options_class)return 1;
  if(!strcmp(argv[1],"lock-service-info")){Class classes[]={service_class,options_class};for(unsigned ci=0;ci<2;ci++){unsigned count=0;Method *methods=class_copyMethodList(classes[ci],&count);for(unsigned i=0;i<count;i++)printf("%s %s %s\n",class_getName(classes[ci]),sel_getName(method_getName(methods[i])),method_getTypeEncoding(methods[i]));free(methods);}alarm(0);return 0;}
  const char *name=argv[2];if(strncmp(name,"unlock",6)&&strncmp(name,"requestUnlock",13)&&strcmp(name,"requestPasscodeUnlockUIWithOptions:withCompletion:")){puts("unlock selector required");return 2;}SEL selector=sel_registerName(name);Method method=class_getInstanceMethod(service_class,selector);if(!method)return 1;unsigned count=method_getNumberOfArguments(method);char arg[32]={0},reply[32]={0},returns[16]={0};method_getReturnType(method,returns,sizeof returns);if(returns[0]!='v'&&returns[0]!='B'&&returns[0]!='c')return 1;if(count<3||count>4)return 1;method_getArgumentType(method,2,arg,sizeof arg);if(count==4)method_getArgumentType(method,3,reply,sizeof reply);if(arg[0]!='@'||(count==4&&strncmp(reply,"@?",2)))return 1;
  id service=((id(*)(id,SEL))objc_msgSend)((id)service_class,sel_registerName("new"));id options=((id(*)(id,SEL))objc_msgSend)((id)options_class,sel_registerName("new"));if(!service||!options)return 1;
  SEL source=sel_registerName("setUnlockSource:");Method setter=class_getInstanceMethod(options_class,source);if(setter){char type[16]={0};method_getArgumentType(setter,2,type,sizeof type);if(strchr("qiIQ",type[0]))((void(*)(id,SEL,long))objc_msgSend)(options,source,24);}
  void(^completion)(void)=^{puts("unlock completion received; lock status still requires verification");};
  printf("requesting normal %s %s\n",class_getName(service_class),name);
  if(count==4)((void(*)(id,SEL,id,id))objc_msgSend)(service,selector,options,(id)completion);else ((void(*)(id,SEL,id))objc_msgSend)(service,selector,!strncmp(arg,"@?",2)?(id)completion:options);
  CFRunLoopRunInMode(kCFRunLoopDefaultMode,3,0);alarm(0);puts("unlock request returned; verify SpringBoard lock status");return 0;
 }
 if((argc==2&&!strcmp(argv[1],"wake-sbs"))||(argc==3&&!strcmp(argv[1],"keep-display-awake"))){
  /* Shipped SBSUndimScreen0x199d57f54 has no arguments. Use the normal
   * user-idle display assertion and repeated wake requests, with a bounded
   * lifetime. Neither bypasses the display-transition watchdog. */
  unsigned seconds=argc==3?(unsigned)strtoul(argv[2],NULL,0):0;
  if(argc==3&&(seconds<10||seconds>3600))return 2;
  void *sbs=dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices",RTLD_NOW|RTLD_LOCAL);
  void(*undim)(void)=sbs?(void(*)(void))dlsym(sbs,"SBSUndimScreen"):NULL;
  if(!undim){puts("SpringBoard wake API unavailable; no request");return 1;}
  uint32_t assertion=0;int(*release)(uint32_t)=NULL;
  if(seconds){void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_LOCAL);int(*create)(CFStringRef,uint32_t,CFStringRef,uint32_t*)=io?(int(*)(CFStringRef,uint32_t,CFStringRef,uint32_t*))dlsym(io,"IOPMAssertionCreateWithName"):NULL;release=io?(int(*)(uint32_t))dlsym(io,"IOPMAssertionRelease"):NULL;int status=create&&release?create(CFSTR("PreventUserIdleDisplaySleep"),255,CFSTR("UniXNU bounded live display diagnosis"),&assertion):-1;printf("display-idle assertion status=%#x id=%#x duration=%u\n",status,assertion,seconds);}
  undim();puts("SpringBoard undim request sent; visible state requires verification");
  for(unsigned elapsed=0;elapsed<seconds;elapsed++){sleep(1);if((elapsed+1)%5==0)undim();}
  if(assertion&&release)printf("display-idle assertion release=%#x\n",release(assertion));
  return 0;
 }
 if(argc==2&&!strcmp(argv[1],"purge-ca")){
  /* Exact shipped iOS27 wrapper0x184639cb8 takes only the server port.
   * Release reusable render-server resources after a format-policy change.
   * A successful request does not establish a new physical frame. */
  void *library=dlopen("/System/Library/Frameworks/QuartzCore.framework/QuartzCore",RTLD_NOW|RTLD_LOCAL);
  int(*purge)(mach_port_t)=library?(int(*)(mach_port_t))dlsym(library,"CARenderServerPurgeServer"):NULL;
  if(!purge){puts("CA purge API unavailable; no request");return 1;}
  int status=purge(MACH_PORT_NULL);printf("CA render-server purge status=%d\n",status);return status?1:0;
 }
 if(argc==2&&(!strcmp(argv[1],"wake-bks")||!strcmp(argv[1],"blank-bks"))){
  /* Shipped wrapper ABI verified at0x18a03c3cc: one Boolean argument,
   * forwarded in a one-way BackBoard MIG request. A send is not wake proof. */
  void *library=dlopen("/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices",RTLD_NOW|RTLD_LOCAL);
  void(*blank)(int)=library?(void(*)(int))dlsym(library,"BKSDisplayServicesSetScreenBlanked"):NULL;
  if(!blank){puts("BackBoard wake API unavailable; no request");return 1;}
  int requested=!strcmp(argv[1],"blank-bks");blank(requested);printf("BackBoard screen-blank=%d request sent; display state requires verification\n",requested);return 0;
 }
 if(argc==2&&!strcmp(argv[1],"check-debug-int")){
  unsigned char value[64]={0};size_t length=sizeof value;int result=sysctlbyname("debug.bpf_debug",value,&length,NULL,0);uint32_t word=0;memcpy(&word,value,4);printf("debug int result=%d bytes=%zu value=%#x\n",result,length,word);return !result&&length==4?0:1;
 }
 if(argc==3&&(!strcmp(argv[1],"patch-debug-lines")||!strcmp(argv[1],"patch-debug-index-pair"))){
  int pair=!strcmp(argv[1],"patch-debug-index-pair");
  /* An owner record file holds a chain of exact64-byte pre/post images.
   * Each transition changes at most one aligned32-bit word. A wrong debug
   * target or handler fails the full preimage check before any write. */
  struct stat st;if(strncmp(argv[2],"/private/var/ngpu/shell/",24))return 2;
  int fd=open(argv[2],O_RDONLY);if(fd<0)return 1;if(fstat(fd,&st)||st.st_size<132||st.st_size>2116){close(fd);return 1;}
  unsigned char *data=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);close(fd);if(data==MAP_FAILED)return 1;
  uint32_t count=0;memcpy(&count,data,4);if(!count||count>32||(uint64_t)st.st_size!=4+(uint64_t)(count+1)*64){munmap(data,(size_t)st.st_size);return 1;}
  for(uint32_t i=0;i<count;i++){
   unsigned changes=0,changed_pair=8;for(unsigned off=0;off<64;off+=4)if(memcmp(data+4+i*64+off,data+4+(i+1)*64+off,4)){changes++;if(changed_pair==8)changed_pair=off/8;else if(pair&&changed_pair!=off/8){munmap(data,(size_t)st.st_size);puts("multiple index pairs changed; no write");return 1;}}
   if((!pair&&changes>1)||(pair&&(count!=1||!changes||changes>2))){munmap(data,(size_t)st.st_size);puts("invalid bounded line transition; no write");return 1;}
   if(pair){uint32_t before[2],after[2];memcpy(before,data+4+i*64+changed_pair*8,8);memcpy(after,data+4+(i+1)*64+changed_pair*8,8);if(before[0]>=before[1]||after[0]>=after[1]||after[1]>1048576||after[1]-after[0]!=before[1]-before[0]+1){munmap(data,(size_t)st.st_size);puts("invalid replacement fixup range; no write");return 1;}}
  }
  unsigned char current[64];size_t length=sizeof current;int result=sysctlbyname("debug.bpf_debug",current,&length,NULL,0);
  if(result||length!=64){printf("line handler guard result=%d bytes=%zu; no write\n",result,length);munmap(data,(size_t)st.st_size);return 1;}
  uint32_t begin=count+1;for(uint32_t i=0;i<=count;i++)if(!memcmp(current,data+4+i*64,64))begin=i;
  if(begin==count+1){puts("full line preimage mismatch; no write");munmap(data,(size_t)st.st_size);return 1;}
  for(uint32_t i=begin;i<count;i++){
   result=sysctlbyname("debug.bpf_debug",NULL,NULL,data+4+(i+1)*64,64);length=64;
   if(result||sysctlbyname("debug.bpf_debug",current,&length,NULL,0)||length!=64||memcmp(current,data+4+(i+1)*64,64)){puts("native line readback mismatch");munmap(data,(size_t)st.st_size);return 1;}
  }
  printf("kernel line transitions=%u resumed_at=%u readback_exact=1\n",count,begin);munmap(data,(size_t)st.st_size);return 0;
 }
 if(argc==2&&!strcmp(argv[1],"root-revalidation-probe")){
  /* Exact DEVELOPMENT kernel path: a root union request selects fresh-mount
   * handling; an unregistered filesystem type fails before mount mutation.
   * The earlier root branch sets only root_fs_upgrade_try, which disables
   * the validated-page bitmap optimization (actual signature checks remain). */
  struct statfs before,after;if(statfs("/",&before)){perror("statfs before");return 1;}
  printf("root before type=%s flags=%#x fsid=%#x:%#x\n",before.f_fstypename,before.f_flags,before.f_fsid.val[0],before.f_fsid.val[1]);
  if(!(before.f_flags&MNT_ROOTFS)){puts("root mount guard failed; no request");return 1;}
  int(*lookup)(const char*,void*)=(int(*)(const char*,void*))dlsym(RTLD_DEFAULT,"getvfsbyname");
  int(*request)(const char*,const char*,int,void*)=(int(*)(const char*,const char*,int,void*))dlsym(RTLD_DEFAULT,"mount");unsigned char config[4096]={0};
  if(!lookup||!request){puts("VFS APIs unavailable; no request");return 1;}
  errno=0;int found=lookup("zeta_cs_diag",config);int reason=errno;printf("diagnostic filesystem lookup result=%d errno=%d\n",found,reason);
  if(found==0||(reason!=ENOENT&&reason!=ENODEV)){puts("unknown filesystem guard failed; no request");return 1;}
  errno=0;int result=request("zeta_cs_diag","/",MNT_UNION,NULL);reason=errno;
  if(statfs("/",&after)){perror("statfs after");return 1;}
  int same=before.f_flags==after.f_flags&&!memcmp(&before.f_fsid,&after.f_fsid,sizeof before.f_fsid)&&!strcmp(before.f_fstypename,after.f_fstypename);
  printf("invalid-type union request result=%d errno=%d root_mount_unchanged=%d\n",result,reason,same);return result==-1&&same?0:1;
 }
 if(argc==4&&!strcmp(argv[1],"hash-file")){
  uint64_t expected=strtoull(argv[3],NULL,0);struct stat st;int fd=open(argv[2],O_RDONLY);
  if(fd<0){perror("open hash file");return 1;}if(fstat(fd,&st)||(uint64_t)st.st_size!=expected||!expected||expected>1024*1024*1024){close(fd);puts("hash file size mismatch");return 1;}
  void *data=mmap(NULL,(size_t)expected,PROT_READ,MAP_PRIVATE,fd,0);close(fd);if(data==MAP_FAILED){perror("map hash file");return 1;}
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data,(CC_LONG)expected,digest);munmap(data,(size_t)expected);printf("file sha256=");for(unsigned i=0;i<sizeof digest;i++)printf("%02x",digest[i]);printf(" bytes=%llu\n",(unsigned long long)expected);return 0;
 }
 if((argc==6||argc==7)&&!strcmp(argv[1],"invalidate-cache-page")){
  const char *prefix="/System/Library/Caches/com.apple.dyld/";
  const char *cryptex="/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/";
  uint64_t expected=strtoull(argv[3],NULL,0),offset=strtoull(argv[4],NULL,0);uint32_t expected_word=(uint32_t)strtoul(argv[5],NULL,0);
  if((strncmp(argv[2],prefix,strlen(prefix))&&strncmp(argv[2],cryptex,strlen(cryptex)))||strstr(argv[2],"..")||expected<4||expected>512*1024*1024||offset>expected-4||(offset&3)){puts("invalid cache page request");return 2;}
  int fd=open(argv[2],O_RDONLY);struct stat st;if(fd<0){perror("open cache");return 1;}
  if(fstat(fd,&st)||(uint64_t)st.st_size!=expected){close(fd);puts("cache size mismatch");return 1;}
  size_t bytes=(size_t)getpagesize();uint64_t start=offset&~((uint64_t)bytes-1);void *page=mmap(NULL,bytes,PROT_READ,MAP_SHARED,fd,(off_t)start);close(fd);if(page==MAP_FAILED){perror("map cache page");return 1;}
  uint32_t before=0;memcpy(&before,(char*)page+(offset-start),4);printf("cache page offset=%#llx word=%#x\n",(unsigned long long)start,before);
  if(argc==7&&before==(uint32_t)strtoul(argv[6],NULL,0)){puts("cache page already contains target word; keep resident");munmap(page,bytes);return 0;}
  if(before!=expected_word){puts("cache instruction mismatch; no invalidation");munmap(page,bytes);return 1;}
  kern_return_t(*invalidate)(mach_port_t,mach_vm_address_t,mach_vm_size_t,vm_sync_t)=(kern_return_t(*)(mach_port_t,mach_vm_address_t,mach_vm_size_t,vm_sync_t))dlsym(RTLD_DEFAULT,"mach_vm_msync");
  if(!invalidate){munmap(page,bytes);return 1;}kern_return_t status=invalidate(mach_task_self(),(mach_vm_address_t)page,bytes,VM_SYNC_INVALIDATE);munmap(page,bytes);printf("cache page invalidate-only kr=%d; no post-discard reread\n",status);return status?1:0;
 }
 if(argc==4&&!strcmp(argv[1],"upload-fixup-records-zlib")){
  /* Host must guard and temporarily configure debug.bpf_debug's existing
   * opaque handler for precisely this unused BSS range, then restore it. */
  uint64_t expected=strtoull(argv[3],NULL,0);struct stat st;
  if(strncmp(argv[2],"/private/var/ngpu/shell/",24)||!expected||expected>64*1024*1024||expected%112){puts("invalid fixup-record request");return 2;}
  int fd=open(argv[2],O_RDONLY);if(fd<0){perror("open fixup records");return 1;}
  if(fstat(fd,&st)||st.st_size<=0||st.st_size>64*1024*1024){close(fd);puts("fixup container size mismatch");return 1;}
  void *container=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);close(fd);if(container==MAP_FAILED){perror("map fixup container");return 1;}
  void *records=malloc((size_t)expected);void *readback=malloc((size_t)expected);uLongf length=(uLongf)expected;
  if(!records||!readback||uncompress(records,&length,container,(uLong)st.st_size)!=Z_OK||length!=expected){puts("fixup decompression failed");munmap(container,(size_t)st.st_size);free(records);free(readback);return 1;}
  munmap(container,(size_t)st.st_size);
  size_t baseline=(size_t)expected;int initial=sysctlbyname("debug.bpf_debug",readback,&baseline,NULL,0);int zero=!initial&&baseline==expected;
  if(zero){const unsigned char *bytes=readback;for(size_t i=0;i<baseline;i++)if(bytes[i]){zero=0;break;}}
  if(!zero){puts("kernel destination is not the exact unused zero range; no upload");free(records);free(readback);return 1;}
  puts("kernel destination full preimage zero verified");
  int result=sysctlbyname("debug.bpf_debug",NULL,NULL,records,(size_t)expected);int error=errno;
  size_t actual=(size_t)expected;int checked=result?-1:sysctlbyname("debug.bpf_debug",readback,&actual,NULL,0);
  int exact=!result&&!checked&&actual==expected&&!memcmp(records,readback,(size_t)expected);
  printf("bounded fixup upload bytes=%llu result=%d errno=%d kernel_readback_exact=%d crc32=%#lx\n",(unsigned long long)expected,result,result?error:0,exact,(unsigned long)crc32(0,records,(uInt)expected));free(records);free(readback);return exact?0:1;
 }
 if((argc==5&&!strcmp(argv[1],"invalidate-stock-file"))||(argc==2&&(!strcmp(argv[1],"invalidate-tccd-page")||!strcmp(argv[1],"invalidate-tccd-file")||!strcmp(argv[1],"invalidate-contextstored-file")))){
  int generic=argc==5;
  int context=!strcmp(argv[1],"invalidate-contextstored-file");
  const char *path=generic?argv[2]:(context?"/System/Library/PrivateFrameworks/CoreDuetContext.framework/Resources/contextstored":"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd");
  uint64_t entry=generic?strtoull(argv[4],NULL,0):(context?0x2930ULL:0x314acULL);
  uint64_t expected=generic?strtoull(argv[3],NULL,0):(context?106416:1127104);
  if(generic&&((strncmp(path,"/System/Library/",16)&&strncmp(path,"/usr/libexec/",13)&&strncmp(path,"/usr/sbin/",10)&&strncmp(path,"/Applications/",14)&&strncmp(path,"/private/var/containers/Bundle/Application/",43))||strstr(path,"..")||expected<4||expected>64*1024*1024||entry>expected-4||(entry&3))){puts("invalid stock-file request");return 2;}
  int fd=open(path,O_RDONLY);if(fd<0){perror("open tccd");return 1;}
  size_t page_bytes=(size_t)getpagesize();off_t file_offset=(off_t)(entry&~((uint64_t)page_bytes-1));size_t entry_offset=entry-(uint64_t)file_offset;
  if(generic||context||!strcmp(argv[1],"invalidate-tccd-file")){
   struct stat st;if(fstat(fd,&st)||(uint64_t)st.st_size!=expected){puts("unexpected stock file size; no invalidation");close(fd);return 1;}
   file_offset=0;entry_offset=(size_t)entry;page_bytes=((size_t)st.st_size+(size_t)getpagesize()-1)&~((size_t)getpagesize()-1);
  }
  printf("invalidate %s mapping=%zu file_offset=%#llx entry_offset=%#zx\n",path,page_bytes,(unsigned long long)file_offset,entry_offset);
  void *page=mmap(NULL,page_bytes,PROT_READ|PROT_EXEC,MAP_SHARED,fd,file_offset);close(fd);
  if(page==MAP_FAILED){perror("map tccd page");return 1;}
  uint32_t before=0;memcpy(&before,(char*)page+entry_offset,4);printf("tccd mapped entry before=%#x\n",before);
  if(before!=0xd503201f&&before!=0xdac1a7fe&&before!=0xd65f03c0){puts("unexpected page bytes; no invalidation");munmap(page,page_bytes);return 1;}
  /* Invalidate only: unlike msync(2)'s implicit synchronous mode, this
   * requests no dirty-page writeback to the sealed backing file. */
  kern_return_t(*invalidate)(mach_port_t,mach_vm_address_t,mach_vm_size_t,vm_sync_t)=(kern_return_t(*)(mach_port_t,mach_vm_address_t,mach_vm_size_t,vm_sync_t))dlsym(RTLD_DEFAULT,"mach_vm_msync");
  if(!invalidate){puts("mach_vm_msync unavailable; no invalidation");munmap(page,page_bytes);return 1;}
  kern_return_t status=invalidate(mach_task_self(),(mach_vm_address_t)page,page_bytes,VM_SYNC_INVALIDATE);
  printf("tccd page invalidate-only kr=%d; next executable owns first refault\n",status);
  /* A diagnostic reread would repopulate the vnode page under this helper's
   * validation context before tccd's exec fixups can run. Leave it discarded. */
  munmap(page,page_bytes);return status?1:0;
 }
 if((argc==3&&!strcmp(argv[1],"kick-service"))||(argc==2&&(!strcmp(argv[1],"kick-liveactivities")||!strcmp(argv[1],"kick-tccd")||!strcmp(argv[1],"kick-contextstored")))){
  /* Verified shipped iOS27 libxpc service API. flags0: not suspended,
   * no kill; the API always includes unthrottle=true in the launchd request. */
  void *xpc=dlopen("/usr/lib/system/libxpc.dylib",RTLD_NOW|RTLD_LOCAL);
  void*(*create)(const char*,void*)=xpc?(void*(*)(const char*,void*))dlsym(xpc,"xpc_service_create_from_specifier"):NULL;
  int(*kick)(void*,uint64_t)=xpc?(int(*)(void*,uint64_t))dlsym(xpc,"xpc_service_kickstart_with_flags"):NULL;
  void(*release)(void*)=xpc?(void(*)(void*))dlsym(xpc,"xpc_release"):NULL;
  if(!create||!kick||!release){puts("service APIs missing");return 1;}
  const char *specifier=argc==3?argv[2]:(!strcmp(argv[1],"kick-contextstored")?"system/com.apple.contextstored":(!strcmp(argv[1],"kick-tccd")?"system/com.apple.tccd":"system/com.apple.liveactivitiesd"));
  if(strncmp(specifier,"system/com.apple.",17)||strstr(specifier,"..")||strchr(specifier+7,'/')){puts("invalid stock service specifier");return 2;}
  void *service=create(specifier,NULL);printf("create %s service=%p\n",specifier,service);if(!service)return 1;
  int status=kick(service,0);printf("%s kickstart/unthrottle status=%d\n",specifier,status);release(service);return status?1:0;
 }
 if(argc==3&&!strcmp(argv[1],"capture"))return capture_ca_display(argv[2],0);
 if(argc==3&&!strcmp(argv[1],"present"))return capture_ca_display(argv[2],1);
 if(argc==2&&!strcmp(argv[1],"wake"))return probe_framebuffer(1);
 if(argc==2&&!strcmp(argv[1],"framebuffer"))return probe_framebuffer(0);
 if(argc==2&&!strcmp(argv[1],"framebuffer-notifications"))return probe_framebuffer(2);
 if(argc==2&&!strcmp(argv[1],"probe")){const char *names[]={"com.apple.CARenderServer","com.apple.libEDR.Notification","com.apple.backboard.display.services"};for(unsigned i=0;i<3;i++){mach_port_t port=0;kern_return_t kr=bootstrap_look_up(bootstrap_port,names[i],&port);printf("lookup %s kr=%d port=%#x\n",names[i],kr,port);if(port)mach_port_deallocate(mach_task_self(),port);}return 0;}
 if(argc<3){fprintf(stderr,"usage: display-control probe | threads PID | abort PID TID | read32 PID ADDRESS | write32 PID ADDRESS EXPECTED VALUE\n");return 2;}
 pid_t pid=(pid_t)strtol(argv[2],0,0);if(pid<=1)return 2;mach_port_t task=0;kern_return_t kr=task_for_pid(mach_task_self(),pid,&task);printf("task_for_pid %d kr=%d task=%#x\n",pid,kr,task);if(kr)return 1;
 int result=0;
 if(!strcmp(argv[1],"stacks")&&argc==3){
  /* Passive, bounded user frame walks in one request. USB round trips
   * otherwise outlive the display watchdog and leave stale evidence. */
  thread_act_array_t threads=NULL;mach_msg_type_number_t n=0;
  kr=task_threads(task,&threads,&n);printf("task_threads kr=%d count=%u\n",kr,n);
  if(kr){result=1;goto finish;}
  for(unsigned i=0;i<n;i++){
   thread_identifier_info_data_t ident={0};mach_msg_type_number_t count=THREAD_IDENTIFIER_INFO_COUNT;
   kern_return_t ik=thread_info(threads[i],THREAD_IDENTIFIER_INFO,(thread_info_t)&ident,&count);
   arm_thread_state64_t s={0};count=ARM_THREAD_STATE64_COUNT;
   kern_return_t sk=thread_get_state(threads[i],ARM_THREAD_STATE64,(thread_state_t)&s,&count);
   printf("stack tid=%llu ident_kr=%d state_kr=%d pc=%#llx lr=%#llx fp=%#llx sp=%#llx x19=%#llx\n",(unsigned long long)ident.thread_id,ik,sk,(unsigned long long)arm_thread_state64_get_pc(s),(unsigned long long)arm_thread_state64_get_lr(s),(unsigned long long)arm_thread_state64_get_fp(s),(unsigned long long)arm_thread_state64_get_sp(s),(unsigned long long)s.__x[19]);
   if(!sk){
    uint64_t fp=arm_thread_state64_get_fp(s),sp=arm_thread_state64_get_sp(s);
    for(unsigned depth=0;depth<24;depth++){
     uint64_t pair[2]={0};vm_size_t got=0;
     if((fp&7)||fp<sp||fp-sp>8*1024*1024)break;
     kr=vm_read_overwrite(task,fp,sizeof pair,(vm_address_t)pair,&got);
     if(kr||got!=sizeof pair)break;
     printf(" frame tid=%llu depth=%u fp=%#llx pc=%#llx\n",(unsigned long long)ident.thread_id,depth,(unsigned long long)fp,(unsigned long long)pair[1]);
     if(pair[1]==0x1805a5304){
      uint64_t connection=0,channel=0,label=0;char text[160]={0};
      if(!vm_read_overwrite(task,fp-0x20,8,(vm_address_t)&connection,&got)&&got==8&&connection&&
         !vm_read_overwrite(task,connection+0xa8,8,(vm_address_t)&channel,&got)&&got==8&&channel&&
         !vm_read_overwrite(task,channel+0x48,8,(vm_address_t)&label,&got)&&got==8&&label&&
         !vm_read_overwrite(task,label,sizeof text-1,(vm_address_t)text,&got))
       printf(" xpc tid=%llu connection=%#llx label=%s\n",(unsigned long long)ident.thread_id,(unsigned long long)connection,text);
     }
     if(pair[0]<=fp)break;fp=pair[0];
    }
   }
   mach_port_deallocate(mach_task_self(),threads[i]);
  }
  vm_deallocate(mach_task_self(),(vm_address_t)threads,n*sizeof *threads);
 }
 else if(!strcmp(argv[1],"edr-start")&&argc==3){result=start_edr_in_task(task);}
 else if(!strcmp(argv[1],"cancel-coreduet")&&argc==4&&pid==59){result=cancel_named_service_in_task(task,(vm_address_t)strtoull(argv[3],NULL,0),"com.apple.coreduetd.context");}
 else if(!strcmp(argv[1],"cancel-datamigrator")&&argc==4&&pid>1){result=cancel_named_service_in_task(task,(vm_address_t)strtoull(argv[3],NULL,0),"com.apple.datamigrator");}
 else if(!strcmp(argv[1],"cancel-bluetooth-att")&&argc==4&&pid>1){result=cancel_named_service_in_task(task,(vm_address_t)strtoull(argv[3],NULL,0),"com.apple.server.bluetooth.le.att.xpc");}
 else if((!strcmp(argv[1],"read32")&&argc==4)||(!strcmp(argv[1],"write32")&&argc==6)){vm_address_t address=strtoull(argv[3],0,0);uint32_t value=0;vm_size_t count=0;kr=vm_read_overwrite(task,address,sizeof value,(vm_address_t)&value,&count);printf("read32 %#llx kr=%d bytes=%llu value=%#x\n",(unsigned long long)address,kr,(unsigned long long)count,value);if(kr||count!=4){result=1;goto finish;}if(argc==6){uint32_t expected=(uint32_t)strtoul(argv[4],0,0),next=(uint32_t)strtoul(argv[5],0,0);if(value!=expected){puts("preflight mismatch; no write");result=1;goto finish;}kr=vm_write(task,address,(vm_offset_t)&next,4);printf("write32 kr=%d\n",kr);uint32_t after=0;count=0;kern_return_t check=vm_read_overwrite(task,address,4,(vm_address_t)&after,&count);printf("readback kr=%d bytes=%llu value=%#x\n",check,(unsigned long long)count,after);result=kr||check||count!=4||after!=next;}}
 else if(!strcmp(argv[1],"threads")||(!strcmp(argv[1],"abort")&&argc==4)){thread_act_array_t threads=NULL;mach_msg_type_number_t n=0;kr=task_threads(task,&threads,&n);printf("task_threads kr=%d count=%u\n",kr,n);if(kr){result=1;goto finish;}uint64_t target=argc==4?strtoull(argv[3],0,0):0;int found=0;for(unsigned i=0;i<n;i++){thread_identifier_info_data_t ident={0};mach_msg_type_number_t len=THREAD_IDENTIFIER_INFO_COUNT;kr=thread_info(threads[i],THREAD_IDENTIFIER_INFO,(thread_info_t)&ident,&len);if(!kr&&(!target||ident.thread_id==target)){arm_thread_state64_t state={0};len=ARM_THREAD_STATE64_COUNT;kern_return_t sk=thread_get_state(threads[i],ARM_THREAD_STATE64,(thread_state_t)&state,&len);printf("thread tid=%llu port=%#x state_kr=%d pc=%#llx lr=%#llx sp=%#llx\n",(unsigned long long)ident.thread_id,threads[i],sk,(unsigned long long)arm_thread_state64_get_pc(state),(unsigned long long)arm_thread_state64_get_lr(state),(unsigned long long)arm_thread_state64_get_sp(state));if(target){found=1;kr=thread_abort_safely(threads[i]);printf("thread_abort_safely tid=%llu kr=%d\n",(unsigned long long)target,kr);result=kr!=0;}}mach_port_deallocate(mach_task_self(),threads[i]);}if(target&&!found){puts("target thread absent; no mutation");result=1;}vm_deallocate(mach_task_self(),(vm_address_t)threads,n*sizeof *threads);}
 else result=2;
finish:mach_port_deallocate(mach_task_self(),task);return result;
}
#ifdef ZETA_DISPLAY_DYLIB
__attribute__((constructor)) static void injected_control(void){const char *request=getenv("ZETA_DISPLAY_ARGS");if(!request)return;char*copy=strdup(request);if(!copy)_exit(1);char *args[12]={"display-control"};int n=1;char *save=NULL;for(char*p=strtok_r(copy," ",&save);p&&n<11;p=strtok_r(NULL," ",&save))args[n++]=p;args[n]=NULL;int status=control(n,args);free(copy);_exit(status);}
#else
int main(int argc,char**argv){return control(argc,argv);}
#endif

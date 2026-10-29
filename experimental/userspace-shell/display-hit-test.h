/* Bounded native BackBoard finger hit-test filter. This does not inject events,
 * change SpringBoard state, or create a second WindowServer. The caller must
 * identify one existing context; native assertion invalidation restores policy. */
#include <signal.h>
static volatile sig_atomic_t hit_test_filter_stop;
static void hit_test_filter_signal(int number){(void)number;hit_test_filter_stop=1;}
static void hit_test_filter_state(id service){
 Ivar waiting=class_getInstanceVariable(object_getClass(service),"_lock_waitingOnServerHandshake");
 Ivar connection=class_getInstanceVariable(object_getClass(service),"_connection");
 if(waiting)printf("finger filter waiting_on_server_handshake=%u\n",*(const unsigned char*)((const char*)service+ivar_getOffset(waiting)));
 if(connection){id value=object_getIvar(service,connection);printf("finger filter connection_class=%s\n",value?object_getClassName(value):"nil");}
}
static int finger_hit_test_filter(const char *context_text,const char *duration_text){
 char *end=NULL;unsigned long context=strtoul(context_text,&end,0);
 if(!end||*end||!context||context>UINT32_MAX)return 2;
 unsigned long duration=strtoul(duration_text,&end,10);
 if(!end||*end||duration<10||duration>300)return 2;
 void *security=dlopen("/System/Library/Frameworks/Security.framework/Security",RTLD_NOW|RTLD_LOCAL);
 CFTypeRef(*self_task)(CFAllocatorRef)=security?(CFTypeRef(*)(CFAllocatorRef))dlsym(security,"SecTaskCreateFromSelf"):NULL;
 CFTypeRef(*copy_entitlement)(CFTypeRef,CFStringRef,CFErrorRef*)=security?(CFTypeRef(*)(CFTypeRef,CFStringRef,CFErrorRef*))dlsym(security,"SecTaskCopyValueForEntitlement"):NULL;
 if(!self_task||!copy_entitlement)return 1;
 CFTypeRef task=self_task(NULL);if(!task)return 1;CFErrorRef error=NULL;
 CFTypeRef granted=copy_entitlement(task,CFSTR("com.apple.backboardd.hitTestFilterBySender"),&error);CFRelease(task);
 int allowed=granted&&CFEqual(granted,kCFBooleanTrue);printf("finger filter native_entitlement_granted=%d\n",allowed);
 if(granted)CFRelease(granted);if(error){CFShow(error);CFRelease(error);}if(!allowed)return 1;
 if(!dlopen("/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices",RTLD_NOW|RTLD_LOCAL))return 1;
 Class cls=objc_getClass("BKSTouchEventService");
 SEL shared=sel_registerName("sharedInstance"),exclude=sel_registerName("excludeEventsFromStimulus:fromHitTestingToContextIDs:");
 Method factory=cls?class_getClassMethod(cls,shared):NULL,method=cls?class_getInstanceMethod(cls,exclude):NULL;
 if(!factory||!method||strcmp(method_getTypeEncoding(factory),"@16@0:8")||strcmp(method_getTypeEncoding(method),"@32@0:8Q16@24")){puts("finger hit-test ABI mismatch; no filter");return 1;}
 id service=((id(*)(id,SEL))objc_msgSend)((id)cls,shared);if(!service)return 1;
 int64_t number=(int64_t)context;CFNumberRef id_number=CFNumberCreate(NULL,kCFNumberSInt64Type,&number);
 const void *value=id_number;CFArrayRef contexts=CFArrayCreate(NULL,&value,1,&kCFTypeArrayCallBacks);CFRelease(id_number);
 id token=((id(*)(id,SEL,uint64_t,id))objc_msgSend)(service,exclude,1,(id)contexts);CFRelease(contexts);
 if(!token){puts("native finger hit-test filter returned nil");return 1;}
 SEL invalidate=sel_registerName("invalidate");Method cleanup=class_getInstanceMethod(object_getClass(token),invalidate);
 if(!cleanup||strcmp(method_getTypeEncoding(cleanup),"v16@0:8")){puts("unexpected native assertion token; exiting to tear down client");_exit(1);}
 ((id(*)(id,SEL))objc_msgSend)(token,sel_registerName("retain"));
 printf("finger filter context=%lu stimulus=1 token_class=%s duration=%lu; allocation is not routing proof\n",context,object_getClassName(token),duration);
 hit_test_filter_state(service);
 struct sigaction handler={0},old_term={0},old_int={0},old_alarm={0};handler.sa_handler=hit_test_filter_signal;
 sigemptyset(&handler.sa_mask);hit_test_filter_stop=0;
 sigaction(SIGTERM,&handler,&old_term);sigaction(SIGINT,&handler,&old_int);sigaction(SIGALRM,&handler,&old_alarm);
 mach_timebase_info_data_t timebase;mach_timebase_info(&timebase);
 uint64_t deadline=mach_continuous_time()+(uint64_t)duration*1000000000ULL*timebase.denom/timebase.numer;
 alarm((unsigned)duration+20);
 unsigned ticks=0;
 while(!hit_test_filter_stop&&mach_continuous_time()<deadline){CFRunLoopRunInMode(kCFRunLoopDefaultMode,.1,0);usleep(10000);if(++ticks%50==0)hit_test_filter_state(service);}
 ((void(*)(id,SEL))objc_msgSend)(token,invalidate);
 puts("native finger hit-test assertion invalidated; original server policy requested");
 ((void(*)(id,SEL))objc_msgSend)(token,sel_registerName("release"));alarm(0);
 sigaction(SIGTERM,&old_term,NULL);sigaction(SIGINT,&old_int,NULL);sigaction(SIGALRM,&old_alarm,NULL);return 0;
}

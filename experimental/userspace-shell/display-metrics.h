/* Read-only UIKit/display traits and sampled task counters. */
typedef struct { double x,y,w,h; } UIProbeRect;
static Method ui_getter(id object,const char *name,char kind){
 if(!object)return NULL;Method m=class_getInstanceMethod(object_getClass(object),sel_registerName(name));char type[100]={0};if(!m||method_getNumberOfArguments(m)!=2)return NULL;method_getReturnType(m,type,sizeof type);return type[0]==kind?m:NULL;
}
static id ui_object(id object,const char *name){return ui_getter(object,name,'@')?((id(*)(id,SEL))objc_msgSend)(object,sel_registerName(name)):NULL;}
static void ui_rect(id object,const char *label,const char *name){
 Method m=ui_getter(object,name,'{');if(!m){printf("%s.%s unavailable\n",label,name);return;}char type[120]={0};method_getReturnType(m,type,sizeof type);if(strcmp(type,"{CGRect={CGPoint=dd}{CGSize=dd}}")){printf("%s.%s ABI=%s\n",label,name,type);return;}
 UIProbeRect r=((UIProbeRect(*)(id,SEL))objc_msgSend)(object,sel_registerName(name));printf("%s.%s x=%.8g y=%.8g width=%.8g height=%.8g\n",label,name,r.x,r.y,r.w,r.h);
}
static void ui_number(id object,const char *label,const char *name,char kind){
 if(!ui_getter(object,name,kind)){printf("%s.%s unavailable\n",label,name);return;}
 if(kind=='d')printf("%s.%s=%.10g\n",label,name,((double(*)(id,SEL))objc_msgSend)(object,sel_registerName(name)));
 else printf("%s.%s=%lld\n",label,name,((long long(*)(id,SEL))objc_msgSend)(object,sel_registerName(name)));
}
static int ui_metrics(void){
 alarm(25);const char *paths[]={"/System/Library/Frameworks/UIKit.framework/UIKit","/System/Library/PrivateFrameworks/SpringBoardHome.framework/SpringBoardHome"};
 for(unsigned i=0;i<2;i++){void *h=dlopen(paths[i],RTLD_NOW|RTLD_LOCAL);printf("metrics framework %s loaded=%u\n",paths[i],h!=NULL);}
 Class cls=objc_getClass("UIScreen");if(!cls||!class_getClassMethod(cls,sel_registerName("mainScreen"))){puts("UIScreen unavailable");return 1;}
 id screen=((id(*)(id,SEL))objc_msgSend)((id)cls,sel_registerName("mainScreen"));if(!screen){puts("main screen absent");return 1;}
 printf("screen class=%s\n",object_getClassName(screen));ui_rect(screen,"screen","bounds");ui_rect(screen,"screen","nativeBounds");ui_number(screen,"screen","scale",'d');ui_number(screen,"screen","nativeScale",'d');ui_number(screen,"screen","sbh_screenType",'q');
 id config=ui_object(screen,"displayConfiguration");printf("display configuration class=%s\n",config?object_getClassName(config):"nil");ui_rect(config,"configuration","bounds");ui_number(config,"configuration","pointScale",'d');ui_number(config,"configuration","nativeScale",'d');ui_number(config,"configuration","orientation",'q');
 id traits=ui_object(screen,"traitCollection");ui_number(traits,"traits","userInterfaceIdiom",'q');ui_number(traits,"traits","horizontalSizeClass",'q');ui_number(traits,"traits","verticalSizeClass",'q');
 const char *trait_names[]={"UITraitArtworkSubtype","UITraitDisplayCornerRadius"};const char *selectors[]={"valueForNSIntegerTrait:","valueForCGFloatTrait:"};
 for(unsigned i=0;i<2;i++){Class trait=objc_getClass(trait_names[i]);SEL sel=sel_registerName(selectors[i]);Method method=traits?class_getInstanceMethod(object_getClass(traits),sel):NULL;char result[16]={0},argument[16]={0};if(method){method_getReturnType(method,result,sizeof result);method_getArgumentType(method,2,argument,sizeof argument);}if(!trait||!method||method_getNumberOfArguments(method)!=3||argument[0]!='#'||result[0]!=(i?'d':'q')){printf("trait %s unavailable\n",trait_names[i]);continue;}if(i)printf("trait %s=%.10g\n",trait_names[i],((double(*)(id,SEL,Class))objc_msgSend)(traits,sel,trait));else printf("trait %s=%lld\n",trait_names[i],((long long(*)(id,SEL,Class))objc_msgSend)(traits,sel,trait));}
 Class device=objc_getClass("UIDevice");id dev=device&&class_getClassMethod(device,sel_registerName("currentDevice"))?((id(*)(id,SEL))objc_msgSend)((id)device,sel_registerName("currentDevice")):NULL;ui_number(dev,"device","userInterfaceIdiom",'q');ui_number(dev,"device","orientation",'q');
 puts("metrics sampled in diagnostic process; SpringBoard scene orientation/cache require separate verification");return 0;
}
struct perf_snapshot {task_thread_times_info_data_t times;task_events_info_data_t events;kern_return_t times_kr,events_kr;};
static struct perf_snapshot perf_snapshot(task_t task){struct perf_snapshot s={0};mach_msg_type_number_t n=TASK_THREAD_TIMES_INFO_COUNT;s.times_kr=task_info(task,TASK_THREAD_TIMES_INFO,(task_info_t)&s.times,&n);n=TASK_EVENTS_INFO_COUNT;s.events_kr=task_info(task,TASK_EVENTS_INFO,(task_info_t)&s.events,&n);return s;}
static long long perf_us(time_value_t t){return (long long)t.seconds*1000000+t.microseconds;}
static int perf_sample(int argc,char **argv){
 if(argc<3||argc>10)return 2;alarm(15);task_t tasks[8]={0};struct perf_snapshot before[8],after[8];
 for(int i=2;i<argc;i++){pid_t pid=(pid_t)strtol(argv[i],NULL,10);if(pid<1)return 2;kern_return_t k=task_for_pid(mach_task_self(),pid,&tasks[i-2]);printf("perf pid=%d task_kr=%d\n",pid,k);before[i-2]=perf_snapshot(tasks[i-2]);}
 usleep(1000000);
 for(int i=2;i<argc;i++){unsigned j=(unsigned)i-2;after[j]=perf_snapshot(tasks[j]);struct perf_snapshot *a=&after[j],*b=&before[j];printf("perf pid=%s interval_target_ms=1000 live_thread_times_kr=%d/%d events_kr=%d/%d",argv[i],b->times_kr,a->times_kr,b->events_kr,a->events_kr);if(!a->times_kr&&!b->times_kr)printf(" user_us=%lld system_us=%lld",perf_us(a->times.user_time)-perf_us(b->times.user_time),perf_us(a->times.system_time)-perf_us(b->times.system_time));if(!a->events_kr&&!b->events_kr)printf(" faults=%u pageins=%u cow=%u mach_calls=%u unix_calls=%u context_switches=%u",(unsigned)(a->events.faults-b->events.faults),(unsigned)(a->events.pageins-b->events.pageins),(unsigned)(a->events.cow_faults-b->events.cow_faults),(unsigned)(a->events.syscalls_mach-b->events.syscalls_mach),(unsigned)(a->events.syscalls_unix-b->events.syscalls_unix),(unsigned)(a->events.csw-b->events.csw));puts("");if(tasks[j])mach_port_deallocate(mach_task_self(),tasks[j]);}
 puts("live-thread CPU deltas are approximate and can exclude threads which exit during sampling");return 0;
}

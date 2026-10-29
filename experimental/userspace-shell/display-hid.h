/* Read-only IORegistry and HID event-system diagnosis. Client types follow
 * WebKit's PAL/pal/spi/mac/IOKitSPIMac.h (admin=0, monitor=1).
 * No service is seized and no events or properties are synthesized. */
static unsigned hid_event_counts[64];
static unsigned (*hid_event_type)(const void *);
static void hid_event_callback(void *target,void *context,void *sender,void *event){
 (void)target;(void)context;(void)sender;
 unsigned type=hid_event_type?hid_event_type(event):63;
 if(type<64)hid_event_counts[type]++;
 if(type==11&&hid_event_counts[type]<=12)printf("HID digitizer event=%u\n",hid_event_counts[type]);
}
static int probe_hid(unsigned seconds){
 if(seconds>15)return 2;
 alarm(25);
 void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_LOCAL);
 if(!io)return 1;
 CFMutableDictionaryRef(*matching)(const char*)=(CFMutableDictionaryRef(*)(const char*))dlsym(io,"IOServiceMatching");
 int(*matches)(mach_port_t,CFDictionaryRef,mach_port_t*)=(int(*)(mach_port_t,CFDictionaryRef,mach_port_t*))dlsym(io,"IOServiceGetMatchingServices");
 mach_port_t(*next)(mach_port_t)=(mach_port_t(*)(mach_port_t))dlsym(io,"IOIteratorNext");
 int(*release)(mach_port_t)=(int(*)(mach_port_t))dlsym(io,"IOObjectRelease");
 int(*properties)(mach_port_t,CFMutableDictionaryRef*,CFAllocatorRef,uint32_t)=(int(*)(mach_port_t,CFMutableDictionaryRef*,CFAllocatorRef,uint32_t))dlsym(io,"IORegistryEntryCreateCFProperties");
 int(*entryid)(mach_port_t,uint64_t*)=(int(*)(mach_port_t,uint64_t*))dlsym(io,"IORegistryEntryGetRegistryEntryID");
 if(!matching||!matches||!next||!release||!properties||!entryid)return 1;
 const char *classes[]={"IOHIDEventService","IOHIDSystem","IOHIDEventSystem"};
 for(unsigned ci=0;ci<3;ci++){
  mach_port_t it=0;int status=matches(MACH_PORT_NULL,matching(classes[ci]),&it);
  printf("HID registry class=%s status=%#x\n",classes[ci],status);
  if(status)continue;
  mach_port_t entry;unsigned count=0;
  while((entry=next(it))){
   uint64_t ident=0;entryid(entry,&ident);CFMutableDictionaryRef props=NULL;
   status=properties(entry,&props,kCFAllocatorDefault,0);
   printf("HID registry id=%#llx properties=%#x\n",(unsigned long long)ident,status);
   if(props){CFShow(props);CFRelease(props);}release(entry);
   if(++count==64)break;
  }
  release(it);printf("HID registry count=%u\n",count);
 }
 CFTypeRef(*create)(CFAllocatorRef,int,CFDictionaryRef)=(CFTypeRef(*)(CFAllocatorRef,int,CFDictionaryRef))dlsym(io,"IOHIDEventSystemClientCreateWithType");
 CFArrayRef(*services)(CFTypeRef)=(CFArrayRef(*)(CFTypeRef))dlsym(io,"_IOHIDEventSystemClientCopyServiceRecords");
 CFArrayRef(*clients)(CFTypeRef,int)=(CFArrayRef(*)(CFTypeRef,int))dlsym(io,"_IOHIDEventSystemClientCopyClientRecords");
 if(!create)return 1;
 CFTypeRef admin=create(kCFAllocatorDefault,0,NULL);printf("HID admin client=%p\n",admin);
 if(admin){
  if(services){CFArrayRef a=services(admin);printf("HID service records=%ld\n",a?CFArrayGetCount(a):-1L);if(a){CFShow(a);CFRelease(a);}}
  if(clients)for(int type=0;type<=4;type++){CFArrayRef a=clients(admin,type);printf("HID clients type=%d count=%ld\n",type,a?CFArrayGetCount(a):-1L);if(a){CFShow(a);CFRelease(a);}}
  CFRelease(admin);
 }
 if(seconds){
  void(*schedule)(CFTypeRef,CFRunLoopRef,CFStringRef)=(void(*)(CFTypeRef,CFRunLoopRef,CFStringRef))dlsym(io,"IOHIDEventSystemClientScheduleWithRunLoop");
  void(*unschedule)(CFTypeRef,CFRunLoopRef,CFStringRef)=(void(*)(CFTypeRef,CFRunLoopRef,CFStringRef))dlsym(io,"IOHIDEventSystemClientUnscheduleWithRunLoop");
  void(*callback)(CFTypeRef,void(*)(void*,void*,void*,void*),void*,void*)=(void(*)(CFTypeRef,void(*)(void*,void*,void*,void*),void*,void*))dlsym(io,"IOHIDEventSystemClientRegisterEventCallback");
  hid_event_type=(unsigned(*)(const void*))dlsym(io,"IOHIDEventGetType");
  if(!schedule||!unschedule||!callback||!hid_event_type)return 1;
  CFTypeRef monitor=create(kCFAllocatorDefault,1,NULL);printf("HID monitor client=%p duration=%u\n",monitor,seconds);if(!monitor)return 1;
  callback(monitor,hid_event_callback,NULL,NULL);schedule(monitor,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
  CFRunLoopRunInMode(kCFRunLoopDefaultMode,seconds,0);
  unschedule(monitor,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);CFRelease(monitor);
  for(unsigned i=0;i<64;i++)if(hid_event_counts[i])printf("HID events type=%u count=%u\n",i,hid_event_counts[i]);
 }
 alarm(0);return 0;
}

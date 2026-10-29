/* Bounded live adapter using the existing kernel HID queues and the virtual
 * service callbacks used in the retained HackiOS/OnePlus input reference.
 * Reads real device events; no synthetic gestures or exclusive HID opens. */
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include "input-kdk-digitizer.h"
typedef struct {
 uint64_t version;
 void(*notification)(void*,void*,CFTypeRef,uint32_t,CFDictionaryRef);
 Boolean(*set)(void*,void*,CFTypeRef,CFStringRef,CFTypeRef);
 CFTypeRef(*copy)(void*,void*,CFTypeRef,CFStringRef);
 CFTypeRef(*event)(void*,void*,CFTypeRef,uint32_t,CFTypeRef,uint32_t);
 int(*output)(void*,void*,CFTypeRef,CFTypeRef);
 CFTypeRef(*matching)(void*,void*,CFTypeRef,CFDictionaryRef);
} InputCallbacks;
typedef struct {
 const char *name;unsigned type;
 mach_port_t connection;mach_vm_address_t address;mach_vm_size_t size;
 CFMutableDictionaryRef properties;CFTypeRef service;
 uint64_t sender_id;
 unsigned opened,forwarded,failed;
} InputSource;
static InputSource input_sources[2];
static CFTypeRef input_property(void*t,void*c,CFTypeRef s,CFStringRef key){
 (void)t;(void)s;InputSource *source=c;CFTypeRef value=CFDictionaryGetValue(source->properties,key);return value?CFRetain(value):NULL;
}
static Boolean input_set(void*t,void*c,CFTypeRef s,CFStringRef key,CFTypeRef value){
 (void)t;(void)s;InputSource *source=c;
 if(CFEqual(key,CFSTR("DeviceOpenedByEventSystem"))&&CFEqual(value,kCFBooleanTrue)){__atomic_store_n(&source->opened,1,__ATOMIC_RELEASE);printf("input bridge %s opened by event system\n",source->name);}
 if(CFEqual(key,CFSTR("TouchDetectionMode"))){printf("input bridge touch mode=");CFShow(value);}
 return true;
}
static void input_notification(void*t,void*c,CFTypeRef s,uint32_t type,CFDictionaryRef p){(void)t;(void)c;(void)s;(void)p;printf("input bridge notification=%u\n",type);}
static const InputCallbacks input_callbacks={2,input_notification,input_set,input_property,NULL,NULL,NULL};
static int run_input_bridge(unsigned seconds,int native_digitizer){
 if(seconds<1||seconds>3600)return 2;
 alarm(seconds+30);
 void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_LOCAL);if(!io)return 1;
#define INPUT_API(result,name,args) result(*name)args=(result(*)args)dlsym(io,#name);if(!name){puts("missing " #name);return 1;}
 INPUT_API(CFMutableDictionaryRef,IOServiceMatching,(const char*))
 INPUT_API(int,IOServiceGetMatchingServices,(mach_port_t,CFDictionaryRef,mach_port_t*))
 INPUT_API(mach_port_t,IOIteratorNext,(mach_port_t))
 INPUT_API(int,IOObjectRelease,(mach_port_t))
 INPUT_API(CFTypeRef,IORegistryEntryCreateCFProperty,(mach_port_t,CFStringRef,CFAllocatorRef,uint32_t))
 INPUT_API(int,IOServiceOpen,(mach_port_t,mach_port_t,uint32_t,mach_port_t*))
 INPUT_API(int,IOServiceClose,(mach_port_t))
 INPUT_API(int,IOConnectCallScalarMethod,(mach_port_t,uint32_t,const uint64_t*,uint32_t,uint64_t*,uint32_t*))
 INPUT_API(int,IOConnectMapMemory64,(mach_port_t,uint32_t,mach_port_t,mach_vm_address_t*,mach_vm_size_t*,uint32_t))
 INPUT_API(int,IOConnectUnmapMemory64,(mach_port_t,uint32_t,mach_port_t,mach_vm_address_t))
 INPUT_API(Boolean,IODataQueueDataAvailable,(void*))
 INPUT_API(int,IODataQueueDequeue,(void*,void*,uint32_t*))
 INPUT_API(CFTypeRef,IOHIDEventSystemClientCreateWithType,(CFAllocatorRef,int,CFDictionaryRef))
 INPUT_API(void,IOHIDEventSystemClientScheduleWithDispatchQueue,(CFTypeRef,dispatch_queue_t))
 INPUT_API(CFTypeRef,IOHIDVirtualServiceClientCreateWithCallbacks,(CFTypeRef,CFDictionaryRef,const InputCallbacks*,void*,void*))
 INPUT_API(Boolean,IOHIDVirtualServiceClientRemove,(CFTypeRef))
 INPUT_API(Boolean,IOHIDVirtualServiceClientDispatchEvent,(CFTypeRef,CFTypeRef))
 INPUT_API(CFTypeRef,IOHIDEventCreateWithBytes,(CFAllocatorRef,const uint8_t*,CFIndex))
 INPUT_API(unsigned,IOHIDEventGetType,(CFTypeRef))
 INPUT_API(CFIndex,IOHIDEventGetIntegerValue,(CFTypeRef,uint32_t))
 INPUT_API(void,IOHIDEventSetIntegerValue,(CFTypeRef,uint32_t,CFIndex))
 INPUT_API(void,IOHIDEventSetSenderID,(CFTypeRef,uint64_t))
 INPUT_API(CFTypeRef,IOHIDServiceClientGetRegistryID,(CFTypeRef))
 INPUT_API(CFArrayRef,IOHIDEventGetChildren,(CFTypeRef))
 INPUT_API(CFTypeRef,IOHIDEventCreateDigitizerEvent,(CFAllocatorRef,uint64_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,double,double,double,double,double,double,Boolean,Boolean,uint32_t))
 INPUT_API(CFTypeRef,IOHIDEventCreateDigitizerFingerEvent,(CFAllocatorRef,uint64_t,uint32_t,uint32_t,uint32_t,double,double,double,double,double,Boolean,Boolean,uint32_t))
 INPUT_API(void,IOHIDEventAppendEvent,(CFTypeRef,CFTypeRef,uint32_t))
#undef INPUT_API
 CFTypeRef client=IOHIDEventSystemClientCreateWithType(NULL,3,NULL);if(!client)return 1;printf("input bridge client type=3 (rate controlled)\n");
 dispatch_queue_t queue=dispatch_queue_create("org.unixnu.zeta.live-input",NULL);IOHIDEventSystemClientScheduleWithDispatchQueue(client,queue);
 mach_port_t iterator=0;int status=IOServiceGetMatchingServices(MACH_PORT_NULL,IOServiceMatching("IOHIDEventService"),&iterator);if(status){CFRelease(client);return 1;}
 unsigned sources=0;mach_port_t entry;
 while((entry=IOIteratorNext(iterator))){
  CFTypeRef product=IORegistryEntryCreateCFProperty(entry,CFSTR("Product"),NULL,0);
  int index=product&&CFEqual(product,CFSTR("Offline touch digitizer"))?0:product&&CFEqual(product,CFSTR("Offline HID input probe"))?1:-1;
  if(product)CFRelease(product);
  if(index>=0&&!input_sources[index].connection){
   InputSource *source=&input_sources[index];source->name=index?"buttons":"touch";source->type=index?3:11;
   status=IOServiceOpen(entry,mach_task_self(),0,&source->connection);printf("input bridge %s user-client=%#x status=%#x\n",source->name,source->connection,status);
   if(!status){uint64_t options=0;status=IOConnectCallScalarMethod(source->connection,0,&options,1,NULL,NULL);printf("input bridge %s open status=%#x\n",source->name,status);
    if(!status)status=IOConnectMapMemory64(source->connection,0,mach_task_self(),&source->address,&source->size,1);
    printf("input bridge %s queue=%#llx bytes=%llu status=%#x\n",source->name,source->address,source->size,status);
    if(!status&&source->address&&source->size>=12&&source->size<=4*1024*1024){
     source->properties=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
     capture_number(source->properties,"PrimaryUsagePage",index?12:13);capture_number(source->properties,"PrimaryUsage",index?1:4);
     capture_number(source->properties,"DeviceUsagePage",index?12:13);capture_number(source->properties,"DeviceUsage",index?1:4);
     capture_number(source->properties,"VendorID",0);capture_number(source->properties,"ProductID",0);capture_number(source->properties,"ReportInterval",8000);
     CFMutableDictionaryRef pair=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
     capture_number(pair,"DeviceUsagePage",index?12:13);capture_number(pair,"DeviceUsage",index?1:4);
     const void *pair_value=pair;CFArrayRef pairs=CFArrayCreate(NULL,&pair_value,1,&kCFTypeArrayCallBacks);
     CFDictionarySetValue(source->properties,CFSTR("DeviceUsagePairs"),pairs);CFRelease(pairs);CFRelease(pair);
     CFDictionarySetValue(source->properties,CFSTR("Built-In"),kCFBooleanTrue);CFDictionarySetValue(source->properties,CFSTR("Transport"),CFSTR("SPI"));
     CFDictionarySetValue(source->properties,CFSTR("Product"),index?CFSTR("Duo2 live buttons"):CFSTR("Duo2 live touch"));
     if(!index)CFDictionarySetValue(source->properties,CFSTR("DisplayIntegrated"),kCFBooleanTrue);
     source->service=IOHIDVirtualServiceClientCreateWithCallbacks(client,source->properties,&input_callbacks,NULL,source);
     printf("input bridge %s virtual-service=%p\n",source->name,source->service);if(source->service)sources++;
    }
   }
  }
  IOObjectRelease(entry);
 }
 IOObjectRelease(iterator);
 printf("input bridge sources=%u duration=%u\n",sources,seconds);
 uint64_t end=mach_continuous_time();mach_timebase_info_data_t tb;mach_timebase_info(&tb);end+=(uint64_t)seconds*1000000000ULL*tb.denom/tb.numer;
 uint8_t bytes[65536];unsigned elapsed=0;
 while(sources&&mach_continuous_time()<end){
  for(unsigned i=0;i<2;i++){
   InputSource *s=&input_sources[i];if(!s->service||!s->address)continue;
   for(unsigned n=0;n<256&&IODataQueueDataAvailable((void*)s->address);n++){
    uint32_t count=sizeof bytes;status=IODataQueueDequeue((void*)s->address,bytes,&count);
    if(status){printf("input bridge %s dequeue=%#x bytes=%u\n",s->name,status,count);s->failed++;break;}
    CFTypeRef event=NULL;
    if(i==0&&native_digitizer){
     KdkTouch touch;
     if(!decode_kdk_touch(bytes,count,&touch)){s->failed++;if(s->failed<=4)printf("KDK digitizer wire rejected bytes=%u\n",count);continue;}
     uint32_t mask=0;Boolean down=false;
     for(unsigned ci=0;ci<touch.count;ci++){mask|=touch.fingers[ci].mask;down|=touch.fingers[ci].down!=0;}
     event=IOHIDEventCreateDigitizerEvent(NULL,touch.timestamp,3,0,0,mask&~1U,0,touch.fingers[0].x,touch.fingers[0].y,0,0,0,0,down,down,0);
     if(!event){s->failed++;continue;}
     for(unsigned ci=0;ci<touch.count;ci++){
      const KdkFinger *f=&touch.fingers[ci];
      CFTypeRef finger=IOHIDEventCreateDigitizerFingerEvent(NULL,touch.timestamp,f->index+1,f->index+2,f->mask,f->x,f->y,0,f->down?1.0:0.0,0,f->down,f->down,0);
      if(finger){IOHIDEventAppendEvent(event,finger,0);CFRelease(finger);}
     }
     if(s->forwarded<4)printf("KDK touch decoded fingers=%u index=%u mask=%#x x=%.6f y=%.6f down=%d\n",touch.count,touch.fingers[0].index,touch.fingers[0].mask,touch.fingers[0].x,touch.fingers[0].y,touch.fingers[0].down);
    }else event=IOHIDEventCreateWithBytes(NULL,bytes,count);
    if(!event){s->failed++;continue;}
    unsigned type=IOHIDEventGetType(event);
    if(type==3&&s->forwarded<8)printf("input bridge keyboard page=%#lx usage=%#lx down=%ld\n",(unsigned long)IOHIDEventGetIntegerValue(event,0x30000),(unsigned long)IOHIDEventGetIntegerValue(event,0x30001),(long)IOHIDEventGetIntegerValue(event,0x30002));
    // Replacing a kernel producer with a virtual service also replaces the
    // sender identity. Button policy requires built-in events, and UIKit's
    // main-screen digitizer requires integrated hand and finger events.
    /* GetRegistryID returns a borrowed CFNumber, not uint64_t. Passing its
     * tagged object pointer as SenderID loses the event/service association.
     * Match IOKit's native CFNumberGetValue(kCFNumberSInt64Type) callers. */
    CFTypeRef registry_number=IOHIDServiceClientGetRegistryID(s->service);int64_t registry_id=0;
    if(!registry_number||CFGetTypeID(registry_number)!=CFNumberGetTypeID()||!CFNumberGetValue((CFNumberRef)registry_number,kCFNumberSInt64Type,&registry_id)||!registry_id){
     if(++s->failed<=4)printf("input bridge %s numeric sender identity unavailable; event not dispatched\n",s->name);
     CFRelease(event);continue;
    }
    uint64_t sender_id=(uint64_t)registry_id;
    if(sender_id!=s->sender_id){s->sender_id=sender_id;printf("input bridge %s numeric sender=%#llx registry_number=%p\n",s->name,(unsigned long long)sender_id,registry_number);}
    IOHIDEventSetSenderID(event,sender_id);
    IOHIDEventSetIntegerValue(event,4,1);
    if(type==11){IOHIDEventSetIntegerValue(event,0xb0019,1);CFArrayRef children=IOHIDEventGetChildren(event);if(children)for(CFIndex ci=0;ci<CFArrayGetCount(children);ci++){CFTypeRef child=CFArrayGetValueAtIndex(children,ci);IOHIDEventSetIntegerValue(child,4,1);IOHIDEventSetIntegerValue(child,0xb0019,1);}}
    if(type==11&&s->forwarded<4){
     CFArrayRef children=IOHIDEventGetChildren(event);
     printf("input touch bytes=%u children=%ld type=%ld mask=%#lx range=%ld touch=%ld integrated=%ld\n",count,children?(long)CFArrayGetCount(children):0L,(long)IOHIDEventGetIntegerValue(event,0xb0006),(unsigned long)IOHIDEventGetIntegerValue(event,0xb0007),(long)IOHIDEventGetIntegerValue(event,0xb0008),(long)IOHIDEventGetIntegerValue(event,0xb0009),(long)IOHIDEventGetIntegerValue(event,0xb0019));
     CFShow(event);
    }
    if(type==s->type&&__atomic_load_n(&s->opened,__ATOMIC_ACQUIRE)){if(IOHIDVirtualServiceClientDispatchEvent(s->service,event))s->forwarded++;else s->failed++;}
    CFRelease(event);
   }
  }
  usleep(10000);
  if(++elapsed%100==0)for(unsigned i=0;i<2;i++)printf("input bridge %s opened=%u sent=%u failed=%u\n",input_sources[i].name?input_sources[i].name:"absent",input_sources[i].opened,input_sources[i].forwarded,input_sources[i].failed);
 }
 for(unsigned i=0;i<2;i++){
  InputSource *s=&input_sources[i];if(s->service){IOHIDVirtualServiceClientRemove(s->service);CFRelease(s->service);}
  if(s->address)IOConnectUnmapMemory64(s->connection,0,mach_task_self(),s->address);
  if(s->connection){uint64_t options=0;IOConnectCallScalarMethod(s->connection,1,&options,1,NULL,NULL);IOServiceClose(s->connection);}
 }
 CFRelease(client);alarm(0);return sources?0:1;
}

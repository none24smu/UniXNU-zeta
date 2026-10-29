/* Read-only queries through the shipped iOS27 IOMobileFramebuffer interface.
 * The getter trampolines' register contracts were checked in the exact cache.
 * No guessed external-method selectors or synthesized scanout are used. */
static unsigned framebuffer_notification_count;
static void framebuffer_notification(void *context,uint64_t a,uint64_t b,uint64_t c){
 printf("IOMFB notification context=%p words=%#llx/%#llx/%#llx\n",context,(unsigned long long)a,(unsigned long long)b,(unsigned long long)c);framebuffer_notification_count++;
}
static int probe_framebuffer(int wake){
 void *library=dlopen("/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer",RTLD_NOW|RTLD_LOCAL);
 if(!library){printf("IOMobileFramebuffer dlopen failed: %s\n",dlerror());return 1;}
 typedef int(*getmain_t)(void**);typedef int(*getsize_t)(void*,void*);typedef int(*getsurface_t)(void*,unsigned,void**);typedef unsigned(*surfaceid_t)(void*);typedef size_t(*surfacevalue_t)(void*);
 getmain_t main_display=(getmain_t)dlsym(library,"IOMobileFramebufferGetMainDisplay");getsize_t display_size=(getsize_t)dlsym(library,"IOMobileFramebufferGetDisplaySize");getsurface_t layer_surface=(getsurface_t)dlsym(library,"IOMobileFramebufferGetLayerDefaultSurface");
 if(!main_display||!display_size||!layer_surface){puts("missing verified IOMFB getter exports");return 1;}
 void *display=NULL;int status=main_display(&display);printf("IOMobileFramebufferGetMainDisplay status=%#x ref=%p\n",status,display);if(status||!display)return 1;
 union{unsigned char bytes[32];double f64[4];uint32_t u32[8];} size={0};status=display_size(display,&size);printf("GetDisplaySize status=%#x raw=",status);for(unsigned i=0;i<16;i++)printf("%02x",size.bytes[i]);printf(" f64=%gx%g u32=%ux%u\n",size.f64[0],size.f64[1],size.u32[0],size.u32[1]);
 surfaceid_t surface_id=(surfaceid_t)dlsym(RTLD_DEFAULT,"IOSurfaceGetID");surfacevalue_t width=(surfacevalue_t)dlsym(RTLD_DEFAULT,"IOSurfaceGetWidth"),height=(surfacevalue_t)dlsym(RTLD_DEFAULT,"IOSurfaceGetHeight"),stride=(surfacevalue_t)dlsym(RTLD_DEFAULT,"IOSurfaceGetBytesPerRow");
 for(unsigned layer=0;layer<3;layer++){void *surface=NULL;status=layer_surface(display,layer,&surface);printf("GetLayerDefaultSurface layer=%u status=%#x ref=%p",layer,status,surface);if(!status&&surface&&surface_id&&width&&height&&stride)printf(" id=%u size=%zux%zu stride=%zu",surface_id(surface),width(surface),height(surface),stride(surface));puts("");}
 const unsigned offsets[]={0xb20,0xb38,0xc20,0xc28,0xca8,0xcb0,0xcd0};for(unsigned i=0;i<7;i++){uintptr_t target=0;memcpy(&target,(unsigned char*)display+offsets[i],sizeof target);printf("IOMFB callback offset=%#x target=%#llx\n",offsets[i],(unsigned long long)target);}
 if(wake==2){
  typedef int(*enable_t)(void*,void(*)(void*,uint64_t,uint64_t,uint64_t),void*);typedef int(*disable_t)(void*);
  enable_t vsync=(enable_t)dlsym(library,"IOMobileFramebufferEnableVSyncNotifications"),power=(enable_t)dlsym(library,"IOMobileFramebufferEnablePowerNotifications");
  disable_t stopvsync=(disable_t)dlsym(library,"IOMobileFramebufferDisableVSyncNotifications"),stoppower=(disable_t)dlsym(library,"IOMobileFramebufferDisablePowerNotifications");
  if(!vsync||!power||!stopvsync||!stoppower)return 1;
  int v=vsync(display,framebuffer_notification,(void*)5),p=power(display,framebuffer_notification,(void*)1);
  printf("IOMFB notifications vsync=%#x power=%#x\n",v,p);CFRunLoopRunInMode(kCFRunLoopDefaultMode,5,0);
  printf("IOMFB notification total=%u\n",framebuffer_notification_count);if(!v)stopvsync(display);if(!p)stoppower(display);
  return v||p?1:0;
 }
 if(wake==1){int(*power)(void*,uint32_t)=(int(*)(void*,uint32_t))dlsym(library,"IOMobileFramebufferRequestPowerChange");if(!power)return 1;status=power(display,1);printf("IOMobileFramebufferRequestPowerChange requested=1 status=%#x\n",status);if(status)return 1;}
 printf("Power request API=%p; layer submission APIs=%p/%p/%p (not called)\n",dlsym(library,"IOMobileFramebufferRequestPowerChange"),dlsym(library,"IOMobileFramebufferSwapBegin"),dlsym(library,"IOMobileFramebufferSwapSetLayer"),dlsym(library,"IOMobileFramebufferSwapEnd"));
 return 0;
}

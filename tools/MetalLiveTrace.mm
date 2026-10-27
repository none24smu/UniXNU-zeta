// Diagnostic loader for the already staged resolve-corrected plugin.
// Hooks forward original arguments/results unchanged. No GPU or kernel policy change.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#include <atomic>
#include <cstdio>
#include <cstdarg>
#include <dlfcn.h>
#include <unistd.h>
#include <string>
static FILE *stream;
static std::atomic<unsigned> records;
static IMP originalPipeline;
static void logline(const char *fmt,...) {
 if(!stream || records.fetch_add(1)>=512)return;
 flockfile(stream);fprintf(stream,"pid=%d ",getpid());va_list a;va_start(a,fmt);vfprintf(stream,fmt,a);va_end(a);fputc('\n',stream);fflush(stream);funlockfile(stream);
}
static void bytes(id obj,const char *stage,const void *p,NSUInteger n,NSUInteger i) {
 if(!p)return;char hex[513];NSUInteger count=MIN(n,256ul);const unsigned char *b=(const unsigned char *)p;
 for(NSUInteger k=0;k<count;k++)snprintf(hex+k*2,3,"%02x",b[k]);hex[count*2]=0;
 logline("B encoder=%p stage=%s index=%lu length=%lu bytes=%s",(__bridge void *)obj,stage,(unsigned long)i,(unsigned long)n,hex);
}
typedef id RetainedPipeline(id,SEL,id,NSError **) __attribute__((ns_returns_retained));
static id tracePipeline(id self,SEL s,MTLRenderPipelineDescriptor *d,NSError **error) __attribute__((ns_returns_retained));
static id tracePipeline(id self,SEL s,MTLRenderPipelineDescriptor *d,NSError **error) {
 id result=((RetainedPipeline *)originalPipeline)(self,s,d,error);
 logline("R pipeline=%p label=%s vertex=%s fragment=%s",(__bridge void *)result,d.label.UTF8String?:"-",d.vertexFunction.name.UTF8String?:"-",d.fragmentFunction.name.UTF8String?:"-");return result;
}
static void install() {
 Class re=objc_getClass("NBRenderEncoder"), cb=objc_getClass("NBCommandBuffer"), dm=objc_getClass("NBDeviceMethods");
 if(!re||!cb||!dm){logline("ERROR required classes missing");return;}
 {
  SEL s=sel_registerName("renderCommandEncoderWithDescriptor:");Method m=class_getInstanceMethod(cb,s);IMP orig=method_getImplementation(m);
  method_setImplementation(m,imp_implementationWithBlock(^id(id self,MTLRenderPassDescriptor *d){
   auto c=d.colorAttachments[0];auto z=d.depthAttachment;
   logline("P cb=%p color=%p size=%lux%lu samples=%lu load=%lu store=%lu clear=%g,%g,%g,%g resolve=%p depth=%p depthLoad=%lu depthStore=%lu depthClear=%g",(__bridge void *)self,(__bridge void *)c.texture,(unsigned long)c.texture.width,(unsigned long)c.texture.height,(unsigned long)c.texture.sampleCount,(unsigned long)c.loadAction,(unsigned long)c.storeAction,c.clearColor.red,c.clearColor.green,c.clearColor.blue,c.clearColor.alpha,(__bridge void *)c.resolveTexture,(__bridge void *)z.texture,(unsigned long)z.loadAction,(unsigned long)z.storeAction,z.clearDepth);
   id result=((id(*)(id,SEL,id))orig)(self,s,d);logline("P encoder=%p cb=%p",(__bridge void *)result,(__bridge void *)self);return result;
  }));
 }
 {
  SEL s=sel_registerName("setViewport:");Method m=class_getInstanceMethod(re,s);IMP orig=method_getImplementation(m);
  method_setImplementation(m,imp_implementationWithBlock(^(id self,MTLViewport v){logline("V encoder=%p xy=%g,%g wh=%g,%g z=%g,%g",(__bridge void *)self,v.originX,v.originY,v.width,v.height,v.znear,v.zfar);((void(*)(id,SEL,MTLViewport))orig)(self,s,v);}));
 }
 {
  SEL s=sel_registerName("setScissorRect:");Method m=class_getInstanceMethod(re,s);IMP orig=method_getImplementation(m);
  method_setImplementation(m,imp_implementationWithBlock(^(id self,MTLScissorRect r){logline("S encoder=%p xy=%lu,%lu wh=%lu,%lu",(__bridge void *)self,(unsigned long)r.x,(unsigned long)r.y,(unsigned long)r.width,(unsigned long)r.height);((void(*)(id,SEL,MTLScissorRect))orig)(self,s,r);}));
 }
 {
  SEL s=sel_registerName("newRenderPipelineStateWithDescriptor:error:");Method m=class_getInstanceMethod(dm,s);originalPipeline=method_getImplementation(m);
  method_setImplementation(m,(IMP)tracePipeline);
 }
 {
  SEL s=sel_registerName("setRenderPipelineState:");Method m=class_getInstanceMethod(re,s);IMP orig=method_getImplementation(m);
  method_setImplementation(m,imp_implementationWithBlock(^(id self,id state){logline("R encoder=%p pipeline=%p",(__bridge void *)self,(__bridge void *)state);((void(*)(id,SEL,id))orig)(self,s,state);}));
 }
 for(NSString *name in @[@"setVertexBytes:length:atIndex:",@"setFragmentBytes:length:atIndex:"]) {
  SEL s=NSSelectorFromString(name);Method m=class_getInstanceMethod(re,s);IMP orig=method_getImplementation(m);BOOL vertex=[name hasPrefix:@"setVertex"];
  method_setImplementation(m,imp_implementationWithBlock(^(id self,const void *p,NSUInteger n,NSUInteger i){bytes(self,vertex?"vertex":"fragment",p,n,i);((void(*)(id,SEL,const void *,NSUInteger,NSUInteger))orig)(self,s,p,n,i);}));
 }
 for(NSString *name in @[@"setVertexBuffer:offset:atIndex:",@"setFragmentBuffer:offset:atIndex:"]) {
  SEL s=NSSelectorFromString(name);Method m=class_getInstanceMethod(re,s);IMP orig=method_getImplementation(m);BOOL vertex=[name hasPrefix:@"setVertex"];
  method_setImplementation(m,imp_implementationWithBlock(^(id self,id<MTLBuffer> b,NSUInteger off,NSUInteger i){logline("B encoder=%p stage=%s buffer=%p index=%lu offset=%lu length=%lu storage=%lu",(__bridge void *)self,vertex?"vertex":"fragment",(__bridge void *)b,(unsigned long)i,(unsigned long)off,(unsigned long)b.length,(unsigned long)b.storageMode);if(b && b.storageMode!=MTLStorageModePrivate && off<b.length){const void *contents=b.contents;if(contents)bytes(self,vertex?"vertex":"fragment",(const char *)contents+off,MIN(b.length-off,256ul),i);}((void(*)(id,SEL,id,NSUInteger,NSUInteger))orig)(self,s,b,off,i);}));
 }
 {
  SEL s=sel_registerName("drawPrimitives:vertexStart:vertexCount:instanceCount:baseInstance:");Method m=class_getInstanceMethod(re,s);IMP orig=method_getImplementation(m);
  method_setImplementation(m,imp_implementationWithBlock(^(id self,MTLPrimitiveType t,NSUInteger start,NSUInteger n,NSUInteger count,NSUInteger base){logline("D encoder=%p primitive=%lu start=%lu count=%lu instances=%lu base=%lu",(__bridge void *)self,(unsigned long)t,(unsigned long)start,(unsigned long)n,(unsigned long)count,(unsigned long)base);((void(*)(id,SEL,MTLPrimitiveType,NSUInteger,NSUInteger,NSUInteger,NSUInteger))orig)(self,s,t,start,n,count,base);}));
 }
 {
  SEL s=sel_registerName("drawIndexedPrimitives:indexCount:indexType:indexBuffer:indexBufferOffset:instanceCount:baseVertex:baseInstance:");Method m=class_getInstanceMethod(re,s);IMP orig=method_getImplementation(m);
  method_setImplementation(m,imp_implementationWithBlock(^(id self,MTLPrimitiveType t,NSUInteger n,MTLIndexType k,id b,NSUInteger off,NSUInteger count,NSInteger baseV,NSUInteger baseI){logline("I encoder=%p primitive=%lu count=%lu type=%lu buffer=%p offset=%lu instances=%lu baseVertex=%ld baseInstance=%lu",(__bridge void *)self,(unsigned long)t,(unsigned long)n,(unsigned long)k,(__bridge void *)b,(unsigned long)off,(unsigned long)count,(long)baseV,(unsigned long)baseI);((void(*)(id,SEL,MTLPrimitiveType,NSUInteger,MTLIndexType,id,NSUInteger,NSUInteger,NSInteger,NSUInteger))orig)(self,s,t,n,k,b,off,count,baseV,baseI);}));
 }
 logline("READY unchanged render argument tracing installed");
}
__attribute__((constructor)) static void start() {
 @autoreleasepool {
  char dir[1024]={};confstr(_CS_DARWIN_USER_TEMP_DIR,dir,sizeof dir);std::string path=std::string(dir)+"metal-live-draws-"+std::to_string(getpid())+".log";stream=fopen(path.c_str(),"a");
  Dl_info image={};if(!dladdr((const void *)&start,&image)||!image.dli_fname){logline("ERROR loader path");return;}
  std::string dependency=image.dli_fname;dependency.resize(dependency.rfind('/')+1);dependency+="NativeAdrenoMetal.msaa";
  if(!dlopen(dependency.c_str(),RTLD_NOW|RTLD_LOCAL)){logline("ERROR dlopen %s",dlerror());return;}
  install();
 }
}

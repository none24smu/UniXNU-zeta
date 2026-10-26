// SPDX-License-Identifier: MIT
// Execute the production present path with a CPU copy peer. Checks ownership,
// mapping identity and copied bytes; this deliberately proves no GPU rendering.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <cassert>
#include <cstring>
#include <cstdio>
#include "GpuScanoutPresenter.h"
static unsigned imports=0,live=0;
@interface CacheBuffer : NSObject
@property(nonatomic) void *contents;
@end
@implementation CacheBuffer
- (instancetype)init {if((self=[super init]))++live;return self;}
- (void)dealloc {--live;}
@end
@interface CacheBlit : NSObject
@end
@implementation CacheBlit
- (void)copyFromBuffer:(id<MTLBuffer>)source sourceOffset:(NSUInteger)a toBuffer:(id<MTLBuffer>)target destinationOffset:(NSUInteger)b size:(NSUInteger)n {
    memcpy((char *)target.contents+b,(const char *)source.contents+a,n);
}
- (void)endEncoding {}
@end
@interface CacheCommand : NSObject
@end
@implementation CacheCommand
- (id<MTLBlitCommandEncoder>)blitCommandEncoder {return (id)[CacheBlit new];}
- (void)commit {}
- (void)waitUntilCompleted {}
- (MTLCommandBufferStatus)status {return MTLCommandBufferStatusCompleted;}
@end
@interface CacheQueue : NSObject
@end
@implementation CacheQueue
- (id<MTLCommandBuffer>)commandBuffer {return (id)[CacheCommand new];}
@end
@interface CacheDevice : NSObject
@property(nonatomic) BOOL failNext;
@end
@implementation CacheDevice
- (id<MTLCommandQueue>)newCommandQueue {return (id)[CacheQueue new];}
- (id<MTLBuffer>)newBufferWithBytesNoCopy:(void *)p length:(NSUInteger)n options:(MTLResourceOptions)o deallocator:(void (^)(void *,NSUInteger))release {
    (void)n;(void)o;(void)release;++imports;
    if(self.failNext){self.failNext=NO;return nil;}
    CacheBuffer *buffer=[CacheBuffer new];buffer.contents=p;return (id)buffer;
}
@end
static gpupresent::Result show(gpupresent::Presenter &presenter,const gpupresent::Frame &frame) {
    @autoreleasepool {return presenter.present(frame);}
}
int main() {
    @autoreleasepool {
        const size_t page=(size_t)getpagesize();void *input=nullptr,*output=nullptr;
        assert(!posix_memalign(&input,page,page*8));assert(!posix_memalign(&output,page,page));
        memset(input,0x6b,page*8);memset(output,0,page);
        CacheDevice *device=[CacheDevice new];
        {
            gpupresent::Presenter presenter((id)device,{output,page,8,2,2});assert(presenter.ready());
            gpupresent::Frame frame={input,page,8,2,2,1};
            assert(show(presenter,frame)==gpupresent::kOk);assert(imports==2 && !memcmp(input,output,16));
            for(unsigned i=0;i<20;++i)assert(show(presenter,frame)==gpupresent::kOk);
            assert(imports==2); // stable mapping imports once, despite repeated frames
            frame.mapping=2;assert(show(presenter,frame)==gpupresent::kOk && imports==3);
            // Same address and length with a new identity must import again.
            for(unsigned i=3;i<=6;++i){frame.mapping=i;assert(show(presenter,frame)==gpupresent::kOk);}
            const unsigned before=imports;frame.mapping=6;
            assert(show(presenter,frame)==gpupresent::kOk && imports==before);
            frame.mapping=1;assert(show(presenter,frame)==gpupresent::kOk && imports==before+1); // evicted
            // Failed imports invalidate older cached sources before the kernel can evict their mappings.
            device.failNext=YES;frame.mapping=99;
            assert(show(presenter,frame)==gpupresent::kNoResource);
            assert(live==1); // only the scanout target survives
            frame.mapping=1;assert(show(presenter,frame)==gpupresent::kOk);
            const unsigned transient=imports;frame.mapping=0;
            for(unsigned i=0;i<2;++i){@autoreleasepool {assert(show(presenter,frame)==gpupresent::kOk);}}
            assert(imports==transient+2 && !memcmp(input,output,16));
        }
        assert(live==0);free(input);free(output);
        puts("PASS: production present copies, stable import reuse, changed identities, LRU, failed-import drain and transient mapping fallback; CPU peer only");
    }
}

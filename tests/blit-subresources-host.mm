// SPDX-License-Identifier: MIT
// Real frontend/runtime textures; intercept the lower-level copy only to verify
// range expansion, then restore it and encode/retire a genuine runtime copy.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#include <cstdio>
#include <vector>
#include "NativeBridgeMetalFrontend.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
struct Copy {NSUInteger ss,sl,ds,dl;MTLSize size;};
static std::vector<Copy> copies;
static void record(id,SEL,id,NSUInteger ss,NSUInteger sl,MTLOrigin so,MTLSize size,id,NSUInteger ds,NSUInteger dl,MTLOrigin dest){
 if(so.x || so.y || so.z || dest.x || dest.y || dest.z)std::abort();
 copies.push_back({ss,sl,ds,dl,size});
}
int main(int argc,char **argv){
 if(argc!=3)return 2;
 @autoreleasepool{
  id<MTLDevice> device=native_bridge_metal_open(argv[1],argv[2],0x7a657461,nullptr);CHECK(device);
  auto td=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:16 height:8 mipmapped:YES];
  td.textureType=MTLTextureType2DArray;td.arrayLength=4;td.storageMode=MTLStorageModePrivate;
  id<MTLTexture> source=[device newTextureWithDescriptor:td];CHECK(source);
  td.width=32;td.height=16;td.mipmapLevelCount=6;td.arrayLength=5;
  id<MTLTexture> destination=[device newTextureWithDescriptor:td];CHECK(destination);
  id<MTLCommandQueue> queue=[device newCommandQueue];CHECK(queue);
  id<MTLCommandBuffer> cb=[queue commandBuffer];id<MTLBlitCommandEncoder> blit=[cb blitCommandEncoder];CHECK(blit);
  SEL range=@selector(copyFromTexture:sourceSlice:sourceLevel:toTexture:destinationSlice:destinationLevel:sliceCount:levelCount:);
  CHECK([blit respondsToSelector:range]);
  SEL lower=@selector(copyFromTexture:sourceSlice:sourceLevel:sourceOrigin:sourceSize:toTexture:destinationSlice:destinationLevel:destinationOrigin:);
  Method method=class_getInstanceMethod(object_getClass(blit),lower);CHECK(method);IMP original=method_setImplementation(method,(IMP)record);
  [blit copyFromTexture:source sourceSlice:1 sourceLevel:1 toTexture:destination destinationSlice:2 destinationLevel:2 sliceCount:2 levelCount:2];
  CHECK(copies.size()==4);
  for(unsigned i=0;i<4;++i){const auto &c=copies[i];CHECK(c.ss==1+i/2 && c.ds==2+i/2 && c.sl==1+i%2 && c.dl==2+i%2 && c.size.width==(8u>>(i%2)) && c.size.height==(4u>>(i%2)) && c.size.depth==1);}
  copies.clear();[blit copyFromTexture:source sourceSlice:1 sourceLevel:1 toTexture:destination destinationSlice:2 destinationLevel:2 sliceCount:0 levelCount:2];CHECK(copies.empty());
  method_setImplementation(method,original);[blit endEncoding];[cb commit];[cb waitUntilCompleted];CHECK(cb.status==MTLCommandBufferStatusCompleted);
  // Real bridge call and completion through the software CP, not a pixel test.
  cb=[queue commandBuffer];blit=[cb blitCommandEncoder];
  [blit copyFromTexture:source sourceSlice:1 sourceLevel:1 toTexture:destination destinationSlice:2 destinationLevel:2 sliceCount:2 levelCount:2];
  [blit endEncoding];[cb commit];[cb waitUntilCompleted];CHECK(cb.status==MTLCommandBufferStatusCompleted);
  // Invalid range and dimension mismatch refuse before any lower-level call.
  for(unsigned test=0;test<4;++test){
   cb=[queue commandBuffer];blit=[cb blitCommandEncoder];copies.clear();method_setImplementation(method,(IMP)record);
   if(test==0)[blit copyFromTexture:source sourceSlice:NSUIntegerMax sourceLevel:0 toTexture:destination destinationSlice:0 destinationLevel:1 sliceCount:2 levelCount:1];
   if(test==1)[blit copyFromTexture:source sourceSlice:0 sourceLevel:4 toTexture:destination destinationSlice:0 destinationLevel:5 sliceCount:1 levelCount:2];
   if(test==2)[blit copyFromTexture:source sourceSlice:0 sourceLevel:0 toTexture:destination destinationSlice:0 destinationLevel:0 sliceCount:1 levelCount:1];
   if(test==3)[blit copyFromTexture:nil sourceSlice:0 sourceLevel:0 toTexture:destination destinationSlice:0 destinationLevel:1 sliceCount:1 levelCount:1];
   CHECK(copies.empty());method_setImplementation(method,original);[blit endEncoding];[cb commit];[cb waitUntilCompleted];CHECK(cb.status==MTLCommandBufferStatusError);
  }
  puts("PASS: ranged texture-copy selector, slice/mip offsets and dimensions, zero-copy count, real runtime encoding/completion and four invalid-range refusals; software peer executes no shader");
 }
}

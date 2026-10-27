// SPDX-License-Identifier: MIT
// Exercise the shipping frontend/C ABI, including a dropped-resolve control.
// The software kernel peer validates descriptors and retires commands. Only an
// executing backend with --pixels establishes the resolved pixel values.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include "NativeBridgeMetalFrontend.h"
#include "bridge/NativeMetalObjects.h"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s (%s)\n",__LINE__,#x,nmb_last_error());return 1;}}while(0)
static id<MTLTexture> texture(id<MTLDevice> device,NSUInteger width,NSUInteger height,NSUInteger samples) {
 auto d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:width height:height mipmapped:NO];
 d.textureType=samples>1?MTLTextureType2DMultisample:MTLTextureType2D;
 d.sampleCount=samples;d.storageMode=samples>1?MTLStorageModePrivate:MTLStorageModeShared;
 d.usage=MTLTextureUsageRenderTarget;
 return [device newTextureWithDescriptor:d];
}
static MTLRenderPassDescriptor *pass(id<MTLTexture> source,id<MTLTexture> destination) {
 auto p=[MTLRenderPassDescriptor renderPassDescriptor];
 p.colorAttachments[0].texture=source;p.colorAttachments[0].resolveTexture=destination;
 p.colorAttachments[0].loadAction=MTLLoadActionClear;
 p.colorAttachments[0].storeAction=MTLStoreActionMultisampleResolve;
 p.colorAttachments[0].clearColor=MTLClearColorMake(1,0,0,1);
 return p;
}
static bool refused(id<MTLCommandQueue> queue,MTLRenderPassDescriptor *p) {
 id<MTLCommandBuffer> cb=[queue commandBuffer];if(!cb)return false;
 id<MTLRenderCommandEncoder> encoder=[cb renderCommandEncoderWithDescriptor:p];
 if(encoder)[encoder endEncoding];
 [cb commit];[cb waitUntilCompleted];
 return cb.status==MTLCommandBufferStatusError;
}
int main(int argc,char **argv) {
 if(argc!=3 && argc!=4)return 2;
 @autoreleasepool {
  const bool pixels=argc==4 && !strcmp(argv[3],"--pixels");
  id<MTLDevice> device=native_bridge_metal_open(argv[1],argv[2],0x7a657461,nullptr);CHECK(device);
  CHECK([device supportsTextureSampleCount:4]);
  id<MTLCommandQueue> queue=[device newCommandQueue];CHECK(queue);
  id<MTLTexture> source=texture(device,8,8,4),destination=texture(device,8,8,1),invalidResolve=texture(device,8,8,4);
  CHECK(source && destination && invalidResolve);
  // The original frontend silently discards this invalid resolve destination
  // and completes the pass. The fixed bridge must reach runtime validation,
  // whether the runtime validates during creation or when the encoder ends.
  if(!refused(queue,pass(source,invalidResolve))) {
   fprintf(stderr,"FAIL: multisampled resolve destination was accepted\n");return 1;
  }
  // Resolve a clear-only pass: no shader compiler or linked functions involved.
  // Both Metal resolve store actions must keep the destination image.
  for(MTLStoreAction store:{MTLStoreActionMultisampleResolve,MTLStoreActionStoreAndMultisampleResolve}) {
   auto p=pass(source,destination);p.colorAttachments[0].storeAction=store;
   id<MTLCommandBuffer> cb=[queue commandBuffer];CHECK(cb);
   id<MTLRenderCommandEncoder> encoder=[cb renderCommandEncoderWithDescriptor:p];CHECK(encoder);
   [encoder endEncoding];[cb commit];[cb waitUntilCompleted];CHECK(cb.status==MTLCommandBufferStatusCompleted);
   if(pixels) {
    unsigned char data[8*8*4]={};
    [destination getBytes:data bytesPerRow:32 fromRegion:MTLRegionMake2D(0,0,8,8) mipmapLevel:0];
    for(unsigned i=0;i<64;++i)CHECK(data[4*i]==255 && data[4*i+1]==0 && data[4*i+2]==0 && data[4*i+3]==255);
   }
  }
  // A nonzero mip and slice must survive the ABI as well. Level 1 of this
  // array destination is the same 8x8 size as the multisample source.
  auto arrayDescriptor=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:16 height:16 mipmapped:YES];
  arrayDescriptor.textureType=MTLTextureType2DArray;arrayDescriptor.arrayLength=2;
  arrayDescriptor.storageMode=MTLStorageModeShared;arrayDescriptor.usage=MTLTextureUsageRenderTarget;
  id<MTLTexture> array=[device newTextureWithDescriptor:arrayDescriptor];CHECK(array);
  auto p=pass(source,array);p.colorAttachments[0].resolveLevel=1;p.colorAttachments[0].resolveSlice=1;
  id<MTLCommandBuffer> cb=[queue commandBuffer];CHECK(cb);
  id<MTLRenderCommandEncoder> encoder=[cb renderCommandEncoderWithDescriptor:p];CHECK(encoder);
  [encoder endEncoding];[cb commit];[cb waitUntilCompleted];CHECK(cb.status==MTLCommandBufferStatusCompleted);
  if(pixels) {
   unsigned char data[8*8*4]={};
   [array getBytes:data bytesPerRow:32 bytesPerImage:256 fromRegion:MTLRegionMake2D(0,0,8,8) mipmapLevel:1 slice:1];
   for(unsigned i=0;i<64;++i)CHECK(data[4*i]==255 && data[4*i+1]==0 && data[4*i+2]==0 && data[4*i+3]==255);
  }
  puts(pixels?"PASS: frontend four-sample resolve produced all 64 red pixels for both store actions":"PASS: frontend resolve destination and subresources reach runtime validation; valid four-sample passes complete; software peer provides no pixel proof");
 }
}

// SPDX-License-Identifier: MIT
// Actual frontend and runtime creation over the software kernel peer. No pixels.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurfaceRef.h>
#include <cstdio>
#include "NativeBridgeMetalFrontend.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv) {
 if(argc!=3)return 2;
 @autoreleasepool {
  id<MTLDevice> device=native_bridge_metal_open(argv[1],argv[2],0x7a657461,nullptr);CHECK(device);
  NSDictionary *first=@{(id)kIOSurfacePlaneWidth:@16,(id)kIOSurfacePlaneHeight:@16,
   (id)kIOSurfacePlaneBytesPerElement:@1,(id)kIOSurfacePlaneBytesPerRow:@64,
   (id)kIOSurfacePlaneOffset:@0,(id)kIOSurfacePlaneSize:@1024};
  NSDictionary *second=@{(id)kIOSurfacePlaneWidth:@16,(id)kIOSurfacePlaneHeight:@16,
   (id)kIOSurfacePlaneBytesPerElement:@2,(id)kIOSurfacePlaneBytesPerRow:@64,
   (id)kIOSurfacePlaneOffset:@4096,(id)kIOSurfacePlaneSize:@1024};
  IOSurfaceRef surface=IOSurfaceCreate((__bridge CFDictionaryRef)@{
   (id)kIOSurfaceWidth:@16,(id)kIOSurfaceHeight:@16,(id)kIOSurfaceAllocSize:@8192,
   (id)kIOSurfacePixelFormat:@((uint32_t)0x5f524234),(id)kIOSurfacePlaneInfo:@[first,second]});
  CHECK(surface && IOSurfaceGetPlaneCount(surface)==2);
  auto descriptor=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:(MTLPixelFormat)542 width:16 height:16 mipmapped:NO];
  descriptor.storageMode=MTLStorageModeShared;descriptor.usage=MTLTextureUsageShaderRead;
  id<MTLTexture> rgb=[device newTextureWithDescriptor:descriptor iosurface:surface plane:0];
  CHECK(rgb && rgb.iosurface==surface && rgb.width==16 && rgb.height==16);
  descriptor.pixelFormat=MTLPixelFormatRG8Unorm;
  id<MTLTexture> chroma=[device newTextureWithDescriptor:descriptor iosurface:surface plane:1];
  CHECK(chroma && chroma.iosurface==surface);
  CHECK(![device newTextureWithDescriptor:descriptor iosurface:surface plane:2]);
  CHECK(![device newTextureWithDescriptor:descriptor iosurface:nullptr plane:0]);
  CFRelease(surface);
  puts("PASS: production two-plane RGB/plane-view creation and invalid-plane refusal over software peer; no shader or pixel proof");
 }
}

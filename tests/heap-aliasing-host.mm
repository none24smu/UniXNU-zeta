// SPDX-License-Identifier: MIT
// Exercises the shipping Objective-C frontend and Rust bridge over Turnip's
// software kernel peer. Checks heap ownership/reuse, not rendered pixels.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "NativeBridgeMetalFrontend.h"
#define CHECK(x) do { if(!(x)) { std::fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1; } } while(0)
int main(int argc,char **argv) {
 if(argc!=3)return 2;
 @autoreleasepool {
  id<MTLDevice> device=native_bridge_metal_open(argv[1],argv[2],0x7a657461,nullptr);
  CHECK(device);
  // A full automatic heap must reuse a still-retained buffer after makeAliasable.
  MTLHeapDescriptor *hd=[MTLHeapDescriptor new];hd.size=16384;hd.storageMode=MTLStorageModeShared;
  id<MTLHeap> heap=[device newHeapWithDescriptor:hd];CHECK(heap);
  id<MTLBuffer> first=[heap newBufferWithLength:8192 options:MTLResourceStorageModeShared];
  id<MTLBuffer> second=[heap newBufferWithLength:8192 options:MTLResourceStorageModeShared];
  CHECK(first && second && heap.usedSize==16384 && !first.isAliasable);
  CHECK(![heap newBufferWithLength:8192 options:MTLResourceStorageModeShared]);
  void *address=first.contents;std::memset(address,0x3a,8192);
  [first makeAliasable];[first makeAliasable];
  CHECK(first.isAliasable && heap.usedSize==8192);
  id<MTLBuffer> replacement=[heap newBufferWithLength:8192 options:MTLResourceStorageModeShared];
  CHECK(replacement && replacement.contents==address && replacement.heap==heap && !replacement.isAliasable);
  CHECK(((unsigned char *)replacement.contents)[0]==0x3a && heap.usedSize==16384);
  first=nil;CHECK(heap.usedSize==16384); // destruction must not release the replacement's range
  second=nil;replacement=nil;CHECK(heap.usedSize==0);
  id<MTLBuffer> outside=[device newBufferWithLength:4096 options:MTLResourceStorageModeShared];
  CHECK(outside && !outside.isAliasable);[outside makeAliasable];CHECK(!outside.isAliasable);
  outside=nil;heap=nil;
  // Placement heaps start aliasable and expose the actual requested offset.
  hd.type=MTLHeapTypePlacement;hd.size=32768;
  heap=[device newHeapWithDescriptor:hd];CHECK(heap);
  first=[heap newBufferWithLength:4096 options:MTLResourceStorageModeShared offset:4096];
  CHECK(first && first.isAliasable && first.heapOffset==4096 && first.heap==heap);
  [first makeAliasable];CHECK(first.isAliasable);first=nil;heap=nil;
  // Retained texture views must share aliasability and return the same heap.
  MTLTextureDescriptor *td=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:64 height:64 mipmapped:NO];
  td.storageMode=MTLStorageModePrivate;
  td.usage=MTLTextureUsageShaderRead|MTLTextureUsageShaderWrite|MTLTextureUsageRenderTarget|MTLTextureUsagePixelFormatView;
  MTLSizeAndAlign need=[device heapTextureSizeAndAlignWithDescriptor:td];CHECK(need.size && need.align);
  hd.type=MTLHeapTypeAutomatic;hd.storageMode=MTLStorageModePrivate;hd.size=2*((need.size+need.align-1)/need.align*need.align);
  heap=[device newHeapWithDescriptor:hd];CHECK(heap);
  NSMutableArray<id<MTLTexture>> *held=[NSMutableArray array];
  bool full=false;
  for(unsigned i=0;i<64;++i) {
   id<MTLTexture> t=[heap newTextureWithDescriptor:td];
   if(!t){full=true;break;}[held addObject:t];
  }
  CHECK(full && held.count>=2);
  id<MTLTexture> original=held[0];
  id<MTLTexture> view=[original newTextureViewWithPixelFormat:td.pixelFormat];
  CHECK(view && view.heap==heap && !view.isAliasable);
  const NSUInteger before=heap.usedSize;
  [view makeAliasable];[view makeAliasable];
  CHECK(view.isAliasable && original.isAliasable && heap.usedSize<before);
  id<MTLTexture> reused=[heap newTextureWithDescriptor:td];CHECK(reused && !reused.isAliasable && heap.usedSize==before);
  [held removeObjectAtIndex:0];original=nil;view=nil;CHECK(heap.usedSize==before);
  for(unsigned i=0;i<32;++i) {
   [reused makeAliasable];
   id<MTLTexture> next=[heap newTextureWithDescriptor:td];CHECK(next && heap.usedSize==before);
   reused=nil;CHECK(heap.usedSize==before);reused=next;
  }
  reused=nil;[held removeAllObjects];CHECK(heap.usedSize==0);
  std::puts("PASS: frontend heap buffer/texture/view aliasing, retained-owner reuse, repeated release, placement offsets and non-heap controls; no pixel proof");
 }
 return 0;
}

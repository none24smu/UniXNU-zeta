// SPDX-License-Identifier: MIT
// Real Objective-C frontend -> C ABI -> runtime -> AIR compiler -> Vulkan.
// The Turnip host peer retires commands without executing shaders. Optional
// --pixels is for an executing Vulkan backend and verifies every output texel.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <cstdio>
#include <cstring>
#include "NativeBridgeMetalFrontend.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static id<MTLLibrary> library(NSString *path) {
 NSData *data=[NSData dataWithContentsOfFile:path];
 return data?native_bridge_metal_library_with_air(data.bytes,data.length):nil;
}
static bool missing(id<MTLDevice> device,MTLRenderPipelineDescriptor *d,NSString *symbol) {
 NSError *error=nil;id<MTLRenderPipelineState> state=[device newRenderPipelineStateWithDescriptor:d error:&error];
 if(state || ![error.localizedDescription containsString:@"LinkedFunction"] || ![error.localizedDescription containsString:symbol]) {
  fprintf(stderr,"unexpected missing-link result: %s\n",error.localizedDescription.UTF8String);return false;
 }
 return true;
}
int main(int argc,char **argv) {
 if(argc!=5 && argc!=6)return 2;
 @autoreleasepool {
  const bool pixels=argc==6 && !strcmp(argv[5],"--pixels");
  id<MTLDevice> device=native_bridge_metal_open(argv[1],argv[2],0x7a657461,nullptr);CHECK(device);
  id<MTLLibrary> caller=library(@(argv[3])),functions=library(@(argv[4]));CHECK(caller && functions);
  auto d=[MTLRenderPipelineDescriptor new];d.label=@"linked-render-regression";
  d.vertexFunction=[caller newFunctionWithName:@"linked_vertex"];d.fragmentFunction=[caller newFunctionWithName:@"linked_fragment"];
  d.colorAttachments[0].pixelFormat=MTLPixelFormatRGBA8Unorm;CHECK(d.vertexFunction && d.fragmentFunction);
  CHECK(missing(device,d,@"vertex_gain"));
  auto values=[MTLFunctionConstantValues new];bool enabled=true;[values setConstantValue:&enabled type:MTLDataTypeBool atIndex:0];
  NSError *error=nil;
  id<MTLFunction> vertex=[functions newFunctionWithName:@"vertex_gain" constantValues:values error:&error];CHECK(vertex);
  id<MTLFunction> fragment=[functions newFunctionWithName:@"fragment_gain" constantValues:values error:&error];CHECK(fragment);
  d.vertexLinkedFunctions.functions=@[vertex];CHECK(missing(device,d,@"fragment_gain"));
  d.fragmentLinkedFunctions.functions=@[fragment];
  id<MTLRenderPipelineState> state=[device newRenderPipelineStateWithDescriptor:d error:&error];
  if(!state)fprintf(stderr,"linked pipeline must compile: %s\n",error.localizedDescription.UTF8String);
  CHECK(state);CHECK(!error);
  // Private functions follow the same resolution path, without table exports.
  d.vertexLinkedFunctions.functions=nil;d.vertexLinkedFunctions.privateFunctions=@[vertex];
  d.fragmentLinkedFunctions.functions=nil;d.fragmentLinkedFunctions.privateFunctions=@[fragment];
  id<MTLFunction> unused=[functions newFunctionWithName:@"unused_gain"];CHECK(unused);
  d.fragmentLinkedFunctions.groups=@{@"unused_call_site":@[unused]};
  CHECK([device newRenderPipelineStateWithDescriptor:d error:&error]);CHECK(!error);
  auto archive=[device newBinaryArchiveWithDescriptor:[MTLBinaryArchiveDescriptor new] error:&error];CHECK(archive);
  CHECK([archive addRenderPipelineFunctionsWithDescriptor:d error:&error]);CHECK(!error);
  // Dropping specialization would take the absent-symbol branch in either stage.
  d.fragmentLinkedFunctions.privateFunctions=@[[functions newFunctionWithName:@"fragment_gain"]];
  CHECK(missing(device,d,@"absent"));d.fragmentLinkedFunctions.privateFunctions=@[fragment];
  d.vertexLinkedFunctions.privateFunctions=@[[functions newFunctionWithName:@"vertex_gain"]];
  CHECK(missing(device,d,@"absent"));d.vertexLinkedFunctions.privateFunctions=@[vertex];
  // Merely placing an ordinary function in binaryFunctions must not invent the
  // compile-to-binary flag: runtime validation still owns that refusal.
  d.fragmentLinkedFunctions.privateFunctions=nil;d.fragmentLinkedFunctions.binaryFunctions=@[fragment];
  CHECK(![device newRenderPipelineStateWithDescriptor:d error:&error]);CHECK(error);
  d.fragmentLinkedFunctions.binaryFunctions=nil;d.fragmentLinkedFunctions.privateFunctions=@[fragment];
  auto td=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:8 height:8 mipmapped:NO];
  td.storageMode=MTLStorageModeShared;td.usage=MTLTextureUsageRenderTarget;
  id<MTLTexture> target=[device newTextureWithDescriptor:td];CHECK(target);
  auto pass=[MTLRenderPassDescriptor renderPassDescriptor];pass.colorAttachments[0].texture=target;
  pass.colorAttachments[0].loadAction=MTLLoadActionClear;pass.colorAttachments[0].storeAction=MTLStoreActionStore;
  pass.colorAttachments[0].clearColor=MTLClearColorMake(1,0,0,1);
  id<MTLCommandQueue> queue=[device newCommandQueue];id<MTLCommandBuffer> cb=[queue commandBuffer];
  id<MTLRenderCommandEncoder> encoder=[cb renderCommandEncoderWithDescriptor:pass];CHECK(encoder);
  const float positions[3][2]={{-1,-1},{3,-1},{-1,3}};
  [encoder setRenderPipelineState:state];[encoder setVertexBytes:positions length:sizeof positions atIndex:0];
  [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];[encoder endEncoding];
  [cb commit];[cb waitUntilCompleted];CHECK(cb.status==MTLCommandBufferStatusCompleted);
  if(pixels) {
   unsigned char bytes[8*8*4]={};[target getBytes:bytes bytesPerRow:32 fromRegion:MTLRegionMake2D(0,0,8,8) mipmapLevel:0];
   for(unsigned i=0;i<64;++i)CHECK(bytes[i*4]==0 && bytes[i*4+1]>=127 && bytes[i*4+1]<=128 && bytes[i*4+2]==0 && bytes[i*4+3]==255);
   puts("PASS: executing Vulkan backend produced all 64 expected linked-function pixels");
  }
  puts("PASS: render linked functions cross the real frontend/C ABI: two stages, private functions, groups, constants, archive population, binary validation and command completion; host peer alone does not verify pixels");
 }
}

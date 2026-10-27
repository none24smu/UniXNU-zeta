// SPDX-License-Identifier: MIT
// Owned actual MTL frontend -> checked external provider -> Vulkan -> readback.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "duo_metal/probe_support.hpp"
#include "NativeMetalObjects.h"
#include "duo_external_owned_inputs.h"
#ifndef NMB_HOST_ORACLE
#define NMB_HOST_ORACLE 0
#endif
static void emit(NSDictionary *fields) {
 NSMutableDictionary *record=[fields mutableCopy];record[@"probe"]=@"duo_air_frontend";
 NSData *data=[NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingSortedKeys error:nullptr];
 std::cout.write((const char *)data.bytes,data.length);std::cout<<'\n'<<std::flush;
}
template<class T>static T symbol(void *library,const char *name) {
 auto value=reinterpret_cast<T>(dlsym(library,name));if(!value)throw std::runtime_error(std::string("missing symbol ")+name);return value;
}
static std::string policy(const char *driverPath) {
 void *library=dlopen(driverPath,RTLD_NOW|RTLD_LOCAL);if(!library)throw std::runtime_error("driver dlopen failed");
 auto get=symbol<PFN_vkGetInstanceProcAddr>(library,"vkGetInstanceProcAddr");
 auto create=reinterpret_cast<PFN_vkCreateInstance>(get(VK_NULL_HANDLE,"vkCreateInstance"));
 VkApplicationInfo app{};app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;app.apiVersion=VK_API_VERSION_1_2;
 VkInstanceCreateInfo info{};info.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;info.pApplicationInfo=&app;
 VkInstance instance=VK_NULL_HANDLE;if(create(&info,nullptr,&instance)!=VK_SUCCESS)throw std::runtime_error("policy instance creation failed");
 auto enumerate=reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(get(instance,"vkEnumeratePhysicalDevices"));
 auto properties=reinterpret_cast<PFN_vkGetPhysicalDeviceProperties2>(get(instance,"vkGetPhysicalDeviceProperties2"));
 auto destroy=reinterpret_cast<PFN_vkDestroyInstance>(get(instance,"vkDestroyInstance"));
 uint32_t count=0;if(enumerate(instance,&count,nullptr)!=VK_SUCCESS || count!=1)throw std::runtime_error("policy requires exactly one physical device");
 VkPhysicalDevice physical=VK_NULL_HANDLE;if(enumerate(instance,&count,&physical)!=VK_SUCCESS || count!=1)throw std::runtime_error("policy enumeration changed");
 VkPhysicalDeviceDriverProperties driver{};driver.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES;
 VkPhysicalDeviceProperties2 p{};p.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;p.pNext=&driver;properties(physical,&p);
#if NMB_HOST_ORACLE
 const std::string refusal=driver.driverID==VK_DRIVER_ID_MOLTENVK?"":"host oracle requires MoltenVK";
#else
 const auto refusal=duo::metal::probe::rejection(p.properties,driver);
#endif
 emit(@{@"event":@"device_policy",@"name":@(p.properties.deviceName),@"driver":@(driver.driverName),@"vendor_id":@(p.properties.vendorID),@"device_id":@(p.properties.deviceID),@"driver_id":@(driver.driverID),@"host_oracle":@(bool(NMB_HOST_ORACLE)),@"accepted":@(refusal.empty())});
 const std::string name=p.properties.deviceName;destroy(instance,nullptr);dlclose(library);
 if(!refusal.empty())throw std::runtime_error(refusal);return name;
}
static void deadline(int) {static const char message[]="{\"probe\":\"duo_air_frontend\",\"event\":\"deadline\",\"passed\":false}\n";write(STDOUT_FILENO,message,sizeof(message)-1);_Exit(124);}
int main(int argc,char **argv) {
 signal(SIGALRM,deadline);alarm(20);
 @autoreleasepool { @try { try {
 const char *candidate=nullptr,*driver=nullptr;
 if(argc==3){candidate=argv[1];driver=argv[2];}
 else if(argc==5 && !std::strcmp(argv[1],"--backend") && !std::strcmp(argv[2],"/private/var/ngpu/addons/duo-air-probe/libduoair.dylib") && !std::strcmp(argv[3],"--library") && !std::strcmp(argv[4],"/private/var/ngpu/addons/duo-air-probe/duo-air-probe.metallib")) {
 candidate="/private/var/ngpu/addons/duo-air-probe/libduoexternalmetal.dylib";driver="/private/var/ngpu/addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib";
 } else throw std::runtime_error("usage: candidate-dylib vulkan-driver, or exact fixed g launcher arguments");
 emit(@{@"event":@"start",@"host_oracle":@(bool(NMB_HOST_ORACLE)),@"system_replacement":@NO});
 const auto physical=policy(driver);
 void *library=dlopen(candidate,RTLD_NOW|RTLD_LOCAL);if(!library)throw std::runtime_error(dlerror());
 auto open=symbol<id(*)(const char *,const char *,uint64_t,void(*)(const char *,const char *))>(library,"native_bridge_metal_open");
 auto air=symbol<id(*)(const void *,size_t)>(library,"native_bridge_metal_library_with_air");
 auto install=symbol<bool(*)(const NmbExternalStage *,size_t)>(library,"native_bridge_metal_register_external_stages");
 auto stats=symbol<bool(*)(uint64_t *)>(library,"native_bridge_metal_external_stats");
 const std::string cache=std::string(NSTemporaryDirectory().UTF8String)+"duo-external-stage-"+std::to_string(getpid());
 id<MTLDevice> device=open(driver,cache.c_str(),0x64756f657874,nullptr);
 if(!device)throw std::runtime_error("candidate Metal device creation refused");
 if(physical!=device.name.UTF8String)throw std::runtime_error("MTL device differs from policy-selected physical device");
 if(!install(duo_external_stages,2))throw std::runtime_error("external stage registration refused");
 id<MTLLibrary> vl=air(duo_external_vertex_air,sizeof(duo_external_vertex_air));
 id<MTLLibrary> fl=air(duo_external_fragment_air,sizeof(duo_external_fragment_air));
 if(!vl || !fl)throw std::runtime_error("owned AIR library refused");
 MTLRenderPipelineDescriptor *d=[MTLRenderPipelineDescriptor new];
 d.vertexFunction=[vl newFunctionWithName:@"duo_triangle_vertex"];d.fragmentFunction=[fl newFunctionWithName:@"duo_solid_fragment"];
 d.colorAttachments[0].pixelFormat=MTLPixelFormatRGBA8Unorm;d.inputPrimitiveTopology=MTLPrimitiveTopologyClassTriangle;
 if(!d.vertexFunction || !d.fragmentFunction)throw std::runtime_error("owned AIR function lookup refused");
 NSError *error=nil;d.colorAttachments[0].writeMask=MTLColorWriteMaskRed;
 if([device newRenderPipelineStateWithDescriptor:d error:&error])throw std::runtime_error("unsupported write mask unexpectedly accepted");
 emit(@{@"event":@"negative_render_contract",@"refused":@YES});
 d.colorAttachments[0].writeMask=MTLColorWriteMaskAll;error=nil;
 id<MTLRenderPipelineState> pipeline=[device newRenderPipelineStateWithDescriptor:d error:&error];
 if(!pipeline)throw std::runtime_error(std::string("owned MTL pipeline refused: ")+(error ? error.localizedDescription.UTF8String : "unknown"));
 emit(@{@"event":@"pipeline_created"});
 MTLTextureDescriptor *td=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:32 height:32 mipmapped:NO];
 td.usage=MTLTextureUsageRenderTarget;td.storageMode=MTLStorageModePrivate;
 id<MTLTexture> texture=[device newTextureWithDescriptor:td];
 id<MTLBuffer> readback=[device newBufferWithLength:256*32 options:MTLResourceStorageModeShared];
 if(!texture || !readback || !readback.contents)throw std::runtime_error("owned target/readback allocation failed");
 std::memset(readback.contents,0x5a,256*32);
 MTLRenderPassDescriptor *pass=[MTLRenderPassDescriptor renderPassDescriptor];pass.colorAttachments[0].texture=texture;
 pass.colorAttachments[0].loadAction=MTLLoadActionClear;pass.colorAttachments[0].storeAction=MTLStoreActionStore;
 pass.colorAttachments[0].clearColor=MTLClearColorMake(0,0,0,0);
 id<MTLCommandQueue> queue=[device newCommandQueue];id<MTLCommandBuffer> command=[queue commandBuffer];
 id<MTLRenderCommandEncoder> encoder=[command renderCommandEncoderWithDescriptor:pass];
 [encoder setRenderPipelineState:pipeline];[encoder setCullMode:MTLCullModeNone];[encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];[encoder endEncoding];
 id<MTLBlitCommandEncoder> blit=[command blitCommandEncoder];
 [blit copyFromTexture:texture sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0,0,0) sourceSize:MTLSizeMake(32,32,1) toBuffer:readback destinationOffset:0 destinationBytesPerRow:256 destinationBytesPerImage:256*32];[blit endEncoding];
 emit(@{@"event":@"commit"});[command commit];[command waitUntilCompleted];
 if(command.status!=MTLCommandBufferStatusCompleted)throw std::runtime_error(std::string("MTL completion failed: ")+(command.error ? command.error.localizedDescription.UTF8String : "unknown"));
 const uint8_t expected[4]={64,128,32,64};const auto bytes=(const uint8_t *)readback.contents;size_t mismatches=0,padding=0;
 for(size_t y=0;y<32;y++){for(size_t x=0;x<128;x++)mismatches+=bytes[y*256+x]!=expected[x%4];for(size_t x=128;x<256;x++)padding+=bytes[y*256+x]!=0x5a;}
 uint64_t counts[8]={};if(!stats(counts))throw std::runtime_error("provider telemetry failed");
 const bool counters=counts[0]==1 && counts[1]==2 && counts[2]==1 && counts[4]==1 && counts[5]==1 && (NMB_HOST_ORACLE || counts[3]==1);
 const bool passed=!mismatches && !padding && counters;
 emit(@{@"event":@"readback",@"draws":@1,@"components":@4096,@"mismatches":@(mismatches),@"padding_mismatches":@(padding),@"registered":@(counts[0]),@"requests":@(counts[1]),@"imported_pairs":@(counts[2]),@"constant_folds":@(counts[3]),@"refusals":@(counts[4]),@"pipeline_objects":@(counts[5]),@"passed":@(passed),@"ui_frame_rate_proven":@NO});
 alarm(0);return passed?0:1;
 }catch(const std::exception& e){emit(@{@"event":@"error",@"message":@(e.what()),@"passed":@NO});return 1;}
 }@catch(NSException *e){emit(@{@"event":@"exception",@"message":e.reason ? e.reason : @"unknown",@"passed":@NO});return 1;} }
}

// SPDX-License-Identifier: MIT
// Reuse the proven bounded pass/readback owners without changing their artifact.
#ifndef DUO_EXISTING_VULKAN_PROBE
#define DUO_EXISTING_VULKAN_PROBE "../probe.cpp"
#endif
#define main duoExistingClearProbeMain
#include DUO_EXISTING_VULKAN_PROBE
#undef main
#include "../fixtures/duo_air_spirv_owned.h"
namespace {
void bridgeEvent(const std::string& fields) {
    std::cout << "{\"probe\":\"duo_air_spirv\"," << fields << "}\n" << std::flush;
}
struct PipelineOwner {
    std::shared_ptr<Runtime> runtime;
    VkShaderModule vertex=VK_NULL_HANDLE,fragment=VK_NULL_HANDLE;
    VkPipelineLayout layout=VK_NULL_HANDLE;
    VkPipeline pipeline=VK_NULL_HANDLE;
    PFN_vkDestroyShaderModule destroyModule=nullptr;
    PFN_vkDestroyPipelineLayout destroyLayout=nullptr;
    PFN_vkDestroyPipeline destroyPipeline=nullptr;
    ~PipelineOwner() {
        if(pipeline)destroyPipeline(runtime->device,pipeline,nullptr);
        if(layout)destroyLayout(runtime->device,layout,nullptr);
        if(vertex)destroyModule(runtime->device,vertex,nullptr);
        if(fragment)destroyModule(runtime->device,fragment,nullptr);
    }
};
struct GraphicsDispatch {
    PFN_vkCreateShaderModule createShader=nullptr;
    PFN_vkCreatePipelineLayout createLayout=nullptr;
    PFN_vkCreateGraphicsPipelines createGraphics=nullptr;
    PFN_vkCmdBindPipeline bind=nullptr;
    PFN_vkCmdDraw draw=nullptr;
};
std::shared_ptr<PipelineOwner> pipeline(const std::shared_ptr<Runtime>& r,VkRenderPass pass,bool blend,GraphicsDispatch& f) {
    auto owner=std::make_shared<PipelineOwner>();owner->runtime=r;
    auto get=reinterpret_cast<PFN_vkGetInstanceProcAddr>(dlsym(r->library,"vkGetInstanceProcAddr"));
    if(!get)get=reinterpret_cast<PFN_vkGetInstanceProcAddr>(dlsym(r->library,"vk_icdGetInstanceProcAddr"));
    auto deviceProc=instanceFunction<PFN_vkGetDeviceProcAddr>(get,r->instance,"vkGetDeviceProcAddr");
#define LOAD(target,type,name) target=reinterpret_cast<type>(deviceProc(r->device,name)); if(!target)throw std::runtime_error("missing " name)
    LOAD(f.createShader,PFN_vkCreateShaderModule,"vkCreateShaderModule");
    LOAD(f.createLayout,PFN_vkCreatePipelineLayout,"vkCreatePipelineLayout");
    LOAD(f.createGraphics,PFN_vkCreateGraphicsPipelines,"vkCreateGraphicsPipelines");
    LOAD(f.bind,PFN_vkCmdBindPipeline,"vkCmdBindPipeline");LOAD(f.draw,PFN_vkCmdDraw,"vkCmdDraw");
    LOAD(owner->destroyModule,PFN_vkDestroyShaderModule,"vkDestroyShaderModule");
    LOAD(owner->destroyLayout,PFN_vkDestroyPipelineLayout,"vkDestroyPipelineLayout");
    LOAD(owner->destroyPipeline,PFN_vkDestroyPipeline,"vkDestroyPipeline");
#undef LOAD
    VkShaderModuleCreateInfo module{};module.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    module.codeSize=sizeof(duo_air_spirv_triangle);module.pCode=duo_air_spirv_triangle;
    require(f.createShader(r->device,&module,nullptr,&owner->vertex),"create_air_spirv_vertex");
    module.codeSize=sizeof(duo_air_spirv_solid);module.pCode=duo_air_spirv_solid;
    require(f.createShader(r->device,&module,nullptr,&owner->fragment),"create_air_spirv_fragment");
    VkPipelineLayoutCreateInfo layout{};layout.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    require(f.createLayout(r->device,&layout,nullptr,&owner->layout),"create_empty_pipeline_layout");
    VkPipelineShaderStageCreateInfo stages[2]{};
    for(auto& s:stages){s.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;s.pName="main";}
    stages[0].stage=VK_SHADER_STAGE_VERTEX_BIT;stages[0].module=owner->vertex;
    stages[1].stage=VK_SHADER_STAGE_FRAGMENT_BIT;stages[1].module=owner->fragment;
    VkPipelineVertexInputStateCreateInfo vertex{};vertex.sType=VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    VkPipelineInputAssemblyStateCreateInfo input{};input.sType=VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;input.topology=VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkViewport viewport{0,0,float(extent),float(extent),0,1};VkRect2D scissor{{0,0},{extent,extent}};
    VkPipelineViewportStateCreateInfo view{};view.sType=VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;view.viewportCount=view.scissorCount=1;view.pViewports=&viewport;view.pScissors=&scissor;
    VkPipelineRasterizationStateCreateInfo raster{};raster.sType=VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;raster.polygonMode=VK_POLYGON_MODE_FILL;raster.cullMode=VK_CULL_MODE_NONE;raster.frontFace=VK_FRONT_FACE_COUNTER_CLOCKWISE;raster.lineWidth=1;
    VkPipelineMultisampleStateCreateInfo sample{};sample.sType=VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;sample.rasterizationSamples=VK_SAMPLE_COUNT_1_BIT;
    VkPipelineColorBlendAttachmentState attachment{};attachment.blendEnable=blend;attachment.colorWriteMask=0xf;
    attachment.srcColorBlendFactor=attachment.srcAlphaBlendFactor=VK_BLEND_FACTOR_ONE;
    attachment.dstColorBlendFactor=attachment.dstAlphaBlendFactor=VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    attachment.colorBlendOp=attachment.alphaBlendOp=VK_BLEND_OP_ADD;
    VkPipelineColorBlendStateCreateInfo color{};color.sType=VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;color.attachmentCount=1;color.pAttachments=&attachment;
    VkGraphicsPipelineCreateInfo create{};create.sType=VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;create.stageCount=2;create.pStages=stages;
    create.pVertexInputState=&vertex;create.pInputAssemblyState=&input;create.pViewportState=&view;create.pRasterizationState=&raster;
    create.pMultisampleState=&sample;create.pColorBlendState=&color;create.layout=owner->layout;create.renderPass=pass;
    require(f.createGraphics(r->device,VK_NULL_HANDLE,1,&create,nullptr,&owner->pipeline),"create_air_spirv_graphics_pipeline");return owner;
}
bool draw(const std::shared_ptr<Runtime>& r,bool blend) {
    const auto started=micros();auto image=allocateImage(r,1,false,true);auto readback=allocateReadback(r);auto binding=makeImageBinding(image,1);auto device=encoderDevice(r);
    PassDescriptor descriptor;Attachment attachment;attachment.source.image=binding.image;attachment.load=LoadAction::Clear;
    if(blend)attachment.clearColor={0.125,0.25,0.5,0.5};descriptor.colors[0]=attachment;
    auto plan=planRenderPass(descriptor,device->capabilities.attachments);if(!plan)throw std::runtime_error(plan.error);
    VulkanImageState before{VK_IMAGE_LAYOUT_UNDEFINED,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,0,r->queueFamily};
    VulkanImageState after{VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_ACCESS_TRANSFER_READ_BIT,r->queueFamily};
    auto encoded=encodeVulkanPass(*plan.plan,device,{binding},{{1,0,0,before,after}});if(!encoded)throw std::runtime_error(encoded.error);
    GraphicsDispatch graphics;auto shader=pipeline(r,encoded.pass->renderPass(),blend,graphics);const auto compiled=micros();
    auto commands=std::make_shared<CommandOwner>();commands->runtime=r;
    VkCommandPoolCreateInfo pool{};pool.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;pool.queueFamilyIndex=r->queueFamily;pool.flags=VK_COMMAND_POOL_CREATE_TRANSIENT_BIT;
    require(r->vkCreateCommandPool(r->device,&pool,nullptr,&commands->pool),"create_spirv_command_pool");
    VkCommandBufferAllocateInfo allocate{};allocate.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;allocate.commandPool=commands->pool;allocate.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;allocate.commandBufferCount=1;
    VkCommandBuffer command=VK_NULL_HANDLE;require(r->vkAllocateCommandBuffers(r->device,&allocate,&command),"allocate_spirv_command");
    VkCommandBufferBeginInfo begin{};begin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;begin.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    require(r->vkBeginCommandBuffer(command,&begin),"begin_spirv_command");
    VkBufferMemoryBarrier host{};host.sType=VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;host.srcAccessMask=VK_ACCESS_HOST_WRITE_BIT;host.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;host.srcQueueFamilyIndex=host.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;host.buffer=readback->buffer;host.size=VK_WHOLE_SIZE;
    r->vkCmdPipelineBarrier(command,VK_PIPELINE_STAGE_HOST_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,nullptr,1,&host,0,nullptr);
    requireEmpty(encoded.pass->begin(command),"begin_spirv_pass");graphics.bind(command,VK_PIPELINE_BIND_POINT_GRAPHICS,shader->pipeline);graphics.draw(command,3,1,0,0);requireEmpty(encoded.pass->end(command),"end_spirv_pass");
    VkBufferImageCopy region{};region.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1};region.imageExtent={extent,extent,1};
    r->vkCmdCopyImageToBuffer(command,image->image,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,readback->buffer,1,&region);
    host.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;host.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
    r->vkCmdPipelineBarrier(command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_HOST_BIT,0,0,nullptr,1,&host,0,nullptr);
    require(r->vkEndCommandBuffer(command),"end_spirv_command");auto fence=std::make_shared<FenceOwner>();fence->runtime=r;
    VkFenceCreateInfo fenceInfo{};fenceInfo.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;require(r->vkCreateFence(r->device,&fenceInfo,nullptr,&fence->fence),"create_spirv_fence");
    VulkanCompletionQueue completion(device);requireEmpty(completion.prepareSubmission(encoded.pass,fence->fence,fence),"prepare_spirv_submit");
    VkSubmitInfo submit{};submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;submit.commandBufferCount=1;submit.pCommandBuffers=&command;
    auto result=r->vkQueueSubmit(r->queue,1,&submit,fence->fence);if(result!=VK_SUCCESS)pendingFailure("spirv_submit",result);
    if(!completion.confirmSubmitted(encoded.pass).empty())pendingFailure("spirv_confirm",VK_ERROR_UNKNOWN);
    result=r->vkWaitForFences(r->device,1,&fence->fence,VK_TRUE,2000000000ull);if(result!=VK_SUCCESS)pendingFailure("spirv_wait",result);
    if(completion.pollCompleted()!=VK_SUCCESS)pendingFailure("spirv_retire",VK_ERROR_UNKNOWN);const auto completed=micros();
    if(!readback->coherent){VkMappedMemoryRange range{};range.sType=VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;range.memory=readback->memory;range.size=VK_WHOLE_SIZE;require(r->vkInvalidateMappedMemoryRanges(r->device,1,&range),"spirv_readback_invalidate");}
    const std::array<uint8_t,4> expected=blend?std::array<uint8_t,4>{88,175,128,159}:std::array<uint8_t,4>{64,128,32,64};
    const auto* pixels=static_cast<const uint8_t*>(readback->mapped);size_t mismatches=0;uint64_t hash=1469598103934665603ull;
    for(size_t i=0;i<readBytes;++i){if(std::abs(int(pixels[i])-int(expected[i%4]))>1)++mismatches;hash=(hash^pixels[i])*1099511628211ull;}
    bridgeEvent("\"event\":\"test\",\"name\":"+quote(blend?"air_spirv_source_over":"air_spirv_triangle")+",\"actual_draw\":true,\"components\":4096,\"mismatches\":"+std::to_string(mismatches)+",\"tolerance\":1,\"fnv1a64\":"+quote(std::to_string(hash))+",\"pipeline_and_allocate_us\":"+std::to_string(compiled-started)+",\"submit_wait_us\":"+std::to_string(completed-compiled)+",\"status\":"+quote(mismatches?"fail":"pass"));return !mismatches;
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=3 || std::string(argv[1])!="--driver" || argv[2][0]!='/')throw std::runtime_error("usage: duo-air-spirv-probe --driver /absolute/driver");
        struct sigaction action{};action.sa_handler=alarmHandler;sigemptyset(&action.sa_mask);if(sigaction(SIGALRM,&action,nullptr))throw std::runtime_error("alarm setup");alarm(20);
#ifdef DUO_SPIRV_HOST_REFERENCE
        bridgeEvent("\"event\":\"scope\",\"host_software_oracle\":true,\"physical_gpu_proven\":false");
#else
        bridgeEvent("\"event\":\"scope\",\"software_fallback\":false,\"required_hardware\":\"A660 Turnip\"");
#endif
        auto runtime=initialize(argv[2]);const bool passed=draw(runtime,false)&&draw(runtime,true);alarm(0);
        bridgeEvent("\"event\":\"summary\",\"status\":"+quote(passed?"pass":"fail")+",\"air_to_nir_to_real_spirv\":true,\"metal_frontend_proven\":false,\"gpu_faults_checked\":false,\"ui_frame_rate_proven\":false");return passed?0:1;
    }catch(const std::exception& error){alarm(0);bridgeEvent("\"event\":\"error\",\"message\":"+quote(error.what()));return 1;}
}

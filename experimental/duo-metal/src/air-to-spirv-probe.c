/* SPDX-License-Identifier: MIT */
/* Isolated owned-fixture feasibility bridge. No Gallium/system frontend changes. */
#include "nir.h"
#include "nir_builder.h"
#include "nir_air.h"
#include "nir_to_spirv.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc,char **argv)
{
    if(argc!=3) {fprintf(stderr,"usage: air-to-spirv-probe MODULE.air OUTPUT.spv\n");return 2;}
    FILE *file=fopen(argv[1],"rb");if(!file)return 2;
    if(fseek(file,0,SEEK_END)) {fclose(file);return 2;}
    long length=ftell(file);rewind(file);
    if(length<=0 || length>1024*1024) {fclose(file);return 2;}
    void *bytes=malloc((size_t)length);if(!bytes)return 2;
    if(fread(bytes,1,(size_t)length,file)!=(size_t)length) {fclose(file);free(bytes);return 2;}
    fclose(file);glsl_type_singleton_init_or_ref();void *context=ralloc_context(NULL);
    struct air_constant_value *constants=NULL;
    if(air_module_function_constants(context,bytes,(size_t)length,&constants)) {
        fprintf(stderr,"REFUSE: function constant specialization not bridged\n");return 1;
    }
    struct air_to_nir_options options={0};
    static const nir_shader_compiler_options nir_options={.lower_fdiv=false};
    struct air_shader_info info={0};const char *error=NULL;
    nir_shader *nir=air_to_nir(context,bytes,(size_t)length,NULL,&options,&nir_options,&info,&error);
    if(!nir) {fprintf(stderr,"REFUSE: AIR: %s\n",error?error:"unknown");return 1;}
    if((info.stage!=MESA_SHADER_VERTEX && info.stage!=MESA_SHADER_FRAGMENT) ||
       info.num_resources || info.num_vertex_attributes || info.num_varyings ||
       info.fbfetch_targets || info.raster_order_groups || info.threadgroup_bytes ||
       info.num_notes || info.num_render_targets>1) {
        fprintf(stderr,"REFUSE: initial bridge requires resource-free vertex/fragment without extra interface semantics\n");return 1;
    }
    NIR_PASS_V(nir,nir_copy_prop);
    NIR_PASS_V(nir,nir_opt_dce);
    nir_shader_gather_info(nir,nir_shader_get_entrypoint(nir));
    nir_validate_shader(nir,"AIR input to isolated Zink serializer");
    NIR_PASS_V(nir,nir_convert_from_ssa,true,false);
    struct zink_screen *screen=calloc(1,sizeof(*screen));
    struct zink_shader_info sinfo={0};
    if(!screen)return 2;
    screen->spirv_version=SPIRV_VERSION(1,5);
    struct spirv_shader *spirv=nir_to_spirv(nir,&sinfo,screen);
    if(!spirv) {fprintf(stderr,"REFUSE: Zink serializer\n");return 1;}
    file=fopen(argv[2],"wb");if(!file)return 2;
    const size_t written=fwrite(spirv->words,sizeof(uint32_t),spirv->num_words,file);
    const int closed=fclose(file);
    if(written!=spirv->num_words || closed)return 2;
    fprintf(stderr,"PASS: actual AIR->NIR->Zink SPIR-V serialization, %zu words; external validation and execution still required\n",written);
    spirv_shader_delete(spirv);free(screen);ralloc_free(context);free(bytes);glsl_type_singleton_decref();return 0;
}

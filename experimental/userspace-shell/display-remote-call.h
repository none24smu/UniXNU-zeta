/* A bounded debugger call of the exact iOS27 libEDR startup in its own process.
 * No executable bytes are injected: a new Mach thread asks libpthread to create
 * a normal pthread. Its return parks at an existing RET instruction, then the
 * controller terminates only that bootstrap thread and frees its scratch stack.
 * The normal pthread owns its stack and exits normally after libEDR startup. */
static int start_edr_in_task(mach_port_t task){
 const vm_address_t create=0x180536d58ULL,entry=0x2b7ef04fcULL,park=0x180532e78ULL,queue=0x2ce9e6228ULL;
 const unsigned char create_bytes[]={0x24,0x00,0x80,0x52,0x11,0xef,0xff,0x17};
 const unsigned char entry_bytes[]={0x1f,0x20,0x03,0xd5,0xff,0x83,0x03,0xd1,0xe9,0x23,0x07,0x6d,0xfc,0x6f,0x08,0xa9,0xfa,0x67,0x09,0xa9,0xf8,0x5f,0x0a,0xa9,0xf6,0x57,0x0b,0xa9,0xf4,0x4f,0x0c,0xa9};
 unsigned char data[32];vm_size_t n=0;kern_return_t kr=vm_read_overwrite(task,create,sizeof create_bytes,(vm_address_t)data,&n);if(kr||n!=sizeof create_bytes||memcmp(data,create_bytes,n)){puts("pthread code guard failed; no call");return 1;}
 kr=vm_read_overwrite(task,entry,sizeof entry_bytes,(vm_address_t)data,&n);if(kr||n!=sizeof entry_bytes||memcmp(data,entry_bytes,n)){puts("libEDR code guard failed; no call");return 1;}
 uint32_t instruction=0;kr=vm_read_overwrite(task,park,4,(vm_address_t)&instruction,&n);if(kr||n!=4||instruction!=0xd65f03c0){puts("return park guard failed; no call");return 1;}
 uint64_t server_queue=0;kr=vm_read_overwrite(task,queue,8,(vm_address_t)&server_queue,&n);if(kr||n!=8||server_queue){printf("server startup already initialized or unreadable queue=%#llx kr=%d; no call\n",(unsigned long long)server_queue,kr);return 1;}
 vm_address_t scratch=0;const vm_size_t bytes=128*1024;kr=vm_allocate(task,&scratch,bytes,VM_FLAGS_ANYWHERE);printf("remote scratch kr=%d address=%#llx\n",kr,(unsigned long long)scratch);if(kr)return 1;
 thread_act_t bootstrap=MACH_PORT_NULL;kr=thread_create(task,&bootstrap);if(kr){vm_deallocate(task,scratch,bytes);return 1;}
 arm_thread_state64_t state={0};state.__x[0]=scratch;state.__x[2]=entry;state.__sp=(scratch+bytes-256)&~15ULL;state.__pc=create;state.__lr=park;
 kr=thread_set_state(bootstrap,ARM_THREAD_STATE64,(thread_state_t)&state,ARM_THREAD_STATE64_COUNT);if(!kr)kr=thread_resume(bootstrap);printf("remote libpthread bootstrap port=%#x resume_kr=%d\n",bootstrap,kr);int result=1,returned=0;
 if(!kr){for(unsigned attempt=0;attempt<1000;attempt++){mach_msg_type_number_t count=ARM_THREAD_STATE64_COUNT;kern_return_t sk=thread_get_state(bootstrap,ARM_THREAD_STATE64,(thread_state_t)&state,&count);if(sk){printf("bootstrap state kr=%d\n",sk);break;}if(arm_thread_state64_get_pc(state)==park){uint64_t pthread=0;n=0;kern_return_t read=vm_read_overwrite(task,scratch,8,(vm_address_t)&pthread,&n);printf("pthread_create_from_mach_thread return=%llu pthread=%#llx read_kr=%d\n",(unsigned long long)state.__x[0],(unsigned long long)pthread,read);result=state.__x[0]!=0||read||n!=8||!pthread;returned=1;break;}usleep(10000);}}
 kern_return_t stop=thread_terminate(bootstrap);printf("bootstrap cleanup terminate_kr=%d returned=%d\n",stop,returned);mach_port_deallocate(mach_task_self(),bootstrap);if(!stop){kr=vm_deallocate(task,scratch,bytes);printf("scratch free kr=%d\n",kr);}else result=1;
 server_queue=0;n=0;kr=vm_read_overwrite(task,queue,8,(vm_address_t)&server_queue,&n);printf("libEDR server queue after=%#llx read_kr=%d\n",(unsigned long long)server_queue,kr);return result;
}

/* One owner diagnostic: let identityservicesd receive the normal invalidated
 * connection error for its blocked CoreDuet request. Stock launchd jobs remain.
 * Only existing library code executes on a normal pthread; no code injection. */
static int cancel_named_service_in_task(mach_port_t task,vm_address_t connection,const char *expected){
 const vm_address_t create=0x180536d58ULL,park=0x180532e78ULL;
 const unsigned char create_bytes[]={0x24,0x00,0x80,0x52,0x11,0xef,0xff,0x17};
 unsigned char data[64];vm_size_t n=0;size_t label_bytes=strlen(expected)+1;
 if(label_bytes>sizeof data)return 1;
 kern_return_t kr=vm_read_overwrite(task,create,sizeof create_bytes,(vm_address_t)data,&n);
 if(kr||n!=sizeof create_bytes||memcmp(data,create_bytes,n)){puts("pthread code guard failed; no call");return 1;}
 vm_address_t dm=0,label=0;
 kr=vm_read_overwrite(task,connection+0xa8,8,(vm_address_t)&dm,&n);if(kr||n!=8||!dm)return 1;
 kr=vm_read_overwrite(task,dm+0x48,8,(vm_address_t)&label,&n);if(kr||n!=8||!label)return 1;
 kr=vm_read_overwrite(task,label,label_bytes,(vm_address_t)data,&n);
 if(kr||n!=label_bytes||memcmp(data,expected,n)){puts("service connection label guard failed; no call");return 1;}
 void *entry=dlsym(RTLD_DEFAULT,"xpc_connection_cancel");if(!entry)return 1;
 kr=vm_read_overwrite(task,(vm_address_t)entry,sizeof data,(vm_address_t)data,&n);
 if(kr||n!=sizeof data||memcmp(data,entry,sizeof data)){puts("libxpc code guard failed; no call");return 1;}
 uint32_t word=0;kr=vm_read_overwrite(task,park,4,(vm_address_t)&word,&n);if(kr||n!=4||word!=0xd65f03c0)return 1;
 vm_address_t scratch=0;const vm_size_t bytes=128*1024;kr=vm_allocate(task,&scratch,bytes,VM_FLAGS_ANYWHERE);if(kr)return 1;
 thread_act_t bootstrap=0;kr=thread_create(task,&bootstrap);if(kr){vm_deallocate(task,scratch,bytes);return 1;}
 arm_thread_state64_t state={0};state.__x[0]=scratch;state.__x[2]=(uint64_t)entry;state.__x[3]=connection;state.__sp=(scratch+bytes-256)&~15ULL;state.__pc=create;state.__lr=park;
 kr=thread_set_state(bootstrap,ARM_THREAD_STATE64,(thread_state_t)&state,ARM_THREAD_STATE64_COUNT);if(!kr)kr=thread_resume(bootstrap);
 printf("CoreDuet cancellation pthread bootstrap kr=%d connection=%#llx\n",kr,(unsigned long long)connection);int returned=0,result=1;
 if(!kr)for(unsigned i=0;i<500;i++){
  mach_msg_type_number_t count=ARM_THREAD_STATE64_COUNT;kr=thread_get_state(bootstrap,ARM_THREAD_STATE64,(thread_state_t)&state,&count);if(kr)break;
  if(arm_thread_state64_get_pc(state)==park){uint64_t pthread=0;kr=vm_read_overwrite(task,scratch,8,(vm_address_t)&pthread,&n);result=state.__x[0]!=0||kr||n!=8||!pthread;returned=1;printf("cancel pthread created=%d return=%llu\n",!result,(unsigned long long)state.__x[0]);break;}usleep(10000);
 }
 kr=thread_terminate(bootstrap);printf("cancel bootstrap terminated kr=%d returned=%d\n",kr,returned);
 /* Avoid explicit deallocation of the terminated bootstrap's guarded right;
  * controller exit releases it. Do not free a potentially live bootstrap stack. */
 if(!kr)vm_deallocate(task,scratch,bytes);else result=1;
 return result;
}

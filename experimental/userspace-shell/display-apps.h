/* Stock first-boot application inventory and installation through the shipped
 * LaunchServices/MobileInstallation APIs. No app binaries are rewritten. */
static void app_methods(Class cls){
 if(!cls)return;
 unsigned count=0;Method *methods=class_copyMethodList(cls,&count);
 for(unsigned i=0;i<count;i++){
  const char *name=sel_getName(method_getName(methods[i]));
  if(strstr(name,"nstall")||strstr(name,"egister")||strstr(name,"ystemApp")||strstr(name,"igration")||strstr(name,"Applications")||strstr(name,"Options"))
   printf("app API %s %s %s\n",class_getName(cls),name,method_getTypeEncoding(methods[i]));
 }
 free(methods);
}
static id app_send(id object,const char *name){return ((id(*)(id,SEL))objc_msgSend)(object,sel_registerName(name));}
static int apps_control(int argc,char **argv){
 alarm(!strcmp(argv[1],"app-install-staged")?180:20);
 const char *paths[]={"/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation","/System/Library/Frameworks/CoreServices.framework/CoreServices","/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices"};
 for(unsigned i=0;i<3;i++)dlopen(paths[i],RTLD_NOW|RTLD_LOCAL);
 Class workspace_class=objc_getClass("LSApplicationWorkspace");
 Class options_class=objc_getClass("MIInstallOptions");
 if(!workspace_class){puts("stock LaunchServices workspace unavailable");return 1;}
 if(!strcmp(argv[1],"apps-api")){
  app_methods(workspace_class);app_methods(object_getClass((id)workspace_class));app_methods(options_class);app_methods(objc_getClass("MIInstallerClient"));return 0;
 }
 id workspace=app_send((id)workspace_class,"defaultWorkspace");if(!workspace){puts("stock workspace factory returned nil");return 1;}
 if(!strcmp(argv[1],"apps-list")){
  SEL selector=sel_registerName("allInstalledApplications");
  if(!class_getInstanceMethod(workspace_class,selector)){puts("installed app enumeration API unavailable");return 1;}
  id apps=((id(*)(id,SEL))objc_msgSend)(workspace,selector);
  if(!apps){puts("installed app inventory returned nil");return 1;}
  unsigned long count=((unsigned long(*)(id,SEL))objc_msgSend)(apps,sel_registerName("count"));
  printf("installed application records=%lu\n",count);
  for(unsigned long i=0;i<count&&i<1024;i++){
   id app=((id(*)(id,SEL,unsigned long))objc_msgSend)(apps,sel_registerName("objectAtIndex:"),i);
   id identifier=app_send(app,"applicationIdentifier"),url=app_send(app,"bundleURL");
   printf("installed app %lu identifier=",i);if(identifier)CFShow((CFTypeRef)identifier);
   printf("installed app %lu url=",i);if(url)CFShow((CFTypeRef)url);
  }
  return 0;
 }
 if(strcmp(argv[1],"app-install-staged")||argc!=3||!options_class)return 2;
 const char *name=argv[2];size_t n=strlen(name);
 if(n<5||n>180||strchr(name,'/')||strstr(name,"..")||strcmp(name+n-4,".app")){puts("one original staged .app name required");return 2;}
 char path[256];snprintf(path,sizeof path,"/private/var/staged_system_apps/%s",name);
 struct stat st;if(lstat(path,&st)||!S_ISDIR(st.st_mode)){puts("staged app directory missing");return 1;}
 CFDictionaryRef empty=CFDictionaryCreate(NULL,NULL,NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 id options=((id(*)(id,SEL,id))objc_msgSend)(app_send((id)options_class,"alloc"),sel_registerName("initWithLegacyOptionsDictionary:"),(id)empty);
 CFRelease(empty);if(!options){puts("stock install options initializer returned nil");return 1;}
 const char *setters[]={"setSystemAppInstall:","setInstallForMigrator:"};
 for(unsigned i=0;i<2;i++){
  SEL sel=sel_registerName(setters[i]);Method method=class_getInstanceMethod(options_class,sel);char type[16]={0};
  if(!method||method_getNumberOfArguments(method)!=3){printf("install option setter %s unavailable\n",setters[i]);return 1;}
  method_getArgumentType(method,2,type,sizeof type);if(type[0]!='B'&&type[0]!='c'){printf("install option setter %s ABI=%s\n",setters[i],type);return 1;}
  ((void(*)(id,SEL,Boolean))objc_msgSend)(options,sel,true);
 }
 /* Modern installd requires the requested bundle ID explicitly. Read it from
  * the original bundle, rather than inferring IDs from directory names. */
 char info_path[280];snprintf(info_path,sizeof info_path,"%s/Info.plist",path);
 CFStringRef info_name=CFStringCreateWithCString(NULL,info_path,kCFStringEncodingUTF8);
 id info=((id(*)(id,SEL,id))objc_msgSend)((id)objc_getClass("NSDictionary"),sel_registerName("dictionaryWithContentsOfFile:"),(id)info_name);
 CFRelease(info_name);
 id bundle=info?((id(*)(id,SEL,id))objc_msgSend)(info,sel_registerName("objectForKey:"),(id)CFSTR("CFBundleIdentifier")):NULL;
 SEL bundle_setter=sel_registerName("setBundleIdentifier:");
 Method bundle_method=class_getInstanceMethod(options_class,bundle_setter);
 if(!bundle||CFGetTypeID((CFTypeRef)bundle)!=CFStringGetTypeID()||!bundle_method||method_getNumberOfArguments(bundle_method)!=3){puts("original bundle identifier or option setter unavailable; no request");return 1;}
 char bundle_type[16]={0};method_getArgumentType(bundle_method,2,bundle_type,sizeof bundle_type);
 if(bundle_type[0]!='@'){puts("bundle identifier setter ABI mismatch; no request");return 1;}
 ((void(*)(id,SEL,id))objc_msgSend)(options,bundle_setter,bundle);
 printf("original staged bundle identifier=");CFShow((CFTypeRef)bundle);
 id dictionary=app_send(options,"legacyOptionsDictionary");
 CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),true);
 if(!dictionary||!url){printf("stock install options dictionary=%p URL=%p\n",dictionary,url);return 1;}
 printf("install stock staged app %s options=",path);CFShow((CFTypeRef)dictionary);
 Class installer_class=objc_getClass("MIInstallerClient");
 if(!installer_class){puts("stock MIInstallerClient unavailable; no request");CFRelease(url);return 1;}
 SEL factory=sel_registerName("installerWithProgressBlock:");
 if(!class_getClassMethod(installer_class,factory)){puts("stock installer factory unavailable; no request");CFRelease(url);return 1;}
 id installer=((id(*)(id,SEL,id))objc_msgSend)((id)installer_class,factory,NULL);
 SEL selector=sel_registerName("installURL:identity:targetingDomain:withOptions:returningResultInfo:completion:");
 Method method=class_getInstanceMethod(installer_class,selector);
 if(!installer||!method||method_getNumberOfArguments(method)!=8){puts("stock installer method unavailable; no request");CFRelease(url);return 1;}
 const char expected[]={'@','@','Q','@','B','@'};
 for(unsigned i=0;i<6;i++){char type[32]={0};method_getArgumentType(method,i+2,type,sizeof type);if(type[0]!=expected[i]){printf("installer argument%u ABI=%s; no request\n",i,type);CFRelease(url);return 1;}}
 /* Use the stock initializer's common Data location and default persona.
  * A nil identity reaches ICL as an unknown location type. */
 Class identity_class=objc_getClass("MIAppIdentity");SEL identity_init=sel_registerName("initWithBundleID:");
 Method identity_method=identity_class?class_getInstanceMethod(identity_class,identity_init):NULL;
 if(!identity_method||method_getNumberOfArguments(identity_method)!=3){puts("stock app identity initializer unavailable; no request");CFRelease(url);return 1;}
 char identity_type[16]={0};method_getArgumentType(identity_method,2,identity_type,sizeof identity_type);
 if(identity_type[0]!='@'){puts("stock identity initializer ABI mismatch; no request");CFRelease(url);return 1;}
 id identity=((id(*)(id,SEL,id))objc_msgSend)(app_send((id)identity_class,"alloc"),identity_init,bundle);
 if(!identity){puts("stock app identity initializer returned nil; no request");CFRelease(url);return 1;}
 printf("stock app identity=");CFShow((CFTypeRef)identity);
 /* Exact shipped reply block: v36@?0B8@NSArray12@LSRecordPromise20@NSError28. */
 __block int completed=0,successful=0;
 void(^completion)(Boolean,id,id,id)=^(Boolean ok,id records,id promise,id error){
  (void)promise;printf("stock staged installation success=%u\n",ok);
  if(records)CFShow((CFTypeRef)records);if(error)CFShow((CFTypeRef)error);
  __atomic_store_n(&successful,ok?1:0,__ATOMIC_RELEASE);__atomic_store_n(&completed,1,__ATOMIC_RELEASE);
 };
 ((void(*)(id,SEL,id,id,uint64_t,id,Boolean,id))objc_msgSend)(installer,selector,(id)url,identity,1,options,true,(id)completion);
 for(unsigned seconds=0;seconds<170&&!__atomic_load_n(&completed,__ATOMIC_ACQUIRE);seconds++)CFRunLoopRunInMode(kCFRunLoopDefaultMode,1,0);
 int ok=__atomic_load_n(&completed,__ATOMIC_ACQUIRE)&&__atomic_load_n(&successful,__ATOMIC_ACQUIRE);
 if(!__atomic_load_n(&completed,__ATOMIC_ACQUIRE))puts("stock installer completion not received before diagnostic deadline");
 CFRelease(url);return ok?0:1;
}

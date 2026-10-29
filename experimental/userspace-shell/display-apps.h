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
 if(!strcmp(argv[1],"app-info")||!strcmp(argv[1],"app-reregister")){
  Class cls=objc_getClass("LSApplicationProxy");SEL factory=sel_registerName("applicationProxyForIdentifier:");
  Method method=cls?class_getClassMethod(cls,factory):NULL;char returns[16]={0},argument[16]={0};
  if(!method||method_getNumberOfArguments(method)!=3)return 1;
  method_getReturnType(method,returns,sizeof returns);method_getArgumentType(method,2,argument,sizeof argument);
  if(returns[0]!='@'||argument[0]!='@')return 1;
  CFStringRef bundle=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);if(!bundle)return 1;
  id proxy=((id(*)(id,SEL,id))objc_msgSend)((id)cls,factory,(id)bundle);CFRelease(bundle);if(!proxy)return 1;
  const char *names[]={"applicationIdentifier","applicationType","bundleURL","appState","signerIdentity","compatibilityState","executableArchitectures","minimumSystemVersion","SDKVersion","isInstalled","isRestricted","isLaunchProhibited","isPlaceholder","isDeletable","isContainerized","requiresDeveloperMode"};
  for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
   SEL sel=sel_registerName(names[i]);Method getter=class_getInstanceMethod(object_getClass(proxy),sel);char type[32]={0};
   if(!getter||method_getNumberOfArguments(getter)!=2){printf("app.%s unavailable\n",names[i]);continue;}
   method_getReturnType(getter,type,sizeof type);printf("app.%s=",names[i]);
   if(type[0]=='@'){id value=((id(*)(id,SEL))objc_msgSend)(proxy,sel);if(value)CFShow((CFTypeRef)value);else puts("nil");}
   else if(type[0]=='B'||type[0]=='c')printf("%u\n",((Boolean(*)(id,SEL))objc_msgSend)(proxy,sel));
   else if(type[0]=='Q'||type[0]=='q')printf("%llu\n",(unsigned long long)((uint64_t(*)(id,SEL))objc_msgSend)(proxy,sel));
   else if(type[0]=='I'||type[0]=='i')printf("%u\n",((uint32_t(*)(id,SEL))objc_msgSend)(proxy,sel));
   else printf("unsupported ABI %s\n",type);
  }
  if(!strcmp(argv[1],"app-reregister")){
   /* Rescan only an installed built-in app at its existing bundle URL. */
   id kind=app_send(proxy,"applicationType"),url=app_send(proxy,"bundleURL");char path[1024]={0};
   if(!kind||!CFEqual((CFTypeRef)kind,CFSTR("System"))||!url||CFGetTypeID((CFTypeRef)url)!=CFURLGetTypeID()||!CFURLGetFileSystemRepresentation((CFURLRef)url,true,(UInt8*)path,sizeof path)||strncmp(path,"/Applications/",14)){puts("built-in application location guard failed; no registration");return 1;}
   SEL reg=sel_registerName("registerApplication:");Method registration=class_getInstanceMethod(workspace_class,reg);char rt[16]={0},at[16]={0};
   if(!registration||method_getNumberOfArguments(registration)!=3)return 1;method_getReturnType(registration,rt,sizeof rt);method_getArgumentType(registration,2,at,sizeof at);if((rt[0]!='B'&&rt[0]!='c')||at[0]!='@')return 1;
   Boolean ok=((Boolean(*)(id,SEL,id))objc_msgSend)(workspace,reg,url);printf("stock built-in registration request %s accepted=%u; metadata requires reread\n",argv[2],ok);return ok?0:1;
  }
  return 0;
 }
 if(!strcmp(argv[1],"app-open-error")||!strcmp(argv[1],"app-open-unlock")){
  /* Exact iOS27 FrontBoard callback: v24@?0@BSProcessHandle8@NSError16.
   * Keep the original error; the older LS Boolean API discards it. */
  void *fbs=dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices",RTLD_NOW|RTLD_LOCAL);if(!fbs)return 1;
  Class service_class=objc_getClass("FBSOpenApplicationService"),options_class=objc_getClass("FBSOpenApplicationOptions");
  SEL service_factory=sel_registerName("serviceWithDefaultShellEndpoint"),options_factory=sel_registerName("optionsWithDictionary:"),open=sel_registerName("openApplication:withOptions:completion:");
  Method sf=service_class?class_getClassMethod(service_class,service_factory):NULL,of=options_class?class_getClassMethod(options_class,options_factory):NULL,op=service_class?class_getInstanceMethod(service_class,open):NULL;
  char type[32]={0};if(!sf||!of||!op||method_getNumberOfArguments(sf)!=2||method_getNumberOfArguments(of)!=3||method_getNumberOfArguments(op)!=5)return 1;
  method_getReturnType(sf,type,sizeof type);if(type[0]!='@')return 1;
  method_getReturnType(of,type,sizeof type);if(type[0]!='@')return 1;
  method_getArgumentType(of,2,type,sizeof type);if(type[0]!='@')return 1;
  method_getReturnType(op,type,sizeof type);if(type[0]!='v')return 1;
  for(unsigned i=2;i<=4;i++){method_getArgumentType(op,i,type,sizeof type);if(type[0]!='@'||(i==4&&type[1]!='?'))return 1;}
  CFStringRef bundle=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);CFMutableDictionaryRef empty=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);if(!bundle||!empty)return 1;
  if(!strcmp(argv[1],"app-open-unlock")){
   CFStringRef *unlock=dlsym(fbs,"FBSOpenApplicationOptionKeyUnlockDevice"),*prompt=dlsym(fbs,"FBSOpenApplicationOptionKeyPromptUnlockDevice");
   if(!unlock||!prompt||!*unlock||!*prompt||CFGetTypeID(*unlock)!=CFStringGetTypeID()||CFGetTypeID(*prompt)!=CFStringGetTypeID()){puts("normal unlock option keys unavailable; no launch request");CFRelease(bundle);CFRelease(empty);return 1;}
   CFDictionarySetValue(empty,*unlock,kCFBooleanTrue);CFDictionarySetValue(empty,*prompt,kCFBooleanTrue);puts("requesting normal FrontBoard unlock/prompt handling");
  }
  id service=((id(*)(id,SEL))objc_msgSend)((id)service_class,service_factory),options=((id(*)(id,SEL,id))objc_msgSend)((id)options_class,options_factory,(id)empty);
  if(!service||!options){CFRelease(bundle);CFRelease(empty);return 1;}
  __block int completed=0,successful=0;
  void(^completion)(id,id)=^(id process,id error){
   printf("FrontBoard completion process=%p error=%p\n",process,error);if(process)CFShow((CFTypeRef)process);if(error)CFShow((CFTypeRef)error);
   if(error){id info=app_send(error,"userInfo");if(info)CFShow((CFTypeRef)info);}
   __atomic_store_n(&successful,process&&!error,__ATOMIC_RELEASE);__atomic_store_n(&completed,1,__ATOMIC_RELEASE);
  };
  printf("FrontBoard normal open request %s\n",argv[2]);((void(*)(id,SEL,id,id,id))objc_msgSend)(service,open,(id)bundle,options,(id)completion);
  for(unsigned i=0;i<18&&!__atomic_load_n(&completed,__ATOMIC_ACQUIRE);i++)CFRunLoopRunInMode(kCFRunLoopDefaultMode,1,0);
  int done=__atomic_load_n(&completed,__ATOMIC_ACQUIRE),ok=__atomic_load_n(&successful,__ATOMIC_ACQUIRE);printf("FrontBoard completed=%d successful=%d; actual process/UI still require verification\n",done,ok);CFRelease(bundle);CFRelease(empty);return done&&ok?0:1;
 }
 if(!strcmp(argv[1],"app-open")){
  if(argc!=3||!argv[2][0]||strlen(argv[2])>200)return 2;
  for(const char *p=argv[2];*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='.'||*p=='-'||*p=='_'))return 2;
  SEL open_selector=sel_registerName("openApplicationWithBundleID:");Method open_method=class_getInstanceMethod(workspace_class,open_selector);char ret[16]={0},arg[16]={0};
  if(!open_method||method_getNumberOfArguments(open_method)!=3){puts("stock app open API unavailable");return 1;}
  method_getReturnType(open_method,ret,sizeof ret);method_getArgumentType(open_method,2,arg,sizeof arg);
  if((ret[0]!='B'&&ret[0]!='c')||arg[0]!='@'){puts("stock app open ABI mismatch");return 1;}
  CFStringRef bundle=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);if(!bundle)return 1;
  Boolean accepted=((Boolean(*)(id,SEL,id))objc_msgSend)(workspace,open_selector,(id)bundle);CFRelease(bundle);
  printf("stock app open request %s accepted=%u; process and UI require verification\n",argv[2],accepted);return accepted?0:1;
 }
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

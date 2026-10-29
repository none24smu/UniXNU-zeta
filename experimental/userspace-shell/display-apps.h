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
 id workspace=app_send((id)workspace_class,"defaultWorkspace");if(!workspace)return 1;
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
 id options=app_send((id)options_class,"new");
 const char *setters[]={"setSystemAppInstall:","setInstallForMigrator:"};
 for(unsigned i=0;i<2;i++){
  SEL sel=sel_registerName(setters[i]);Method method=class_getInstanceMethod(options_class,sel);char type[16]={0};
  if(!method||method_getNumberOfArguments(method)!=3)return 1;
  method_getArgumentType(method,2,type,sizeof type);if(type[0]!='B'&&type[0]!='c')return 1;
  ((void(*)(id,SEL,Boolean))objc_msgSend)(options,sel,true);
 }
 id dictionary=app_send(options,"legacyOptionsDictionary");
 CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),true);
 if(!dictionary||!url)return 1;
 printf("install stock staged app %s options=",path);CFShow((CFTypeRef)dictionary);
 SEL selector=sel_registerName("installApplication:withOptions:error:usingBlock:");
 Method method=class_getInstanceMethod(workspace_class,selector);char returns[16]={0};
 if(!method||method_getNumberOfArguments(method)!=6){puts("stock installation API unavailable; no request");CFRelease(url);return 1;}
 method_getReturnType(method,returns,sizeof returns);
 if(returns[0]!='B'&&returns[0]!='c'){puts("installation return ABI mismatch; no request");CFRelease(url);return 1;}
 const char expected[]={'@','@','^','@'};
 for(unsigned i=0;i<4;i++){char type[32]={0};method_getArgumentType(method,i+2,type,sizeof type);const char *t=type;while(*t&&strchr("rnNoORV",*t))t++;if(*t!=expected[i]){printf("installation argument%u ABI=%s; no request\n",i,type);CFRelease(url);return 1;}}
 id error=NULL;Boolean ok=((Boolean(*)(id,SEL,id,id,id*,id))objc_msgSend)(workspace,selector,(id)url,dictionary,&error,NULL);
 printf("stock staged installation success=%u\n",ok);if(error)CFShow((CFTypeRef)error);
 CFRelease(url);return ok?0:1;
}

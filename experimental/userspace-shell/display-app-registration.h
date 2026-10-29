/* Regenerate one original built-in application's registration using the
 * shipped MI bundle/signing/container builder and active LS rebuild API. */
#include <dirent.h>
static int registration_method(id target,const char *name,char returns,const char *arguments){
 Method m=target?class_getInstanceMethod(object_getClass(target),sel_registerName(name)):NULL;char type[32]={0};
 if(!m||method_getNumberOfArguments(m)!=strlen(arguments)+2){printf("registration method unavailable: %s\n",name);return 0;}
 method_getReturnType(m,type,sizeof type);if(type[0]!=returns&&!(returns=='B'&&type[0]=='c'))return 0;
 for(unsigned i=0;arguments[i];i++){method_getArgumentType(m,i+2,type,sizeof type);if(type[0]!=arguments[i]&&!(arguments[i]=='B'&&type[0]=='c'))return 0;}
 return 1;
}
static int registration_source(const char *path,size_t expected,const unsigned char digest[32]){
 int fd=open(path,O_RDONLY);struct stat st;if(fd<0)return 0;if(fstat(fd,&st)||(size_t)st.st_size!=expected){close(fd);return 0;}
 void *data=mmap(NULL,expected,PROT_READ,MAP_PRIVATE,fd,0);close(fd);if(data==MAP_FAILED)return 0;
 unsigned char actual[32];CC_SHA256(data,(CC_LONG)expected,actual);munmap(data,expected);return !memcmp(actual,digest,32);
}
static id registration_record(const char *path,const char *identifier,int extension,CFMutableSetRef personas){
 Class cls=objc_getClass(extension?"MIAppExtensionBundle":"MIExecutableBundle"),data_class=objc_getClass("MIDataContainer"),gather_class=objc_getClass("MIInstalledInfoGatherer");
 if(!cls||!data_class||!gather_class)return NULL;
 id allocated=app_send((id)cls,"alloc");const char *init="initWithBundleURL:error:";if(!registration_method(allocated,init,'@',"@^"))return NULL;
 CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)path,strlen(path),true);id error=NULL;
 id bundle=((id(*)(id,SEL,id,id*))objc_msgSend)(allocated,sel_registerName(init),(id)url,&error);CFRelease(url);
 if(!bundle||error){if(error)CFShow((CFTypeRef)error);return NULL;}
 if(!registration_method(bundle,"bundleType",'C',""))return NULL;
 unsigned char type=((unsigned char(*)(id,SEL))objc_msgSend)(bundle,sel_registerName("bundleType"));printf("native bundle %s type=%u\n",identifier,type);if(!extension&&type!=1)return NULL;
 const char *query="dataContainersForExecutableBundle:createIfNeeded:temporary:created:error:";
 if(!registration_method((id)data_class,query,'@',"@BB^^"))return NULL;
 Boolean created=false;id containers=((id(*)(id,SEL,id,Boolean,Boolean,Boolean*,id*))objc_msgSend)((id)data_class,sel_registerName(query),bundle,false,false,&created,&error);
 if(error){
  if(!registration_method(bundle,"needsDataContainer",'B',""))return NULL;
  Boolean needed=((Boolean(*)(id,SEL))objc_msgSend)(bundle,sel_registerName("needsDataContainer"));
  id domain=app_send(error,"domain");long code=((long(*)(id,SEL))objc_msgSend)(error,sel_registerName("code"));
  if(domain&&CFEqual((CFTypeRef)domain,CFSTR("MIContainerManagerErrorDomain"))&&code==21){
   if(!needed&&type==1){puts("native non-containerized built-in has no data container; retaining nil");error=NULL;containers=NULL;}
   else if(needed){error=NULL;containers=((id(*)(id,SEL,id,Boolean,Boolean,Boolean*,id*))objc_msgSend)((id)data_class,sel_registerName(query),bundle,true,false,&created,&error);printf("native required data-container initialization created=%u\n",created);}
  }
 }
 if(error){CFShow((CFTypeRef)error);puts("native container query failed; no registration");return NULL;}
 id strings=NULL;
 if(containers){if(!registration_method(containers,"allPersonaUniqueStrings",'@',""))return NULL;strings=app_send(containers,"allPersonaUniqueStrings");}
 if(strings){if(CFGetTypeID((CFTypeRef)strings)!=CFSetGetTypeID())return NULL;CFIndex n=CFSetGetCount((CFSetRef)strings);if(n>32)return NULL;const void *items[32];CFSetGetValues((CFSetRef)strings,items);for(CFIndex i=0;i<n;i++)CFSetAddValue(personas,items[i]);}
 id gatherer=app_send((id)gather_class,"alloc");
 if(extension){
  const char *name="initWithAppExtensionBundle:inBundleIdentifier:dataContainers:associatedPersonaUniqueStrings:";
  if(!registration_method(gatherer,name,'@',"@@@@"))return NULL;
  gatherer=((id(*)(id,SEL,id,id,id,id))objc_msgSend)(gatherer,sel_registerName(name),bundle,(id)CFSTR("com.apple.Preferences"),containers,strings);
 }else{
  const char *name="initWithBundle:dataContainers:associatedPersonaUniqueStrings:";
  if(!registration_method(gatherer,name,'@',"@@@"))return NULL;
  gatherer=((id(*)(id,SEL,id,id,id))objc_msgSend)(gatherer,sel_registerName(name),bundle,containers,strings);
 }
 if(!registration_method(gatherer,"bundleRecordWithError:",'@',"^"))return NULL;
 id record=((id(*)(id,SEL,id*))objc_msgSend)(gatherer,sel_registerName("bundleRecordWithError:"),&error);
 if(error||!record){if(error)CFShow((CFTypeRef)error);return NULL;}
 if(!registration_method(record,"legacyRecordDictionary",'@',""))return NULL;
 id legacy=app_send(record,"legacyRecordDictionary");if(!legacy||CFGetTypeID((CFTypeRef)legacy)!=CFDictionaryGetTypeID())return NULL;
 CFStringRef expected=CFStringCreateWithCString(NULL,identifier,kCFStringEncodingUTF8);CFTypeRef actual=CFDictionaryGetValue((CFDictionaryRef)legacy,CFSTR("CFBundleIdentifier"));int same=actual&&CFEqual(actual,expected);CFRelease(expected);if(!same)return NULL;
 CFTypeRef state=CFDictionaryGetValue((CFDictionaryRef)legacy,CFSTR("CompatibilityState"));int64_t value=-1;if(!state||CFGetTypeID(state)!=CFNumberGetTypeID()||!CFNumberGetValue((CFNumberRef)state,kCFNumberSInt64Type,&value))return NULL;
 printf("native fresh registration %s compatibility=%lld\n",identifier,(long long)value);CFShow((CFTypeRef)legacy);if(value!=0)return NULL;
 return record;
}
static int rebuild_settings_registration(id workspace,int publish){
 const unsigned char main_hash[32]={0xd7,0xee,0xc4,0xf5,0xb0,0x9f,0x6b,0xb8,0xe1,0x52,0xe5,0x01,0x03,0xa3,0xa2,0x2d,0x73,0x0d,0x75,0x48,0xa5,0xb2,0x8a,0xac,0xa9,0xb1,0xdb,0xa1,0xf6,0x1c,0x23,0x61};
 const unsigned char extension_hash[32]={0xcb,0xb5,0x39,0x85,0xdf,0x74,0xc2,0xcd,0xf1,0xa0,0x94,0x56,0x7a,0x40,0xd2,0x5f,0x1e,0xd7,0x78,0xf7,0x05,0xda,0xbe,0x1b,0x1d,0x0d,0x73,0x60,0x96,0x3b,0xb7,0xbd};
 const char *root="/Applications/Preferences.app",*extension="/Applications/Preferences.app/PlugIns/SettingsImportExtension.appex";
 if(!registration_source("/Applications/Preferences.app/Preferences",2056112,main_hash)||!registration_source("/Applications/Preferences.app/PlugIns/SettingsImportExtension.appex/SettingsImportExtension",74000,extension_hash)){puts("original Settings fingerprint guard failed; no registration");return 1;}
 DIR *directory=opendir("/Applications/Preferences.app/PlugIns");if(!directory)return 1;unsigned found=0;struct dirent *entry;while((entry=readdir(directory))){if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;if(strcmp(entry->d_name,"SettingsImportExtension.appex")){closedir(directory);puts("unexpected Settings extension; no registration");return 1;}found++;}closedir(directory);if(found!=1)return 1;
 if(!dlopen("/System/Library/PrivateFrameworks/InstalledContentLibrary.framework/InstalledContentLibrary",RTLD_NOW|RTLD_LOCAL))return 1;
 CFMutableSetRef personas=CFSetCreateMutable(NULL,0,&kCFTypeSetCallBacks);
 id app=registration_record(root,"com.apple.Preferences",0,personas);if(!app){CFRelease(personas);return 1;}
 id child=registration_record(extension,"com.apple.Preferences.SettingsImportExtension",1,personas);if(!child){CFRelease(personas);return 1;}
 puts("fresh native main/extension records generated; no custom trust or compatibility fields supplied");if(!publish){CFRelease(personas);return 0;}
 const char *name="registerApplicationForRebuildWithInstallationRecord:extensionInstallationRecords:personaUniqueStrings:requestContext:registrationError:";
 if(!registration_method(workspace,name,'B',"@@@@^")){CFRelease(personas);return 1;}
 const void *value=child;CFArrayRef children=CFArrayCreate(NULL,&value,1,&kCFTypeArrayCallBacks);id strings=app_send((id)personas,"allObjects");id error=NULL;
 Boolean ok=((Boolean(*)(id,SEL,id,id,id,id,id*))objc_msgSend)(workspace,sel_registerName(name),app,(id)children,strings,NULL,&error);
 printf("active LS rebuild registration accepted=%u error=%p\n",ok,error);if(error){CFShow((CFTypeRef)error);id info=app_send(error,"userInfo");if(info)CFShow((CFTypeRef)info);}CFRelease(children);CFRelease(personas);return ok&&!error?0:1;
}

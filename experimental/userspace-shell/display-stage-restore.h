/* Restore an original staged app file from a pinned compressed host copy.
 * This never overwrites a destination and never writes the sealed OS root. */
static int restore_staged_file(int argc,char **argv){
 if(argc!=9)return 2;
 const char *src=argv[2],*relative=argv[3];size_t n=strlen(relative);
 if(strncmp(src,"/private/var/ngpu/shell/",24)||strstr(src,"..")||n<6||n>600||relative[0]=='/'||strstr(relative,"//"))return 2;
 const char *first=strchr(relative,'/');if(!first||first-relative<5||memcmp(first-4,".app",4))return 2;
 for(const char *p=relative;*p;){const char *end=strchr(p,'/');size_t len=end?(size_t)(end-p):strlen(p);if(!len||(len==1&&p[0]=='.')||(len==2&&!memcmp(p,"..",2)))return 2;p=end?end+1:p+len;}
 char *end=NULL;uint64_t expected=strtoull(argv[4],&end,0);if(!end||*end||!expected||expected>32*1024*1024)return 2;
 unsigned mode=(unsigned)strtoul(argv[6],&end,8);if(!end||*end||mode>0777)return 2;
 unsigned uid=(unsigned)strtoul(argv[7],&end,10);if(!end||*end)return 2;
 unsigned gid=(unsigned)strtoul(argv[8],&end,10);if(!end||*end||uid>501||gid>501)return 2;
 if(strlen(argv[5])!=64)return 2;
 int in=open(src,O_RDONLY);struct stat st;if(in<0)return 1;
 if(fstat(in,&st)||st.st_size<1||st.st_size>32*1024*1024){close(in);return 1;}
 void *packed=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,in,0);close(in);if(packed==MAP_FAILED)return 1;
 void *raw=malloc((size_t)expected);uLongf size=(uLongf)expected;int z=raw?uncompress(raw,&size,packed,(uLong)st.st_size):Z_MEM_ERROR;munmap(packed,(size_t)st.st_size);
 if(z!=Z_OK||size!=expected){free(raw);puts("staged file decompression mismatch; no write");return 1;}
 unsigned char digest[CC_SHA256_DIGEST_LENGTH];char hex[65];CC_SHA256(raw,(CC_LONG)expected,digest);for(unsigned i=0;i<sizeof digest;i++)snprintf(hex+i*2,3,"%02x",digest[i]);
 if(strcmp(hex,argv[5])){free(raw);puts("staged file SHA mismatch; no write");return 1;}
 char path[700];snprintf(path,sizeof path,"/private/var/staged_system_apps/%s",relative);
 for(char *p=path+strlen("/private/var/staged_system_apps/");*p;p++)if(*p=='/'){
  *p=0;if(lstat(path,&st)){if(errno!=ENOENT||mkdir(path,0755)){free(raw);return 1;}}else if(!S_ISDIR(st.st_mode)){free(raw);return 1;}*p='/';
 }
 int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);if(fd<0){perror("restore staged file");free(raw);return 1;}
 size_t done=0;while(done<expected){ssize_t wrote=write(fd,(char*)raw+done,(size_t)expected-done);if(wrote<=0)break;done+=(size_t)wrote;}
 int ok=done==expected&&!fchmod(fd,mode)&&!fchown(fd,uid,gid);close(fd);free(raw);if(!ok){unlink(path);return 1;}
 printf("restored original staged file %s bytes=%llu sha256=%s\n",relative,(unsigned long long)expected,hex);return 0;
}

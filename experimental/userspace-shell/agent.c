#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
#define COMMAND_MAX 4096
static void die(const char *why){perror(why);exit(1);}
static void writeall(int fd,const void *data,size_t len){const char*p=data;while(len){ssize_t n=write(fd,p,len);if(n<0&&errno==EINTR)continue;if(n<=0)die("write");p+=n;len-=(size_t)n;}}
static uint64_t fnv(const unsigned char*p,size_t n){uint64_t h=UINT64_C(14695981039346656037);while(n--){h^=*p++;h*=UINT64_C(1099511628211);}return h;}
static int private_file(const char*p){struct stat s;return lstat(p,&s)==0&&S_ISREG(s.st_mode)&&s.st_uid==getuid()&&s.st_nlink==1&&!(s.st_mode&022);}
static void directory(const char*p){if(mkdir(p,0700)&&errno!=EEXIST)die("mkdir");struct stat s;if(lstat(p,&s)||!S_ISDIR(s.st_mode)||s.st_uid!=getuid()){fprintf(stderr,"unowned directory: %s\n",p);exit(1);}if(chmod(p,0700))die("chmod directory");}
static const char *basename_(const char*p){const char*q=strrchr(p,'/');return q?q+1:p;}
static int utility(int argc,char**argv){const char*name=basename_(argv[0]);
 if(!strcmp(name,"id")||(argc==2&&!strcmp(argv[1],"--identity"))){printf("uid=%lu gid=%lu euid=%lu egid=%lu pid=%ld ppid=%ld\n",(unsigned long)getuid(),(unsigned long)getgid(),(unsigned long)geteuid(),(unsigned long)getegid(),(long)getpid(),(long)getppid());return 0;}
 if(!strcmp(name,"uname")){struct utsname u;if(uname(&u))die("uname");printf("%s %s %s %s %s\n",u.sysname,u.nodename,u.release,u.version,u.machine);return 0;}
 if(!strcmp(name,"cat")){char b[8192];int nfiles=argc>1?argc-1:1;for(int i=0;i<nfiles;i++){int fd=argc>1?open(argv[i+1],O_RDONLY):STDIN_FILENO;if(fd<0)die("cat open");ssize_t n;while((n=read(fd,b,sizeof b))>0)writeall(STDOUT_FILENO,b,(size_t)n);if(n<0)die("cat read");if(fd!=STDIN_FILENO)close(fd);}return 0;}
 if(!strcmp(name,"rm")){if(argc<2)return 2;for(int i=1;i<argc;i++)if(unlink(argv[i]))die("rm unlink");return 0;}
 if(!strcmp(name,"ls")){int detail=argc>1&&!strcmp(argv[1],"-l");const char*p=argc>1+detail?argv[1+detail]:".";DIR*d=opendir(p);if(!d)die("ls opendir");struct dirent*e;while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;if(detail){struct stat s;if(fstatat(dirfd(d),e->d_name,&s,AT_SYMLINK_NOFOLLOW))die("ls stat");printf("%07o %lu %lu %lld ",(unsigned)s.st_mode,(unsigned long)s.st_uid,(unsigned long)s.st_gid,(long long)s.st_size);}puts(e->d_name);}closedir(d);return 0;}
 return -1;
}
static void statusfile(const char*path,pid_t child,const char*state){char tmp[1024];if(snprintf(tmp,sizeof tmp,"%s.tmp",path)>=(int)sizeof tmp)die("status path");int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0600);if(fd<0)die("status open");dprintf(fd,"{\"version\":1,\"agent_pid\":%ld,\"shell_pid\":%ld,\"uid\":%lu,\"gid\":%lu,\"state\":\"%s\"}\n",(long)getpid(),(long)child,(unsigned long)getuid(),(unsigned long)getgid(),state);fsync(fd);close(fd);if(rename(tmp,path))die("status rename");}
int main(int argc,char**argv){int util=utility(argc,argv);if(util>=0)return util;const char*work="/private/var/ngpu/shell",*shell="/System/Library/Extensions/ZetaShellAgent.bundle/ZetaDash";for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--work-dir")&&i+1<argc)work=argv[++i];else if(!strcmp(argv[i],"--shell")&&i+1<argc)shell=argv[++i];else{fprintf(stderr,"usage: %s [--work-dir directory] [--shell executable]\n",argv[0]);return 2;}}
 umask(077);signal(SIGPIPE,SIG_IGN);directory(work);char request[1024],ready[1024],output[1024],status[1024],bin[1024],self[4096],path[4096];
 if(!realpath(argv[0],self))die("agent realpath");
#define PATHVAR(v,suffix) do{if(snprintf(v,sizeof v,"%s/%s",work,suffix)>=(int)sizeof v)die("work path");}while(0)
 PATHVAR(request,"request");PATHVAR(ready,"ready");PATHVAR(output,"output.log");PATHVAR(status,"session.json");PATHVAR(bin,"bin");directory(bin);
 const char*names[]={"id","uname","cat","ls","rm"};for(unsigned i=0;i<sizeof names/sizeof names[0];i++){char link[1200];snprintf(link,sizeof link,"%s/%s",bin,names[i]);struct stat st;if(!lstat(link,&st)){char prior[4096];ssize_t n=readlink(link,prior,sizeof prior-1);if(n<0)die("existing utility");prior[n]=0;if(strcmp(prior,self)){fprintf(stderr,"preserve different utility: %s\n",link);return 1;}}else if(errno!=ENOENT||symlink(self,link))die("utility symlink");}
 if(snprintf(path,sizeof path,"%s:/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec",bin)>=(int)sizeof path)die("PATH");if(setenv("PATH",path,1)||setenv("SHELL",shell,1)||setenv("TERM","dumb",1))die("setenv");
 int in[2],out[2];if(pipe(in)||pipe(out))die("pipe");posix_spawn_file_actions_t fa;int err=posix_spawn_file_actions_init(&fa);if(err){errno=err;die("spawn actions");}
#define ACTION(x) do{int e=(x);if(e){errno=e;die("spawn action");}}while(0)
 ACTION(posix_spawn_file_actions_adddup2(&fa,in[0],STDIN_FILENO));ACTION(posix_spawn_file_actions_adddup2(&fa,out[1],STDOUT_FILENO));ACTION(posix_spawn_file_actions_adddup2(&fa,out[1],STDERR_FILENO));ACTION(posix_spawn_file_actions_addclose(&fa,in[1]));ACTION(posix_spawn_file_actions_addclose(&fa,out[0]));ACTION(posix_spawn_file_actions_addclose(&fa,in[0]));ACTION(posix_spawn_file_actions_addclose(&fa,out[1]));
 posix_spawnattr_t attr;ACTION(posix_spawnattr_init(&attr));ACTION(posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP));ACTION(posix_spawnattr_setpgroup(&attr,0));pid_t child;char*args[]={(char*)shell,"-s",NULL};err=posix_spawn(&child,shell,&fa,&attr,args,environ);posix_spawnattr_destroy(&attr);posix_spawn_file_actions_destroy(&fa);if(err){errno=err;die("spawn shell");}close(in[0]);close(out[1]);int flags=fcntl(out[0],F_GETFL);if(flags<0||fcntl(out[0],F_SETFL,flags|O_NONBLOCK))die("nonblock");
 int log=open(output,O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW,0600);if(log<0)die("output open");dprintf(log,"\n@zagent start agent=%ld shell=%ld uid=%lu gid=%lu\n",(long)getpid(),(long)child,(unsigned long)getuid(),(unsigned long)getgid());fsync(log);statusfile(status,child,"running");char last[17]="";
 for(;;){char b[8192];ssize_t got;while((got=read(out[0],b,sizeof b))>0){writeall(log,b,(size_t)got);fsync(log);}if(got<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)die("shell output");int ws=0;pid_t ended=waitpid(child,&ws,WNOHANG);if(ended==child){dprintf(log,"\n@zagent shell-exited status=%d\n",ws);fsync(log);statusfile(status,child,"exited");return WIFEXITED(ws)?WEXITSTATUS(ws):128+WTERMSIG(ws);}if(ended<0&&errno!=EINTR)die("waitpid");
  if(private_file(ready)){int fd=open(ready,O_RDONLY|O_NOFOLLOW);if(fd<0)die("ready open");char line[128]={0};ssize_t n=read(fd,line,sizeof line-1);close(fd);if(n<=0){unlink(ready);continue;}int sig;if(sscanf(line,"signal %d",&sig)==1&&(sig==SIGINT||sig==SIGTERM)){unlink(ready);if(kill(-child,sig))perror("signal shell");continue;}
   char nonce[17]={0},hash[17]={0},extra=0;size_t len=0;int valid=sscanf(line,"%16[0-9a-f] %zu %16[0-9a-f] %c",nonce,&len,hash,&extra)==3&&strlen(nonce)==16&&strlen(hash)==16&&len>0&&len<=COMMAND_MAX;
   unsigned char cmd[COMMAND_MAX];if(valid&&private_file(request)){fd=open(request,O_RDONLY|O_NOFOLLOW);if(fd<0)die("request open");size_t done=0;while(done<len){ssize_t nr=read(fd,cmd+done,len-done);if(nr<0&&errno==EINTR)continue;if(nr<=0)break;done+=(size_t)nr;}unsigned char tail;ssize_t more=read(fd,&tail,1);close(fd);valid=done==len&&more==0&&fnv(cmd,len)==strtoull(hash,0,16)&&!memchr(cmd,0,len);}else valid=0;
   if(unlink(ready))die("claim request");if(!valid){dprintf(log,"\n@zagent rejected malformed/incomplete request\n");fsync(log);continue;}if(!strcmp(last,nonce)){dprintf(log,"\n@zagent duplicate request refused\n");fsync(log);continue;}memcpy(last,nonce,sizeof last);writeall(in[1],cmd,len);char end[160];int count=snprintf(end,sizeof end,"\n_zeta_status=$?\ncommand printf '\\n@zs%s:%%d\\n' \"$_zeta_status\"\n",nonce);writeall(in[1],end,(size_t)count);
  }
  struct pollfd pollfd={out[0],POLLIN,0};if(poll(&pollfd,1,40)<0&&errno!=EINTR)die("poll");
 }
}

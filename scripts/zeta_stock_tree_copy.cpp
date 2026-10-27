// Host/guest filesystem materializer. Never follows source symlinks or filters
// entries. Compression xattrs are deliberately not copied; native APFS audit
// and independent decoded-content verification must qualify normalization.
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

static uint64_t files=0,dirs=0,links=0,bytes=0,hardlinks=0,nodes=0;
static int destinationRoot=-1;
static std::unordered_map<std::string,std::string> firstLink;
static std::string readPath(FILE *plan) {
    uint32_t length=0;
    if(fread(&length,4,1,plan)!=1 || !length || length>65535)throw std::runtime_error("bad native hardlink path length");
    std::string path(length,'\0');
    if(fread(path.data(),1,length,plan)!=length || path[0]=='/' || path.find('\0')!=std::string::npos)
        throw std::runtime_error("bad native hardlink path");
    size_t at=0;
    while(at<path.size()) {
        size_t end=path.find('/',at);std::string part=path.substr(at,end==std::string::npos?end:end-at);
        if(part.empty() || part=="." || part=="..")throw std::runtime_error("unsafe native hardlink path");
        if(end==std::string::npos)break;
        at=end+1;
    }
    return path;
}
static int openParent(int root,const std::string &path,std::string &name) {
    int current=dup(root);size_t at=0;
    for(;;) {
        size_t end=path.find('/',at);
        if(end==std::string::npos){name=path.substr(at);return current;}
        std::string part=path.substr(at,end-at);
        int next=openat(current,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW);close(current);
        if(next<0)throw std::runtime_error("hardlink path traverses a symlink/non-directory");
        current=next;at=end+1;
    }
}
static int repairLinks(const char *planPath,const char *rootPath) {
    FILE *plan=fopen(planPath,"rb");if(!plan)throw std::runtime_error("cannot open native hardlink plan");
    char magic[8];uint64_t count=0;
    if(fread(magic,1,8,plan)!=8 || memcmp(magic,"ZHLINK01",8) || fread(&count,8,1,plan)!=1 || count>1000000)
        throw std::runtime_error("bad native hardlink plan header");
    int root=open(rootPath,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(root<0)throw std::runtime_error("cannot open hardlink target");
    for(uint64_t i=0;i<count;++i) {
        std::string first=readPath(plan),alias=readPath(plan),firstName,aliasName;struct stat a,b;
        int firstParent=openParent(root,first,firstName),aliasParent=openParent(root,alias,aliasName);
        if(fstatat(firstParent,firstName.c_str(),&a,AT_SYMLINK_NOFOLLOW) || fstatat(aliasParent,aliasName.c_str(),&b,AT_SYMLINK_NOFOLLOW) ||
            !S_ISREG(a.st_mode) || !S_ISREG(b.st_mode) || a.st_size!=b.st_size ||
            a.st_uid!=b.st_uid || a.st_gid!=b.st_gid || a.st_mode!=b.st_mode)
            throw std::runtime_error("native hardlink candidate differs: "+alias);
        if(a.st_ino==b.st_ino && a.st_dev==b.st_dev){close(firstParent);close(aliasParent);continue;}
        if(unlinkat(aliasParent,aliasName.c_str(),0) || linkat(firstParent,firstName.c_str(),aliasParent,aliasName.c_str(),0))
            throw std::runtime_error("native hardlink repair failed: "+alias+": "+std::strerror(errno));
        close(firstParent);close(aliasParent);
    }
    if(fgetc(plan)!=EOF)throw std::runtime_error("trailing native hardlink plan bytes");
    fclose(plan);sync();close(root);
    std::printf("HARDLINK-COMPLETE aliases=%llu\n",(unsigned long long)count);return 0;
}
static void fail(const std::string &path,const char *what) {
    throw std::runtime_error(path+": "+what+": "+std::strerror(errno));
}
static void metadata(int fd,const struct stat &s,const std::string &path) {
    if(fchown(fd,s.st_uid,s.st_gid)||fchmod(fd,s.st_mode&07777))fail(path,"owner/mode");
    struct timespec t[2]={s.st_atim,s.st_mtim};
    if(futimens(fd,t))fail(path,"timestamps");
}
static void copyNode(int source,int target,const char *name,const std::string &relative);
static void copyDir(int source,int target,const std::string &relative,const struct stat &s) {
    ++dirs;
    DIR *d=fdopendir(dup(source));if(!d)fail(relative,"opendir");
    errno=0;
    while(auto *entry=readdir(d)) {
        if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
        copyNode(source,target,entry->d_name,relative.empty()?entry->d_name:relative+"/"+entry->d_name);
        errno=0;
    }
    if(errno)fail(relative,"readdir");
    closedir(d);metadata(target,s,relative);
}
static void copyNode(int source,int target,const char *name,const std::string &relative) {
    struct stat s;if(fstatat(source,name,&s,AT_SYMLINK_NOFOLLOW))fail(relative,"lstat");
    if(S_ISDIR(s.st_mode)) {
        if(mkdirat(target,name,0700))fail(relative,"mkdir");
        int a=openat(source,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW),b=openat(target,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        if(a<0||b<0)fail(relative,"open directory");
        copyDir(a,b,relative,s);close(a);close(b);
    } else if(S_ISLNK(s.st_mode)) {
        std::vector<char> value(65536);auto n=readlinkat(source,name,value.data(),value.size()-1);
        if(n<0||size_t(n)>=value.size()-1)fail(relative,"readlink");
        value[n]=0;
        if(symlinkat(value.data(),target,name)||fchownat(target,name,s.st_uid,s.st_gid,AT_SYMLINK_NOFOLLOW))fail(relative,"symlink");
        struct timespec t[2]={s.st_atim,s.st_mtim};
        if(utimensat(target,name,t,AT_SYMLINK_NOFOLLOW))fail(relative,"symlink timestamps");
        ++links;
    } else if(S_ISREG(s.st_mode)) {
        std::string key=std::to_string(s.st_dev)+":"+std::to_string(s.st_ino);
        auto prior=s.st_nlink>1?firstLink.find(key):firstLink.end();
        if(prior!=firstLink.end()) {
            if(linkat(destinationRoot,prior->second.c_str(),target,name,0))fail(relative,"hardlink");
            ++hardlinks;
        } else {
            int a=openat(source,name,O_RDONLY|O_NOFOLLOW),b=openat(target,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
            if(a<0||b<0)fail(relative,"open file");
            std::vector<char> buffer(1<<20);uint64_t copied=0;
            for(;;) {
                ssize_t n=read(a,buffer.data(),buffer.size());if(n<0)fail(relative,"read file");if(!n)break;
                ssize_t at=0;
                while(at<n){ssize_t wrote=write(b,buffer.data()+at,n-at);if(wrote<=0)fail(relative,"write file");at+=wrote;}
                copied+=n;
            }
            if(copied!=uint64_t(s.st_size)){errno=EIO;fail(relative,"source size changed");}
            metadata(b,s,relative);close(a);close(b);
            if(s.st_nlink>1)firstLink.emplace(key,relative);
        }
        ++files;bytes+=s.st_size;
    } else {errno=EINVAL;fail(relative,"unsupported stock entry type");}
    if(++nodes%4096==0) {
        std::printf("COPY-PROGRESS nodes=%llu files=%llu dirs=%llu links=%llu bytes=%llu\n",
          (unsigned long long)nodes,(unsigned long long)files,(unsigned long long)dirs,(unsigned long long)links,(unsigned long long)bytes);
        std::fflush(stdout);
    }
}
int main(int argc,char **argv) {
    try {
        if(argc==4 && !strcmp(argv[1],"--repair-hardlinks"))return repairLinks(argv[2],argv[3]);
        if(argc!=3){std::fprintf(stderr,"usage: stock-tree-copy SOURCE-RO TARGET-EMPTY\n");return 2;}
        int source=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);destinationRoot=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        if(source<0||destinationRoot<0)fail("root","open");
        DIR *target=fdopendir(dup(destinationRoot));if(!target)fail("root","inspect target");
        while(auto *e=readdir(target))if(strcmp(e->d_name,".")&&strcmp(e->d_name,"..")){errno=EEXIST;fail("root","target not empty");}
        closedir(target);struct stat s;if(fstat(source,&s))fail("root","stat");
        copyDir(source,destinationRoot,"",s);sync();close(source);close(destinationRoot);
        std::printf("COPY-COMPLETE files=%llu directories=%llu symlinks=%llu hardlinks=%llu file_bytes=%llu\n",
          (unsigned long long)files,(unsigned long long)dirs,(unsigned long long)links,(unsigned long long)hardlinks,(unsigned long long)bytes);
        return 0;
    }catch(const std::exception &e){std::fprintf(stderr,"COPY-FAIL %s\n",e.what());return 1;}
}

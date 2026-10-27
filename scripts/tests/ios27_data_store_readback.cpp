// Execute the production seed, overlay and direct-disk readers on host artifacts.
// This is a parser/I/O contract test; it is not a UFS/APFS hardware test.
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <vector>
#include <openssl/evp.h>
#include "SeedDisk.h"
#include "PersistOverlay.h"
#include "DirectDisk.h"
#include "NativeIos27DataStoreGuard.h"

struct Store {
  std::ifstream file;
  unsigned writes = 0;
  explicit Store(const char *path) : file(path, std::ios::binary) { assert(file); }
  bool read(uint64_t b, uint32_t n, void *p) {
    file.clear(); file.seekg(b*4096); file.read(static_cast<char *>(p), uint64_t(n)*4096);
    return bool(file);
  }
  bool write(uint64_t,uint32_t,const void *) { ++writes; return false; }
  bool sync() { return false; }
};
struct Allocation {
  std::vector<uint8_t *> pages;
  uint8_t *allocate() { auto *p=new uint8_t[4096];pages.push_back(p);return p; }
  ~Allocation() { for(auto *p:pages)delete[] p; }
};
struct HashBuffer {
  EVP_MD_CTX *context;
  uint64_t done = 0;
  uint64_t read(uint64_t,void *,uint64_t) { return 0; }
  uint64_t copy(uint64_t at,const void *p,uint64_t n) {
    assert(at==done); assert(EVP_DigestUpdate(context,p,n)==1); done+=n; return n;
  }
};

int main(int argc,char **argv) {
  assert(argc==5);
  std::ifstream input(argv[1],std::ios::binary);assert(input);
  std::vector<uint8_t> encoded{std::istreambuf_iterator<char>(input),{}};
  uint64_t bytes=0,nonzero=0;
  assert(ramPackedLayout(encoded.data(),encoded.size(),&bytes));
  assert(bytes>0x80000000ULL && seedCountNonzero(encoded.data(),encoded.size(),&nonzero));
  std::vector<uint64_t> indexes(nonzero);std::vector<uint8_t *> pointers(nonzero);
  SeedDisk seed;seed.bytes=bytes;seed.capacity=nonzero;seed.index=indexes.data();seed.page=pointers.data();
  Allocation alloc;assert(seedImportSparse(seed,encoded.data(),encoded.size(),alloc));
  uint8_t identity[32];
  for(unsigned i=0;i<32;++i)identity[i]=uint8_t(std::stoul(std::string(argv[3]+2*i,2),nullptr,16));
  auto *identityContext=EVP_MD_CTX_new();assert(identityContext);uint8_t computedIdentity[32];
  seedIdentity(seed,identityContext,
    [](EVP_MD_CTX *&c){assert(EVP_DigestInit_ex(c,EVP_sha256(),nullptr)==1);},
    [](EVP_MD_CTX *&c,const void *p,size_t n){assert(EVP_DigestUpdate(c,p,n)==1);},
    [](EVP_MD_CTX *&c,uint8_t *out){unsigned n=0;assert(EVP_DigestFinal_ex(c,out,&n)==1 && n==32);},computedIdentity);
  EVP_MD_CTX_free(identityContext);assert(!memcmp(identity,computedIdentity,32));
  Store store(argv[2]);persist::Overlay overlay;
  std::vector<uint8_t> bits(persist::bitmapBlocks(bytes/4096)*4096),stage(32*4096);
  assert(zetaFullStockStoreOpen(overlay,store,bytes/4096,identity,false,bits.data(),false)==persist::Open::Resumed);
  assert(overlay.present==bytes/4096 && store.writes==0);
  auto *ctx=EVP_MD_CTX_new();assert(ctx && EVP_DigestInit_ex(ctx,EVP_sha256(),nullptr)==1);
  for(uint64_t at=0;at<bytes;at+=8ULL*1024*1024) {
    uint64_t n=std::min<uint64_t>(8ULL*1024*1024,bytes-at);HashBuffer buf{ctx};bool error=false;
    assert(directDiskIO(seed,overlay,store,stage.data(),32,false,at,n,buf,&error)==n && !error);
  }
  uint8_t hash[32];unsigned length=0;assert(EVP_DigestFinal_ex(ctx,hash,&length)==1 && length==32);EVP_MD_CTX_free(ctx);
  std::ostringstream hex;for(auto v:hash)hex<<std::hex<<std::setfill('0')<<std::setw(2)<<unsigned(v);
  assert(hex.str()==argv[4]);
  // A different seed cannot silently accept this complete Data store.
  identity[0]^=1;persist::Overlay wrong;std::vector<uint8_t> wrongbits(bits.size());
  assert(zetaFullStockStoreOpen(wrong,store,bytes/4096,identity,false,wrongbits.data(),false)==persist::Open::Failed && !wrong.active);
  assert(store.writes==0);
  std::cout<<"PASS production DirectDisk: "<<bytes<<" bytes, full SHA256="<<hex.str()
           <<", seed metadata resident="<<seed.resident<<", no writes, wrong-seed refused\n";
}

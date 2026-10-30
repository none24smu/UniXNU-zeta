"""Ad-hoc owner launchd data-cache signing; executable admission is separate."""
import hashlib
import struct

def sign_owner_cache(data, template):
    """Rebuild the existing ad-hoc detached signature for the owner RAM cache.

    Retain requirements/special slots and both SHA-1/SHA-256 directories. The
    new SHA-256 CDHash must be explicitly admitted by this image's static trust
    bundle; page validation remains enabled.
    """
    magic,length,count=struct.unpack_from(">3I",template)
    assert magic==0xfade0cc0 and length==len(template)
    blobs=[];cdhash=None
    for i in range(count):
        kind,offset=struct.unpack_from(">II",template,12+8*i)
        blob_magic,size=struct.unpack_from(">II",template,offset)
        blob=bytearray(template[offset:offset+size]);assert len(blob)==size
        if blob_magic==0xfade0c02:
            _,_,version,flags,hash_offset,ident,special,slots,limit,hash_size,hash_type,platform,page=struct.unpack_from(">9I4B",blob)
            assert flags&2 and page==12 and platform==0 and version==0x20500
            assert (hash_type,hash_size) in ((1,20),(2,32))
            assert hash_offset+slots*hash_size==len(blob)
            name=b"zeta-air-owner-launchd-cache\0"
            end=hash_offset-special*hash_size
            assert ident+len(name)<=end
            blob[ident:end]=name+b"\0"*(end-ident-len(name))
            slots=(len(data)+4095)//4096
            blob=blob[:hash_offset]
            digest=hashlib.sha1 if hash_type==1 else hashlib.sha256
            blob.extend(b"".join(digest(data[n:n+4096]).digest() for n in range(0,len(data),4096)))
            struct.pack_into(">I",blob,4,len(blob))
            struct.pack_into(">II",blob,28,slots,len(data))
            # The template uses the 32-bit codeLimit and no scatter/pre-encrypt
            # table. Refuse a different layout rather than retaining stale data.
            assert struct.unpack_from(">IIQ",blob,44)==(0,0,0)
            if hash_type==2:cdhash=hashlib.sha256(blob).digest()[:20]
        elif kind==0x10000:
            assert blob==struct.pack(">II",0xfade0b01,8), "Only ad-hoc signatures are supported"
        blobs.append((kind,bytes(blob)))
    assert cdhash is not None
    cursor=12+8*len(blobs);indices=[]
    for kind,blob in blobs:indices.append(struct.pack(">II",kind,cursor));cursor+=len(blob)
    return struct.pack(">III",magic,cursor,len(blobs))+b"".join(indices)+b"".join(blob for _,blob in blobs),cdhash


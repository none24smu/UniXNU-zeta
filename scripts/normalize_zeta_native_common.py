"""Small offline evidence helpers; no runtime reader or phone commands."""
import hashlib
from pathlib import Path
import struct


def require(value,message):
    if not value:raise ValueError(message)


def record(path):
    path=Path(path).resolve();data=path.read_bytes()
    return {'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}


def unique(rows,kind):
    found=[r for r in rows if r.get('kind')==kind]
    require(len(found)==1,'missing/duplicate '+kind);return found[0]


def mach_window(data,address,size):
    require(struct.unpack_from('<I',data)[0]==0xfeedfacf,'kernel is not 64-bit Mach-O')
    ncmds,cmdsize=struct.unpack_from('<II',data,16);at=32;end=at+cmdsize
    require(end<=len(data),'Mach-O command range')
    for _ in range(ncmds):
        command,length=struct.unpack_from('<II',data,at);require(length>=8 and at+length<=end,'Mach-O command bounds')
        if command==0x19:
            va,vm_size,offset,file_size=struct.unpack_from('<4Q',data,at+24)
            if va<=address and address+size<=va+file_size:
                require(offset+address-va+size<=len(data),'Mach-O source segment bounds')
                return data[offset+address-va:offset+address-va+size]
        at+=length
    raise ValueError('runtime window is not backed by selected kernel file')

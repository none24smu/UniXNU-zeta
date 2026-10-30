#!/usr/bin/env python3
"""Repack the pinned RAM-only firmware with a 64MiB ADT ReadFile limit.

Requires the retained loader71 firmware inputs and its uefi_firmware tooling.
All 91 untargeted firmware files and the appended device tree remain exact.
"""
from pathlib import Path
import argparse,sys,struct,uuid,json,hashlib,zlib,gzip
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--inputs',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();D=a.inputs.resolve();O=a.output.resolve()
assert not O.exists();O.mkdir(parents=True)
sys.path.insert(0,str(D/'tooling'));import uefi_firmware as u
raw=(D/'firmware-uncompressed-control.bin').read_bytes();original=(D/'firmware-kernel-control.bin').read_bytes();geom=json.loads((D/'firmware-geometry.json').read_text());assert geom['gzip_offset']==0 and len(raw)==2097344
outer=u.uefi.FirmwareVolume(raw[192:]);assert outer.process();outer_file=outer.firmware_filesystems[0].files[1];section=outer_file.sections[0];guided=section.parsed_object;assert str(uuid.UUID(bytes_le=guided.guid))=='ee4e5898-3914-4259-9d6e-dc7bd79403cf'and guided.attr_mask==1 and guided.offset==24
inner=guided.subsections[1].parsed_object;innerraw=inner._data[:inner.size];pe=(D/'DarwinBoot-control.efi').read_bytes();assert innerraw.count(pe)==1;pe_in_inner=innerraw.index(pe);assert innerraw[pe_in_inner-28:pe_in_inner-12]==uuid.UUID('1b64af87-8415-4b57-9b16-680d70913b9f').bytes_le
pg=json.loads((D/'loader-pe-geometry.json').read_text());assert pg['protocols']==[{'protocol_fileoff':32816,'boot_va':4860}]
def fileoff(va):
 s=next(s for s in pg['sections']if s['rva']<=va<s['rva']+s['size']);return s['offset']+va-s['rva']
# Pin the entire original PE, then validate all three bounded ReadFile calls.
assert hashlib.sha256(pe).hexdigest()=='47e5d262c2229f701f411ffc0569b09ca9507f047781953cf5f73fbf00bb9962'
assert hashlib.sha256(original).hexdigest()=='896c04709f4247302399d36b42104e421e2306355171ec705dbec4cda5d036c1'
pcs=[0x149c,0x1a94,0x1c14];loads=[0x52a10002,0x52a02002,0x52a02002];targets=[]
for pc,word in zip(pcs,loads):
 assert struct.unpack_from('<I',pe,fileoff(pc))[0]==word
 for delta in range(4,68,4):
  call=struct.unpack_from('<I',pe,fileoff(pc+delta))[0]
  if call&0xfc000000==0x94000000:
   imm=call&0x3ffffff;imm-=0x4000000 if imm&0x2000000 else 0
   targets.append(pc+delta+4*imm);break
 else:raise ValueError('ReadFile BL absent')
assert len(set(targets))==1
at=fileoff(pcs[1]);assert at==0xe94
newpe=bytearray(pe);struct.pack_into('<I',newpe,at,0x52a08002);newpe=bytes(newpe)
assert sum(a!=b for a,b in zip(pe,newpe))==1
assert struct.unpack_from('<I',newpe,fileoff(pcs[0]))[0]==loads[0]
assert struct.unpack_from('<I',newpe,fileoff(pcs[2]))[0]==loads[2]
# This FFS file has checksum-disabled data integrity0xaa. Size/header stay exact.
file=next(f for f in inner.firmware_filesystems[0].files if f.guid==uuid.UUID('1b64af87-8415-4b57-9b16-680d70913b9f').bytes_le);assert not file.attributes&0x40 and file.checksum>>8==0xaa
newinner=innerraw[:pe_in_inner]+newpe+innerraw[pe_in_inner+len(pe):];assert len(newinner)==len(innerraw) and sum(a!=b for a,b in zip(innerraw,newinner))==1
assert guided.data.count(innerraw)==1;pos=guided.data.index(innerraw);newdata=guided.data[:pos]+newinner+guided.data[pos+len(innerraw):]
assert len(newdata)==len(guided.data)and sum(a!=b for a,b in zip(newdata,guided.data))==1
compressed=u.efi_compressor.LzmaCompress(newdata,len(newdata));assert u.efi_compressor.LzmaDecompress(compressed,len(compressed))==newdata
# Rebuild only the containing GUIDed section and second outer FFS file.
oldsection=section._data[:section.size];assert oldsection[3]==2;newsection=bytes(3)+oldsection[3:24]+compressed;newsection=len(newsection).to_bytes(3,'little')+newsection[3:]
outer_bytes=raw[192:];guid=outer_file.guid;starts=[];start=0
while True:
 i=outer_bytes.find(guid,start)
 if i<0:break
 starts.append(i);start=i+1
assert starts==[65536];fs=starts[0];oldsize=int.from_bytes(outer_bytes[fs+20:fs+23],'little');assert oldsize==outer_file.size and outer_bytes[fs+24:fs+oldsize]==oldsection
assert set(outer_bytes[fs+oldsize:])=={255};header=bytearray(outer_bytes[fs:fs+24]);newsize=24+len(newsection);assert newsize<0xffffff and fs+newsize<len(outer_bytes);header[20:23]=newsize.to_bytes(3,'little');assert not header[19]&0x40 and header[17]==0xaa
header[16]=0;copy=bytearray(header);copy[17]=0;copy[23]=0;header[16]=(-sum(copy))&255;assert (sum(header)-header[17]-header[23])&255==0
newouter=outer_bytes[:fs]+bytes(header)+newsection+bytes([255])*(len(outer_bytes)-fs-newsize);assert len(newouter)==len(outer_bytes)
newraw=raw[:192]+newouter;newv=u.uefi.FirmwareVolume(newouter);assert newv.process();newg=newv.firmware_filesystems[0].files[1].sections[0].parsed_object;assert newg.data==newdata
# Verify every untargeted inner firmware file byte-for-byte through the parser.
newiv=newg.subsections[1].parsed_object;oldfiles=inner.firmware_filesystems[0].files;newfiles=newiv.firmware_filesystems[0].files;assert len(oldfiles)==len(newfiles)==92
for old,new in zip(oldfiles,newfiles):
 assert old.guid==new.guid
 if old.guid!=file.guid:assert old._data[:old.size]==new._data[:new.size]
newgzip=gzip.compress(newraw,compresslevel=9,mtime=0);zd=zlib.decompressobj(31);assert zd.decompress(newgzip)+zd.flush()==newraw and not zd.unused_data
newkernel=newgzip+(D/'firmware-gzip-tail.bin').read_bytes();assert original[-743107:]==newkernel[-743107:]
for name,data in [('DarwinBoot-adt64.efi',newpe),('inner-fv-adt64.bin',newinner),('firmware-uncompressed-adt64.bin',newraw),('Image.gz-dtb',newkernel)]:assert not(O/name).exists();(O/name).write_bytes(data)
r=dict(result='pass',scope='Only embedded DarwinBoot ADT ReadFile16->64MiB instruction; other ReadFile limits and firmware modules preserved',original_pe_sha256=hashlib.sha256(pe).hexdigest(),patched_pe_sha256=hashlib.sha256(newpe).hexdigest(),PE_file_offset=at,PE_rva=hex(pcs[1]),before_word='0x52a02002',after_word='0x52a08002',changed_uncompressed_PE_bytes=1,actual_PE_guard_matched=True,untargeted_firmware_files_exact=91,inner_FV_changed_bytes=1,outer_first_FFS_exact=outer_bytes[72:fs]==newouter[72:fs],outer_volume_size_unchanged=True,header_checksum_verified=True,compression_roundtrip_exact=True,original_device_tree_tail_exact=True,original_kernel_sha256=hashlib.sha256(original).hexdigest(),patched_kernel_sha256=hashlib.sha256(newkernel).hexdigest(),native_execution=False)
(O/'firmware-patch-proof.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))

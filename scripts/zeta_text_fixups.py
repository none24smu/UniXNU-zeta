"""Strict format for the optional post-validation iOS27 text-fixup table."""
import re

MAX_ENTRIES=262144
MAX_FILES=512
MAX_BYTES=16
PAGE_SIZE=4096


def parse_table(blob):
    if not blob or len(blob)>MAX_ENTRIES*160 or not blob.endswith(b'\0'):
        raise ValueError('iOS27 fixup table must be bounded and NUL terminated')
    records=[];names=set();previous=None
    for raw in blob[:-1].split(b'\0'):
        if not raw or len(raw)>=160:
            raise ValueError('empty or oversized iOS27 fixup descriptor')
        fields=raw.decode('ascii').split(',')
        if len(fields)!=4 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,63}',fields[0]) or not re.fullmatch(r'[0-9a-fA-F]{1,16}',fields[1]):
            raise ValueError('malformed iOS27 fixup name/offset/fields')
        name,offset=fields[0],int(fields[1],16)
        for value in fields[2:]:
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,16}',value):
                raise ValueError('malformed iOS27 fixup bytes')
        before,after=bytes.fromhex(fields[2]),bytes.fromhex(fields[3])
        if len(before)!=len(after) or offset>(1<<64)-1-len(before) or offset%PAGE_SIZE+len(before)>PAGE_SIZE:
            raise ValueError('iOS27 fixup overflow/length/page boundary')
        if previous and (name<previous[0] or (name==previous[0] and offset<previous[1]+len(previous[2]))):
            raise ValueError('iOS27 fixup table is unsorted or overlapping')
        record=(name,offset,before,after);records.append(record);names.add(name);previous=record
        if len(records)>MAX_ENTRIES or len(names)>MAX_FILES:
            raise ValueError('iOS27 fixup table exceeds entry/file capacity')
    return records


def encode_table(records):
    blob=b''.join(f'{name},{offset:x},{before.hex()},{after.hex()}'.encode('ascii')+b'\0' for name,offset,before,after in records)
    parse_table(blob)
    return blob

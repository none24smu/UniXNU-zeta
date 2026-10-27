#!/usr/bin/env python3
"""Publish fresh unsealed-template UUIDs only after all stock readback gates."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import uuid
import zeta_apfs_image as apfs

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tree',type=Path,required=True)
    p.add_argument('--output-directory',type=Path,required=True);a=p.parse_args();items=[]
    for root_name,label in [('main','OS'),('system','SystemOS'),('app','AppOS')]:
        directory=a.tree/root_name;gate_path=directory/'completeness-metadata-gate.json'
        gate=json.loads(gate_path.read_text());n=json.loads((directory/'native-normalization.json').read_text());image=directory/'normalized.apfs'
        if (not gate.get('stock_payload_complete') or not gate.get('normalized_file_metadata_qualified') or gate.get('failures') or
                not n.get('native_hardlink_equivalence_verified') or n.get('full_decoded_data_readback_pending',True)):
            raise ValueError(root_name+': full decoded/native metadata/hardlink readback required')
        if image.stat().st_mtime_ns>gate_path.stat().st_mtime_ns:raise ValueError('image changed after qualification')
        with image.open('rb') as f:
            c=apfs.Container(f);v,=c.volumes();identity=str(uuid.UUID(bytes=v.superblock[0xf0:0x100])).upper()
            if v.incompatible&0x20:raise ValueError('template must be unsealed')
            allocated=struct.unpack_from('<Q',v.superblock,0x58)[0]*c.block_size
        items.append(dict(name=label,root_name=root_name,source=str(image.resolve()),source_bytes=image.stat().st_size,
            source_sha256=n['output_sha256'],volume_uuid=identity,native_allocated_bytes=allocated,
            metadata_gate=str(gate_path.resolve()),metadata_gate_sha256=hashlib.sha256(gate_path.read_bytes()).hexdigest(),
            hardlink_groups=n['native_hardlink_groups_preserved'],hardlink_aliases=n['native_hardlink_aliases_preserved']))
    if len({x['volume_uuid'] for x in items})!=3:raise ValueError('ambiguous fresh volume UUIDs')
    if a.output_directory.exists():raise ValueError('refuse existing published input profile')
    a.output_directory.mkdir(parents=True)
    result=dict(schema='zeta-ios27-qualified-unsealed-inputs-v1',windows=items,all_three_namespaces_preserved=True,
        owner_scaffold_in_main=True,all_file_content_and_metadata_gates_passed=True,
        original_images_unchanged=True,isa_converted=False,signed_storage_assembled=False,
        native_mount_verified=False,boot_qualified=False,phone_modified=False,
        volume_semantics='new generic role0/feature0x2 owner filesystems; no stock volume-group role/feature semantics are fabricated')
    (a.output_directory/'qualified-inputs.json').write_text(json.dumps(result,indent=2)+'\n')
    (a.output_directory/'NativeIos27StorageProfile.h').write_text('/* Qualified complete stock template inputs; not a deployment claim. */\n#pragma once\n'+''.join(
        f'#define ZETA_IOS27_{x["name"].upper()}_VOLUME_UUID "{x["volume_uuid"]}"\n' for x in items))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()

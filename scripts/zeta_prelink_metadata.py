"""Preserve real kext personalities and source-backed dependency interfaces."""
import base64
import copy
import hashlib
import plistlib
import re
import xml.etree.ElementTree as ET

from zeta_prelink_layout import require, translate

KPI_TEMPLATES = ('BSDKernel', 'MACFramework', 'IOKit', 'Libkern', 'Mach', 'Private', 'Unsupported')


def read_plist(path):
    data = path.read_bytes()
    # The immutable source crypto plist has a license comment before its XML
    # declaration. plistlib requires the declaration to be first.
    if b'<?xml' in data:
        data = data[data.index(b'<?xml'):]
    return plistlib.loads(data)


def xml_value(value):
    if isinstance(value, dict):
        node = ET.Element('dict')
        for key, item in value.items():
            ET.SubElement(node, 'key').text = key
            node.append(xml_value(item))
        return node
    if isinstance(value, list):
        node = ET.Element('array')
        node.extend(xml_value(item) for item in value)
        return node
    if isinstance(value, bool):
        return ET.Element('true' if value else 'false')
    if isinstance(value, int):
        require(0 <= value < 1 << 64, 'prelink integer outside unsigned64')
        node = ET.Element('integer', {'size': '64'})
        node.text = hex(value)
        return node
    if isinstance(value, bytes):
        node = ET.Element('data')
        node.text = base64.b64encode(value).decode()
        return node
    require(isinstance(value, str), 'unsupported prelink metadata value')
    node = ET.Element('string')
    node.text = value
    return node


def replace_versions(value, version):
    if isinstance(value, str):
        return value.replace('###KERNEL_VERSION_LONG###', version).replace('###KERNEL_VERSION_SHORT###', version)
    if isinstance(value, dict):
        return {key: replace_versions(child, version) for key, child in value.items()}
    if isinstance(value, list):
        return [replace_versions(child, version) for child in value]
    return value


def encode(metadata):
    # XNU's getTag accepts <true/> but rejects ElementTree's <true />:
    # after skipping whitespace it expects an attribute '=' even at '/'.
    # Text '<' is escaped by ElementTree, so only actual empty tags match.
    xml = ET.tostring(xml_value(metadata), encoding='utf-8')
    return re.sub(rb'<(dict|array|true|false|data|string|key) />', rb'<\1/>', xml) + b'\0'


def native_release(native):
    symbols = [s for s in native.symbols if s['name'] == '_osrelease' and s['section']]
    require(len(symbols) == 1, 'expected native osrelease constant')
    at = native.file_at(symbols[0]['address'], 16)
    value = native.data[at:at + 32].split(b'\0', 1)[0].decode()
    require(re.fullmatch(r'\d+\.\d+\.\d+', value), 'unsupported native release string')
    return value


def build(native, modules, layout, index, xnu_source, storage_source, crypto_source):
    version = native_release(native)
    entries, provenance = [], {}
    for template in KPI_TEMPLATES:
        path = xnu_source / f'config/System.kext/PlugIns/{template}.kext/Info.plist'
        entry = replace_versions(read_plist(path), version)
        require(entry['OSKernelResource'] is True and entry['CFBundleVersion'] == version,
                'unexpected native KPI template')
        entries.append(entry)
        provenance[entry['CFBundleIdentifier']] = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    source_plists = (
        ('com.apple.iokit.IOStorageFamily', storage_source / 'Info.plist', '2.1'),
        ('com.apple.kec.corecrypto', crypto_source / 'corecrypto_kext/corecrypto_kext-Info.plist', '14.0'),
    )
    for identifier, path, expected in source_plists:
        original = read_plist(path)
        require(original['CFBundleVersion'] == expected and original['OSBundleCompatibleVersion'] == '1.0',
                f'unaudited source provider version: {identifier}')
        # Native code supplies the implementation and initializes it through
        # its existing bootstrap. This interface must never carry a second
        # executable, constructor list or duplicate IOKit personalities.
        entry = dict(CFBundleIdentifier=identifier, CFBundleVersion=expected,
                     OSBundleCompatibleVersion='1.0',
                     CFBundlePackageType='KEXT', CFBundleExecutable='native_source_interface',
                     OSKernelResource=True, OSBundleIsInterface=True, OSBundleRequired='Root')
        entries.append(entry)
        provenance[identifier] = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    for identifier, image in sorted(modules.items()):
        path = index[identifier]['plist_path']
        original = read_plist(path)
        entry = copy.deepcopy(original)
        require(entry['CFBundleIdentifier'] == identifier, 'module metadata identity mismatch')
        text = layout['mapping'][identifier]['__TEXT']
        kmods = [s for s in image.symbols if s['name'] == '_kmod_info' and s['section']]
        require(len(kmods) == 1, 'expected one packed kmod record')
        entry.update(_PrelinkExecutableLoadAddr=text['new_va'],
                     _PrelinkExecutableSourceAddr=text['new_va'],
                     _PrelinkExecutableSize=text['original_filesize'],
                     _PrelinkKmodInfo=translate(layout, identifier, kmods[0]['address'], 196),
                     _PrelinkBundlePath=f'/System/Library/Extensions/{path.parent.parent.name}',
                     _PrelinkExecutableRelativePath='Contents/MacOS/' + original['CFBundleExecutable'])
        require(entry.get('IOKitPersonalities') == original.get('IOKitPersonalities'), 'driver personalities changed')
        entries.append(entry)
        provenance[identifier] = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    identifiers = [entry['CFBundleIdentifier'] for entry in entries]
    require(len(entries) == len(modules) + 9 and len(set(identifiers)) == len(entries), 'incorrect prelink entry set')
    for entry in entries:
        require(set(entry.get('OSBundleLibraries', {})) <= set(identifiers), 'metadata dependency outside included providers')
    identity = hashlib.sha256((native.identity['sha256'] + ''.join(
        modules[key].identity['sha256'] for key in sorted(modules))).encode()).digest()[:16]
    metadata = dict(_PrelinkInfoDictionary=entries, _PrelinkKCID=identity)
    encoded = encode(metadata)
    info = layout['groups'][-1]
    require(len(encoded) <= info['size'], 'serialized metadata exceeds reserved segment')
    return metadata, encoded, provenance

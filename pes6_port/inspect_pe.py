"""Inventory a PE32 game binary without executing it."""
import argparse
import hashlib
import json
import struct
from pathlib import Path


def inspect(path):
    data = path.read_bytes()
    if data[:2] != b'MZ' or len(data) < 64:
        raise ValueError('Not an MZ executable')
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Invalid PE signature')
    machine, count, timestamp, _, _, optional_size, characteristics = struct.unpack_from('<HHIIIHH', data, pe + 4)
    optional = pe + 24
    if struct.unpack_from('<H', data, optional)[0] != 0x10b:
        raise ValueError('Expected PE32')
    base = struct.unpack_from('<I', data, optional + 28)[0]
    entry = base + struct.unpack_from('<I', data, optional + 16)[0]
    sections = []
    for index in range(count):
        start = optional + optional_size + index * 40
        name = data[start:start + 8].split(b'\0')[0].decode('ascii', errors='replace')
        virtual_size, rva, raw_size, offset = struct.unpack_from('<4I', data, start + 8)
        assert offset + raw_size <= len(data)
        flags = struct.unpack_from('<I', data, start + 36)[0]
        sections.append({'name': name, 'address': hex(base + rva), 'rva': rva,
                         'virtual_size': virtual_size, 'file_offset': offset,
                         'file_size': raw_size, 'executable': bool(flags & 0x20000000)})

    def offset_for(rva):
        for section in sections:
            delta = rva - section['rva']
            if 0 <= delta < section['file_size']:
                return section['file_offset'] + delta
        raise ValueError(f'RVA {rva:x} has no file-backed section')

    def cstring(rva):
        start = offset_for(rva)
        end = data.find(b'\0', start, min(start + 1024, len(data)))
        if end < 0:
            raise ValueError('Unterminated string')
        return data[start:end].decode('ascii', errors='replace')

    imports = []
    import_rva, import_size = struct.unpack_from('<II', data, optional + 104)
    if import_rva:
        start = offset_for(import_rva)
        for index in range(4096):
            original, _, _, name, thunk = struct.unpack_from('<5I', data, start + index * 20)
            if not any((original, name, thunk)):
                break
            symbols = []
            thunk_offset = offset_for(original or thunk)
            for slot in range(65536):
                value = struct.unpack_from('<I', data, thunk_offset + slot * 4)[0]
                if value == 0:
                    break
                symbols.append('ordinal_' + str(value & 0xffff) if value & 0x80000000 else cstring(value + 2))
            imports.append({'dll': cstring(name), 'symbols': symbols})
    signatures = [
        ('PES6 PC', 0x77dca8, '{20418978-752D-491c-AF1E-A2EDE086E000}'),
        ('PES6 PC 1.10', 0x77eca8, '{20418978-752D-491c-AF1E-A2EDE086E000}'),
        ('WE-PES 2007 PC', 0x77eca8, '{EEF9975D-2F76-42c6-AC44-8F84C6B4E68D}')]
    matches = [label for label, offset, guid in signatures if data[offset:offset + len(guid)] == guid.encode()]
    return {'path': str(path), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'machine': hex(machine), 'image_base': hex(base), 'entry': hex(entry),
            'timestamp': timestamp, 'sections': sections, 'imports': imports,
            'kitserver_file_signature_matches': matches,
            'signature_source': 'https://github.com/kitserver/kitserver6/blob/master/src/detect.cpp',
            'runtime_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = inspect(args.binary)
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k not in ('sections', 'imports')}, indent=2))
    print('Imports:', ', '.join(x['dll'] for x in result['imports']))


if __name__ == '__main__':
    main()

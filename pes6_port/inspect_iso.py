"""Read ISO9660 metadata locally or through validated HTTP byte ranges.

Does not decrypt, execute, or publish game files. Extracts only SYSTEM.CNF
and the boot executable when --extract-boot is requested.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path


class Source:
    def __init__(self, location, prefix_cache=None, range_cache=None):
        self.location = location
        self.remote = location.startswith(('https://', 'http://'))
        self.prefix_cache = Path(prefix_cache) if prefix_cache else None
        self.range_cache = range_cache

    def read(self, offset, size):
        if size == 0:
            return b''
        if self.prefix_cache and self.prefix_cache.stat().st_size >= offset + size:
            with self.prefix_cache.open('rb') as stream:
                stream.seek(offset)
                return stream.read(size)
        if self.remote:
            cache = None
            if self.range_cache:
                self.range_cache.mkdir(parents=True, exist_ok=True)
                key = hashlib.sha256(self.location.encode()).hexdigest()[:16]
                cache = self.range_cache / f'{key}-{offset}-{size}.bin'
                if cache.is_file() and cache.stat().st_size == size:
                    return cache.read_bytes()
            req = urllib.request.Request(self.location, headers={
                'Range': f'bytes={offset}-{offset + size - 1}',
                'Accept-Encoding': 'identity'})
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=45) as response:
                        expected = f'bytes {offset}-{offset + size - 1}/'
                        if response.status != 206 or not response.headers.get('Content-Range', '').startswith(expected):
                            raise ValueError('Server did not honor the exact byte range')
                        data = response.read(size + 1)
                    break
                except (urllib.error.URLError, TimeoutError) as error:
                    if attempt == 2:
                        raise
                    print(f'Retrying read at {offset}: {error}', file=sys.stderr, flush=True)
        else:
            with open(self.location, 'rb') as stream:
                stream.seek(offset)
                data = stream.read(size)
        if len(data) != size:
            raise ValueError(f'Truncated read at {offset}: expected {size}, got {len(data)}')
        if self.remote and cache:
            cache.write_bytes(data)
        return data


def record(data):
    name = data[33:33 + data[32]]
    return {'name': name.decode('ascii', errors='replace').split(';')[0],
            'lba': struct.unpack_from('<I', data, 2)[0],
            'size': struct.unpack_from('<I', data, 10)[0],
            'directory': bool(data[25] & 2)}


def inventory(source):
    pvd = None
    for sector in range(16, 80):
        descriptor = source.read(sector * 2048, 2048)
        if descriptor[1:6] != b'CD001':
            raise ValueError('Not a valid ISO9660 descriptor')
        if descriptor[0] == 1:
            pvd = descriptor
            break
        if descriptor[0] == 255:
            break
    if pvd is None:
        raise ValueError('Primary volume descriptor not found')
    block_size = struct.unpack_from('<H', pvd, 128)[0]
    if block_size != 2048:
        raise ValueError(f'Unsupported block size: {block_size}')
    files, visited = [], set()

    def walk(directory, prefix=''):
        key = (directory['lba'], directory['size'])
        if key in visited:
            return
        visited.add(key)
        if directory['size'] > 16 * 1024 * 1024:
            raise ValueError('Unexpectedly large directory')
        data = source.read(directory['lba'] * block_size, directory['size'])
        cursor = 0
        while cursor < len(data):
            length = data[cursor]
            if length == 0:
                cursor = (cursor // block_size + 1) * block_size
                continue
            raw = data[cursor:cursor + length]
            if len(raw) != length or length < 34:
                raise ValueError('Malformed directory record')
            entry = record(raw)
            cursor += length
            if raw[33:33 + raw[32]] in (b'\x00', b'\x01'):
                continue
            entry['path'] = prefix + entry.pop('name')
            files.append(entry)
            if entry['directory']:
                walk(entry, entry['path'] + '/')

    walk(record(pvd[156:190]))
    return {'volume_id': pvd[40:72].decode('ascii').strip(),
            'declared_bytes': struct.unpack_from('<I', pvd, 80)[0] * block_size,
            'files': files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extract-boot', action='store_true')
    parser.add_argument('--prefix-cache', type=Path, help='Existing contiguous prefix of the same ISO')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = Source(args.source, args.prefix_cache, args.output / 'range-cache')
    result = inventory(source)
    result['source'] = args.source
    for entry in result['files']:
        if entry['directory']:
            continue
        print('Inspecting ' + entry['path'], file=sys.stderr, flush=True)
        header = source.read(entry['lba'] * 2048, min(64, entry['size']))
        entry['header_hex'] = header[:16].hex()
        if header.startswith(b'AFS\x00'):
            count = struct.unpack_from('<I', header, 4)[0]
            if count > 1000000 or 8 + count * 8 > entry['size']:
                raise ValueError('Invalid AFS entry count')
            table = source.read(entry['lba'] * 2048 + 8, count * 8)
            items = []
            for i in range(count):
                offset, size = struct.unpack_from('<II', table, i * 8)
                if offset + size > entry['size']:
                    raise ValueError('AFS entry extends outside archive')
                items.append({'index': i, 'offset': offset, 'size': size})
            entry['afs_entries'] = count
            (args.output / (Path(entry['path']).name + '.entries.json')).write_text(json.dumps(items, indent=2))
    boot = next((e for e in result['files'] if e['path'].upper() == 'SYSTEM.CNF'), None)
    if boot:
        cnf = source.read(boot['lba'] * 2048, boot['size'])
        result['system_cnf'] = cnf.decode('ascii', errors='replace')
        match = re.search(r'BOOT2\s*=\s*cdrom0:\\([^;\r\n]+)', result['system_cnf'], re.I)
        if match:
            name = match.group(1).replace('\\', '/')
            executable = next(e for e in result['files'] if e['path'].upper() == name.upper())
            result['boot_executable'] = executable['path']
            if args.extract_boot:
                data = source.read(executable['lba'] * 2048, executable['size'])
                result['boot_sha256'] = hashlib.sha256(data).hexdigest()
                (args.output / Path(name).name).write_bytes(data)
                (args.output / 'SYSTEM.CNF').write_bytes(cnf)
                if data[:6] == b'\x7fELF\x01\x01':
                    fields = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
                    result['elf'] = {'bits': 32, 'endian': 'little', 'machine': fields[1],
                                     'entry': hex(fields[3]), 'flags': hex(fields[6]),
                                     'program_headers': fields[9], 'section_headers': fields[11]}
    (args.output / 'inventory.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != 'files'}, indent=2))
    for entry in result['files']:
        print(entry['path'], entry['size'], 'AFS entries=' + str(entry.get('afs_entries', '-')))


if __name__ == '__main__':
    main()

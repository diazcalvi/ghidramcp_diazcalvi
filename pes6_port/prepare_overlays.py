"""Extract MWo3 overlays and synthesize analysis-only ELF containers.

The inferred size fields are checked against every payload. These containers
are not playable rebuilt games. They combine the original main load segment
with one overlay, allowing cross-references at their observed guest addresses.
"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent / 'results'


def main():
    archive = (ROOT / 'OVER.AFS').read_bytes()
    table = json.loads((ROOT / 'OVER.AFS.entries.json').read_text())
    boot = (ROOT / 'SLES_542.03').read_bytes()
    phoff = struct.unpack_from('<I', boot, 28)[0]
    phsize, phcount = struct.unpack_from('<HH', boot, 42)
    loads = [struct.unpack_from('<8I', boot, phoff + i * phsize) for i in range(phcount)]
    primary = next(p for p in loads if p[0] == 1 and p[1] and p[4])
    original = boot[primary[1]:primary[1] + primary[4]]
    result = []
    out = ROOT / 'overlay-analysis-elf'
    out.mkdir(exist_ok=True)
    for item in table:
        blob = archive[item['offset']:item['offset'] + item['size']]
        magic, ident, base, code_size, data_size, zero_size, end1, end2 = struct.unpack_from('<8I', blob)
        assert magic == 0x336f574d and len(blob) == item['size']
        name = blob[32:128].split(b'\0')[0].decode('ascii')
        assert name.endswith('.ovl') and '/' not in name and '\\' not in name
        file_bytes = end2 - base
        assert end1 == end2
        assert file_bytes == 64 + code_size + data_size
        assert 128 <= file_bytes <= len(blob)
        assert file_bytes + zero_size <= 32 * 1024 * 1024
        assert base >= primary[2] + primary[5]
        # Three PT_LOAD segments: core, overlay header/code, overlay data/BSS.
        offset_core = 4096
        offset_overlay = (offset_core + len(original) + 4095) & ~4095
        text_bytes = 64 + code_size
        segments = [
            (1, offset_core, primary[2], primary[3], len(original), primary[5], 7, 1),
            (1, offset_overlay, base, base, text_bytes, text_bytes, 5, 1),
            (1, offset_overlay + text_bytes, base + text_bytes, base + text_bytes,
             data_size, data_size + zero_size, 6, 1),
        ]
        header = b'\x7fELF\x01\x01\x01' + bytes(9)
        header += struct.pack('<HHIIIIIHHHHHH', 2, 8, 1, base + 128, 52, 0,
                              struct.unpack_from('<I', boot, 36)[0], 52, 32, 3, 40, 0, 0)
        header += b''.join(struct.pack('<8I', *p) for p in segments)
        image = header.ljust(offset_core, b'\0') + original
        image = image.ljust(offset_overlay, b'\0') + blob[:file_bytes]
        dest = out / (name + '.elf')
        dest.write_bytes(image)
        result.append({'index': item['index'], 'name': name, 'id': ident,
            'load_base': hex(base), 'initialized_end': hex(end2),
            'inferred_header_plus_code_bytes': text_bytes,
            'inferred_data_bytes': data_size, 'inferred_zero_bytes': zero_size,
            'candidate_first_function': hex(base + 128),
            'contains_code_candidate': any(blob[128:text_bytes]),
            'sha256': hashlib.sha256(blob).hexdigest(),
            'analysis_container': str(dest), 'runtime_verified': False})
    (ROOT / 'overlay-layout.json').write_text(json.dumps(result, indent=2))
    print(f'Validated all {len(result)} MWo3 layouts and created analysis-only ELFs.')


if __name__ == '__main__':
    main()

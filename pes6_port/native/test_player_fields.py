"""Differentially compare the C port against the pinned original x86 binary.

Runs only the isolated copy routine under Unicorn, not the game executable.
Requires unicorn, and a C compiler. Builds the shared library locally.
"""
import ctypes
import hashlib
import json
import random
import struct
import subprocess
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EFLAGS, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parent
GAME = ROOT.parent / 'windows/nocd/pes6.exe'
EXPECTED = 'f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'


def main():
    raw = GAME.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED, 'Wrong reference executable'
    info = json.loads((ROOT.parent / 'windows/pe-inventory.json').read_text())
    start = 0x00a4b040
    section = next(s for s in info['sections'] if int(s['address'], 16) <= start < int(s['address'], 16) + s['file_size'])
    offset = section['file_offset'] + start - int(section['address'], 16)
    code = raw[offset:offset + 0x200]
    library = ROOT / 'libpes6_player_fields.so'
    subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-shared', '-fPIC', str(ROOT / 'pes6_player_fields.c'),
                    '-o', str(library)], check=True)
    fn = ctypes.CDLL(str(library)).pes6_pc_copy_player_fields
    fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint16]
    fn.restype = ctypes.c_void_p

    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(start & ~0xfff, 4096)
    machine.mem_write(start, code)
    memory, stack, sentinel = 0x03000000, 0x02008000, 0x01000000
    machine.mem_map(memory, 4096)
    machine.mem_map(stack & ~0xffff, 65536)
    machine.mem_map(sentinel, 4096)
    rng = random.Random(0x50455336)
    cases = 10000
    boundaries = [0, 25, 26, 27, 30, 31, 511]
    overlap_offsets = [0, 1, 3, 4, 8, 12, 24, 36, -1, -4, -24, 128]
    for index in range(cases):
        block = bytearray(rng.randbytes(512))
        source = 160 + index % 4
        destination = source + overlap_offsets[index % len(overlap_offsets)]
        player_id = [0x04cc, 0x0ea8, 0, 65535, rng.randrange(65536)][index % 5]
        field = struct.unpack_from('<I', block, source + 0x3c)[0]
        if index < 700:
            field = (field & ~0x1ff) | boundaries[index % len(boundaries)]
            struct.pack_into('<I', block, source + 0x3c, field)

        machine.mem_write(memory, bytes(block))
        machine.mem_write(stack, struct.pack('<4I', sentinel, memory + destination, memory + source, player_id))
        machine.reg_write(UC_X86_REG_ESP, stack)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        machine.emu_start(start, sentinel, count=1000)
        expected = bytes(machine.mem_read(memory, len(block)))
        assert machine.reg_read(UC_X86_REG_ESP) == stack + 4, 'Original did not return'
        assert machine.reg_read(UC_X86_REG_EAX) == memory + destination

        buffer = (ctypes.c_uint8 * len(block)).from_buffer_copy(block)
        pointer = ctypes.addressof(buffer)
        returned = fn(pointer + destination, pointer + source, player_id)
        actual = bytes(buffer)
        if actual != expected:
            mismatch = next(i for i, (a, b) in enumerate(zip(actual, expected)) if a != b)
            raise AssertionError(f'Case {index}: byte {mismatch} differs, id={player_id}, overlap={destination-source}, actual={actual[destination:destination+44].hex()}, expected={expected[destination:destination+44].hex()}')
        assert returned == pointer + destination
    result = {'reference_sha256': EXPECTED, 'reference_function': hex(start),
              'cases': cases, 'seed': '0x50455336', 'passed': True,
              'coverage': ['random records', 'unaligned buffers', 'forward/backward overlap',
                           'identical buffers', 'field9 boundaries', 'special player IDs',
                           'full-buffer side effects', 'return value'],
              'limitation': 'Isolated routine under x86 emulation; no full-game runtime validation.'}
    (ROOT / 'differential-results.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

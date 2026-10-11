"""Exhaustive team-category comparisons, including special-team indirection."""
import ctypes
import hashlib
import json
import random
import struct
import subprocess
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EFLAGS

ROOT = Path(__file__).resolve().parent
EXPECTED = 'f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'

def main():
    raw = (ROOT.parent / 'windows/nocd/pes6.exe').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    info = json.loads((ROOT.parent / 'windows/pe-inventory.json').read_text())
    start = 0x866d80
    section = next(s for s in info['sections'] if int(s['address'],16) <= start < int(s['address'],16)+s['file_size'])
    offset = section['file_offset'] + start - int(section['address'],16)
    lib = ROOT / 'libpes6_team_category.so'
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_team_category.c'),'-o',str(lib)],check=True)
    fn = ctypes.CDLL(str(lib)).pes6_pc_team_category
    fn.argtypes = [ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint16]
    fn.restype = ctypes.c_uint32
    machine = Uc(UC_ARCH_X86,UC_MODE_32)
    for address,size in [(start & ~0xfff,4096),(0x3000000,4096),(0xc97000,4096),(0x1fff000,8192),(0x1000000,4096)]: machine.mem_map(address,size)
    machine.mem_write(0x866d50,raw[offset-0x30:offset+0x135])
    rng = random.Random(0x866d50)
    cases = 65536 * 3 + 10000
    for index in range(cases):
        if index < 65536:
            team, present, referenced = index, 0, 0
        elif index < 65536*3:
            team = 0x126 if index < 65536*2 else 0x127
            present, referenced = 1, index % 65536
        else:
            team = (rng.getrandbits(16)<<16)|[0x126,0x127,rng.getrandbits(16)][index%3]
            present, referenced = rng.randrange(2), rng.getrandbits(16)
        slot1 = 0x3000000 if present else 0
        machine.mem_write(0xc97334,struct.pack('<2I',slot1,slot1))
        machine.mem_write(0x3000170,struct.pack('<H',referenced))
        machine.mem_write(0x2000000,struct.pack('<2I',0x1000000,team))
        machine.reg_write(UC_X86_REG_ESP,0x2000000)
        machine.reg_write(UC_X86_REG_EFLAGS,2)
        machine.emu_start(start,0x1000000,count=300)
        assert machine.reg_read(UC_X86_REG_ESP)==0x2000004
        assert fn(team,present,referenced)==machine.reg_read(UC_X86_REG_EAX), (index,team)
        assert bytes(machine.mem_read(0xc97334,8))==struct.pack('<2I',slot1,slot1)
    result = dict(reference_sha256=EXPECTED,reference_function=hex(start),cases=cases,passed=True,seed=hex(0x866d50),coverage=['all 65536 direct IDs','all 65536 indirect IDs through each special slot','missing slots','special self/cross references','upper-word truncation','unchanged global slots','return value'],limitation='Numeric categories verified; category meanings and gameplay integration remain unverified.')
    (ROOT/'team-category-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()

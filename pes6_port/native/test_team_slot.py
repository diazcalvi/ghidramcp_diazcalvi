"""Exhaustive low-word and randomized global-slot comparisons with original x86."""
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
    start = 0x866d50
    section = next(s for s in info['sections'] if int(s['address'],16) <= start < int(s['address'],16)+s['file_size'])
    offset = section['file_offset'] + start - int(section['address'],16)
    lib = ROOT / 'libpes6_team_slot.so'
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_team_slot.c'),'-o',str(lib)],check=True)
    fn = ctypes.CDLL(str(lib)).pes6_pc_team_slot
    fn.argtypes = [ctypes.c_uint32]*3
    fn.restype = ctypes.c_uint32
    machine = Uc(UC_ARCH_X86,UC_MODE_32)
    for address,size in [(start & ~0xfff,4096),(0xc97000,4096),(0x2000000,4096),(0x1000000,4096)]: machine.mem_map(address,size)
    machine.mem_write(start,raw[offset:offset+0x23])
    rng = random.Random(0x866d50)
    cases = 65536 + 10000
    for index in range(cases):
        team = index if index < 65536 else (rng.getrandbits(16)<<16)|[0x126,0x127,rng.getrandbits(16)][index%3]
        slot1,slot2 = rng.getrandbits(32),rng.getrandbits(32)
        if index%7==0: slot1,slot2 = 0,0xffffffff
        machine.mem_write(0xc97334,struct.pack('<2I',slot1,slot2))
        machine.mem_write(0x2000000,struct.pack('<2I',0x1000000,team))
        machine.reg_write(UC_X86_REG_ESP,0x2000000)
        machine.reg_write(UC_X86_REG_EFLAGS,2)
        machine.emu_start(start,0x1000000,count=32)
        assert machine.reg_read(UC_X86_REG_ESP)==0x2000004
        assert fn(team,slot1,slot2)==machine.reg_read(UC_X86_REG_EAX), (index,team)
        assert bytes(machine.mem_read(0xc97334,8))==struct.pack('<2I',slot1,slot2)
    result = dict(reference_sha256=EXPECTED,reference_function=hex(start),cases=cases,passed=True,seed=hex(0x866d50),coverage=['all 65536 low-word IDs','upper-word truncation','randomized global slots','zero and all-ones slots','unchanged global slots','return value'],limitation='Isolated address selection helper; team identity meanings and full-game behavior remain unverified.')
    (ROOT/'team-slot-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()

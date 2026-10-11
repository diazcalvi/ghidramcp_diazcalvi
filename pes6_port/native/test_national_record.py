"""Compare team-record address selection with original x86 and real callees."""
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
    start = 0x865100
    section = next(s for s in info['sections'] if int(s['address'],16) <= start < int(s['address'],16)+s['file_size'])
    offset = section['file_offset'] + start - int(section['address'],16)
    lib = ROOT / 'libpes6_national_record.so'
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_national_record.c'),str(ROOT/'pes6_team_info_address.c'),'-o',str(lib)],check=True)
    fn = ctypes.CDLL(str(lib)).pes6_pc_national_record
    fn.argtypes = [ctypes.c_uint32]*6
    fn.restype = ctypes.c_uint32
    machine = Uc(UC_ARCH_X86,UC_MODE_32)
    for address,size in [(start & ~0xfff,4096),(0x866000,4096),(0x864000,4096),(0x1132000,4096),(0x3000000,4096),(0xc97000,4096),(0x1fff000,8192),(0x1000000,4096)]: machine.mem_map(address,size)
    machine.mem_write(start,raw[offset:offset+0xa0])
    callees = 0x866000
    section2 = next(s for s in info['sections'] if int(s['address'],16) <= callees < int(s['address'],16)+s['file_size'])
    offset2 = section2['file_offset']+callees-int(section2['address'],16)
    machine.mem_write(callees,raw[offset2:offset2+4096])
    helper = 0x864fb0
    hs = next(s for s in info['sections'] if int(s['address'],16) <= helper < int(s['address'],16)+s['file_size'])
    ho = hs['file_offset']+helper-int(hs['address'],16)
    machine.mem_write(helper,raw[ho:ho+0x33])
    rng = random.Random(0x866d50)
    cases = 65536 + 20000
    for index in range(cases):
        team = index if index < 65536 else (rng.getrandbits(16)<<16)|[0x126,0x127,rng.getrandbits(16)][index%3]
        present = rng.randrange(2)
        referenced = rng.getrandbits(16)
        record = [0,0xffffffff,0xffffffa8,rng.getrandbits(32)][index%4]
        base1,base2 = rng.getrandbits(32),rng.getrandbits(32)
        base3 = [0,0xffffffff,0xfffffea0,rng.getrandbits(32)][index%4]
        slot1 = 0x3000000 if present else 0
        machine.mem_write(0xc97334,struct.pack('<2I',slot1,slot1))
        machine.mem_write(0x3000000,struct.pack('<I',record))
        machine.mem_write(0x3000170,struct.pack('<H',referenced))
        machine.mem_write(0x113200c,struct.pack('<I',base1))
        machine.mem_write(0x1132064,struct.pack('<I',base2))
        machine.mem_write(0x1132068,struct.pack('<I',base3))
        machine.mem_write(0x2000000,struct.pack('<2I',0x1000000,team))
        machine.reg_write(UC_X86_REG_ESP,0x2000000)
        machine.reg_write(UC_X86_REG_EFLAGS,2)
        machine.emu_start(start,0x1000000,count=300)
        assert machine.reg_read(UC_X86_REG_ESP)==0x2000004
        assert fn(team,present,record,base1,base2,base3)==machine.reg_read(UC_X86_REG_EAX), (index,team)
        assert bytes(machine.mem_read(0xc97334,8))==struct.pack('<2I',slot1,slot1)
    result = dict(reference_sha256=EXPECTED,reference_function=hex(start),cases=cases,passed=True,seed=hex(0x866d50),coverage=['all 65536 low-word IDs','real category and slot callees','missing special slots','special record address wrapping to zero','random table bases and overflow','upper-word truncation','return value'],limitation='Build-specific game address selection, not host memory access or full-game validation.')
    (ROOT/'national-record-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()

"""Defined-index differential tests for mode callback configuration, not callback execution."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_ECX,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());start=0xa4c3b0
 s=next(s for s in info['sections'] if int(s['address'],16)<=start<int(s['address'],16)+s['file_size']);o=s['file_offset']+start-int(s['address'],16)
 lib=ROOT/'libpes6_mode_callbacks.so';subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_mode_callbacks.c'),'-o',str(lib)],check=True)
 fn=ctypes.CDLL(str(lib)).pes6_pc_mode_callbacks;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint32];fn.restype=None
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a,n in [(start&~4095,4096),(0x3000000,4096),(0x1fff000,8192),(0x1000000,4096)]:m.mem_map(a,n)
 m.mem_write(start,raw[o:o+0xc0]);rng=random.Random(start);cases=12000
 for i in range(cases):
  mode=i%12;offset=16+i%4;block=bytearray(rng.randbytes(128));field=[0,1,0xffffffff,0x80000000][(i//12)%4];struct.pack_into('<I',block,offset+0x34,field)
  m.mem_write(0x3000000,bytes(block));m.mem_write(0x2000000,struct.pack('<I',0x1000000));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_EAX,0x3000000+offset);m.reg_write(UC_X86_REG_ECX,mode);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(start,0x1000000,count=100)
  assert m.reg_read(UC_X86_REG_ESP)==0x2000004
  buffer=(ctypes.c_uint8*128).from_buffer_copy(block);fn(ctypes.addressof(buffer)+offset,mode)
  assert bytes(buffer)==bytes(m.mem_read(0x3000000,128)),i
 result=dict(reference_sha256=EXPECTED,reference_function=hex(start),cases=cases,passed=True,seed=hex(start),coverage=['all twelve defined mode indices','zero/nonzero context field','unaligned contexts','full-buffer side effects and guards','return stack'],limitation='Callback address configuration only; original callbacks are not executed. Out-of-range indices access uninitialized original stack and are outside the portable API contract.')
 (ROOT/'mode-callbacks-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

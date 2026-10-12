"""Compare complete setup wait predicate with original status getter."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_EFLAGS,UC_X86_REG_ESI
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());lib=ROOT/'libpes6_setup_idle.so';subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_setup_idle.c'),'-o',str(lib)],check=True)
 fn=ctypes.CDLL(str(lib)).pes6_pc_setup_idle;fn.argtypes=[ctypes.c_void_p];fn.restype=ctypes.c_uint32
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a in [0x65a000,0x1027000,0x1fff000,0x2000000,0x1000000]:m.mem_map(a,4096)
 for va,n in [(0x65a6c0,0x40),(0x65ae40,0x10)]:
  s=next(s for s in info['sections'] if int(s['address'],16)<=va<int(s['address'],16)+s['file_size']);o=s['file_offset']+va-int(s['address'],16);m.mem_write(va,raw[o:o+n])
 rng=random.Random(0x65a6c0);cases=10000
 for i in range(cases):
  block=bytearray(rng.randbytes(72));mask=i%16
  for j in range(1,5):struct.pack_into('<I',block,16+j*8,[1,0x100,0x10000,0x1000000,0xffffffff,rng.getrandbits(32)|1][(i//16)%6] if mask&(1<<(j-1)) else 0)
  m.mem_write(0x1027a80,bytes(block));m.mem_write(0x2000000,struct.pack('<I',0x1000000));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_ESI,0x12345678);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(0x65a6c0,0x1000000,count=100)
  buf=(ctypes.c_uint8*72).from_buffer_copy(block);assert fn(ctypes.addressof(buf)+16)==m.reg_read(UC_X86_REG_EAX),i
  assert bytes(m.mem_read(0x1027a80,72))==bytes(block)
  assert m.reg_read(UC_X86_REG_ESP)==0x2000004 and m.reg_read(UC_X86_REG_ESI)==0x12345678
 result=dict(reference_sha256=EXPECTED,reference_function='0x65a6c0',cases=cases,passed=True,coverage=['all sixteen active-status combinations','nonzero bits in every byte','ignored entry0 and secondary dwords','real original getter','full source guards unchanged','callee-saved ESI and return stack'],limitation='Status-table wait only; rendering initialization and full asset loading remain unresolved.')
 (ROOT/'setup-idle-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

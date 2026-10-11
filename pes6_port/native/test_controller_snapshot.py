"""Compare selection snapshot bytes and surrounding memory with original x86."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());start=0x9d5370
 s=next(s for s in info['sections'] if int(s['address'],16)<=start<int(s['address'],16)+s['file_size']);o=s['file_offset']+start-int(s['address'],16)
 lib=ROOT/'libpes6_controller_snapshot.so';subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_controller_snapshot.c'),'-o',str(lib)],check=True)
 fn=ctypes.CDLL(str(lib)).pes6_pc_controller_snapshot;fn.argtypes=[ctypes.c_void_p]*2;fn.restype=None
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a in [start&~4095,0xd53000,0x3a79000,0x2000000,0x1000000]:m.mem_map(a,4096)
 m.mem_write(start,raw[o:o+0xb5]);rng=random.Random(start);cases=10000
 for i in range(cases):
  source=bytearray(rng.randbytes(448));destination=bytearray(rng.randbytes(48))
  if i<256:
   for j in range(8):source[16+j*52+1]=i;source[16+j*52+2]=(i+j)&255
  m.mem_write(0xd537e8,bytes(source));m.mem_write(0x3a799e8,bytes(destination));m.mem_write(0x2000000,struct.pack('<I',0x1000000));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(start,0x1000000,count=64)
  assert m.reg_read(UC_X86_REG_ESP)==0x2000004
  sb=(ctypes.c_uint8*448).from_buffer_copy(source);db=(ctypes.c_uint8*48).from_buffer_copy(destination)
  fn(ctypes.addressof(db)+16,ctypes.addressof(sb)+16)
  assert bytes(db)==bytes(m.mem_read(0x3a799e8,48)),i
  assert bytes(sb)==bytes(m.mem_read(0xd537e8,448)),i
 result=dict(reference_sha256=EXPECTED,reference_function=hex(start),cases=cases,passed=True,seed=hex(start),coverage=['all selection byte values','eight distinct record slots','random full records','destination guard bytes','source unchanged','return stack'],limitation='Disjoint original source/destination regions; ownership meanings unresolved.')
 (ROOT/'controller-snapshot-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

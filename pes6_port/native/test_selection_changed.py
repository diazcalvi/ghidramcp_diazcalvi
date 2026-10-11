"""Compare selection snapshot bytes and surrounding memory with original x86."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());start=0x9d5430
 s=next(s for s in info['sections'] if int(s['address'],16)<=start<int(s['address'],16)+s['file_size']);o=s['file_offset']+start-int(s['address'],16)
 lib=ROOT/'libpes6_selection_changed.so';subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_selection_changed.c'),'-o',str(lib)],check=True)
 fn=ctypes.CDLL(str(lib)).pes6_pc_selection_changed;fn.argtypes=[ctypes.c_uint32,ctypes.c_void_p,ctypes.c_void_p];fn.restype=ctypes.c_uint32
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a in [start&~4095,0xd53000,0x3a79000,0x1fff000,0x2000000,0x1000000]:m.mem_map(a,4096)
 m.mem_write(start,raw[o:o+0x146]);rng=random.Random(start);cases=32768+20000
 for i in range(cases):
  source=bytearray(rng.randbytes(448));destination=bytearray(rng.randbytes(48))
  slot=i%8;value=(i//8)%256;variant=(i//2048)%16
  for j in range(8):source[16+j*52+1]=0;source[16+j*52+2]=0
  source[16+slot*52+1]=value
  source[16+slot*52+2]=1 if variant&1 else 0
  for j in range(16):destination[16+j]=0
  destination[16+slot]=1 if variant&2 else 0
  destination[24+slot]=value if variant&4 else (value+1)&255
  flag=0 if not variant&8 else [1,2,0xffffffff,0x80000000][i%4]
  if i>=32768:
   source=bytearray(rng.randbytes(448));destination=bytearray(rng.randbytes(48));flag=0 if i%2 else rng.getrandbits(32)
   for j in range(8):source[16+j*52+2]=rng.randrange(2);source[16+j*52+1]=[0,1,2,255,254,3,253,rng.randrange(256)][j]
  struct.pack_into('<I',destination,36,flag)
  m.mem_write(0xd537e8,bytes(source));m.mem_write(0x3a799e8,bytes(destination));m.mem_write(0x2000000,struct.pack('<I',0x1000000));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(start,0x1000000,count=300)
  assert m.reg_read(UC_X86_REG_ESP)==0x2000004
  sb=(ctypes.c_uint8*448).from_buffer_copy(source);db=(ctypes.c_uint8*48).from_buffer_copy(destination)
  result_flag=fn(flag,ctypes.addressof(sb)+16,ctypes.addressof(db)+16)
  struct.pack_into('<I',db,36,result_flag)
  assert bytes(db)==bytes(m.mem_read(0x3a799e8,48)),i
  assert bytes(sb)==bytes(m.mem_read(0xd537e8,448)),i
 result=dict(reference_sha256=EXPECTED,reference_function=hex(start),cases=cases,passed=True,seed=hex(start),coverage=['all 256 selection bytes at each of eight slots','16 snapshot/current/sticky combinations','noncanonical nonzero flags preserved','random multi-slot records','full global and record buffers','return stack'],limitation='Disjoint original source/destination regions; ownership meanings unresolved.')
 (ROOT/'selection-changed-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

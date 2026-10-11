"""Compare both record handlers, real direction helper and complete memory effects."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_ECX,UC_X86_REG_ESI,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text())
 lib=ROOT/'libpes6_selection_record.so'
 subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_selection_record.c'),str(ROOT/'pes6_selection_step.c'),'-o',str(lib)],check=True)
 dll=ctypes.CDLL(str(lib));functions=[dll.pes6_pc_selection_negative,dll.pes6_pc_selection_positive]
 for fn in functions:fn.argtypes=[ctypes.c_void_p,ctypes.c_uint8,ctypes.c_void_p];fn.restype=None
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a,n in [(0x9c2000,4096),(0x9c6000,4096),(0xd53000,4096),(0x3a71000,4096),(0x3000000,16384),(0x1fff000,8192),(0x1000000,4096)]:m.mem_map(a,n)
 for va,n in [(0x9c2250,0x52),(0x9c60b0,0x160)]:
  s=next(s for s in info['sections'] if int(s['address'],16)<=va<int(s['address'],16)+s['file_size']);o=s['file_offset']+va-int(s['address'],16);m.mem_write(va,raw[o:o+n])
 rng=random.Random(0x9c60b0);total=0;per=[]
 for k,start in enumerate([0x9c60b0,0x9c6150]):
  cases=65536+10000
  for i in range(cases):
   state=i//256 if i<65536 else rng.randrange(256);mask=i%256 if i<65536 else rng.randrange(256)
   scan=bytearray(rng.randbytes(416));records=bytearray(rng.randbytes(13312));alias=i%2==0;index=rng.randrange(8) if alias else rng.randrange(256);controller=i%8
   # Deliberately force scan empty/occupied cases at every scan position.
   for j in range(8):scan[j*52+1]=0
   if i%3==1:scan[(i%8)*52+1]=[255,254,1,2][i%4]
   base=0xd537f8 if alias else 0x3000000;target_offset=index*52+1
   if alias:scan[target_offset]=state
   else:records[target_offset]=state
   m.mem_write(0xd537f8,bytes(scan));m.mem_write(0x3000000,bytes(records));inputs=rng.randbytes(32);inputs=bytearray(inputs);struct.pack_into('<I',inputs,controller*4,mask|rng.getrandbits(24)<<8);m.mem_write(0x3a71254,bytes(inputs))
   m.mem_write(0x2000000,struct.pack('<2I',0x1000000,controller));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_ECX,base);m.reg_write(UC_X86_REG_EAX,index|rng.getrandbits(24)<<8);m.reg_write(UC_X86_REG_ESI,0x12345678);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(start,0x1000000,count=300)
   assert m.reg_read(UC_X86_REG_ESP)==0x2000004 and m.reg_read(UC_X86_REG_ESI)==0x12345678
   sb=(ctypes.c_uint8*416).from_buffer_copy(scan);rb=(ctypes.c_uint8*13312).from_buffer_copy(records);target=ctypes.addressof(sb if alias else rb)+target_offset
   functions[k](target,mask,ctypes.addressof(sb))
   assert bytes(sb)==bytes(m.mem_read(0xd537f8,416)),(k,i,'scan')
   assert bytes(rb)==bytes(m.mem_read(0x3000000,13312)),(k,i,'records')
   assert bytes(m.mem_read(0x3a71254,32))==bytes(inputs)
  per.append({'reference_function':hex(start),'cases':cases,'passed':True});total+=cases
 result=dict(reference_sha256=EXPECTED,cases=total,functions=per,passed=True,coverage=['all 256 states and 256 direction bytes per handler','real original direction callee','target aliases scan table or separate records','all eight scan positions','full record/table side effects','ignored upper register bits','all eight input controllers','callee-saved ESI and input table'],limitation='Selection handlers only; ownership meaning and match mode integration remain unresolved.')
 (ROOT/'selection-record-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

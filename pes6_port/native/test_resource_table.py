"""Resource table dependency comparisons, original thunks and full memory effects."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());lib=ROOT/'libpes6_resource_table.so'
 subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_resource_table.c'),'-o',str(lib)],check=True)
 dll=ctypes.CDLL(str(lib));fns=[dll.pes6_pc_resource_handle,dll.pes6_pc_resource_id,dll.pes6_pc_resource_clear]
 for i,f in enumerate(fns):f.argtypes=[ctypes.c_void_p,ctypes.c_int32,ctypes.c_int32];f.restype=None if i==2 else ctypes.c_uint32
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a in [0x8b8000,0x3a5c000,0x3000000,0x2000000,0x1000000]:m.mem_map(a,4096)
 va=0x8b8000;s=next(s for s in info['sections'] if int(s['address'],16)<=va<int(s['address'],16)+s['file_size']);o=s['file_offset']+va-int(s['address'],16);m.mem_write(va,raw[o:o+4096]);rng=random.Random(va);cases=12000;results=[]
 for kind,start in enumerate([0x8b8ab0,0x8b8ac0,0x8b8b00]):
  for i in range(cases):
   index=i%32;count=[-1,0,index,index+1,32][(i//32)%5];present=kind!=0 or i%2==0;block=rng.randbytes(320);table_address=0x3000010
   m.mem_write(0x3000000,block);globals_block=struct.pack('<4I',table_address,count&0xffffffff,table_address if present else 0,count&0xffffffff);m.mem_write(0x3a5cfd8,globals_block);m.mem_write(0x2000000,struct.pack('<2I',0x1000000,index));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(start,0x1000000,count=100)
   assert m.reg_read(UC_X86_REG_ESP)==0x2000004
   buffer=(ctypes.c_uint8*320).from_buffer_copy(block);returned=fns[kind](ctypes.addressof(buffer)+16 if present else None,count,index)
   if kind!=2:assert returned==m.reg_read(UC_X86_REG_EAX),(kind,i)
   assert bytes(buffer)==bytes(m.mem_read(0x3000000,320)),(kind,i)
   assert bytes(m.mem_read(0x3a5cfd8,16))==globals_block
  results.append({'reference_function':hex(start),'cases':cases,'passed':True})
 result=dict(reference_sha256=EXPECTED,cases=cases*3,functions=results,passed=True,coverage=['32 nonnegative resource indices','signed counts and boundary equality','null secondary table','random IDs/handles','clear both record fields','full table guards','unchanged globals','original forwarding thunks'],limitation='Resource table operations only; allocation/loading dependencies and negative original indices are outside this API contract.')
 (ROOT/'resource-table-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

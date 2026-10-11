"""Original-x86 comparisons for controller-selection direction transitions."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes()
 assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());start=0x9c2250
 s=next(s for s in info['sections'] if int(s['address'],16)<=start<int(s['address'],16)+s['file_size']);o=s['file_offset']+start-int(s['address'],16)
 lib=ROOT/'libpes6_selection_step.so'
 subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_selection_step.c'),'-o',str(lib)],check=True)
 fn=ctypes.CDLL(str(lib)).pes6_pc_selection_step;fn.argtypes=[ctypes.c_uint8]+[ctypes.c_int32]*3;fn.restype=ctypes.c_uint32
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a in [start&~4095,0x2000000,0x1000000]:m.mem_map(a,4096)
 m.mem_write(start,raw[o:o+0x52]);rng=random.Random(start);cases=0
 def check(mask,value,lower,upper):
  nonlocal cases
  stack=struct.pack('<5I',0x1000000,mask,value&0xffffffff,lower&0xffffffff,upper&0xffffffff)
  m.mem_write(0x2000000,stack);m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(start,0x1000000,count=64)
  assert m.reg_read(UC_X86_REG_ESP)==0x2000004
  assert bytes(m.mem_read(0x2000000,20))==stack
  assert fn(mask,value,lower,upper)==m.reg_read(UC_X86_REG_EAX),(mask,value,lower,upper)
  cases+=1
 for mask in range(256):
  for lower,upper in [(-4,-1),(1,4),(-4,1),(0,1),(2,1),(4,-4),(-2147483648,2147483647)]:
   for value in [-2147483648,-5,-4,-3,-1,0,1,2,3,4,5,2147483647]:check(mask,value,lower,upper)
 for _ in range(20000):
  vals=[rng.randrange(-2147483648,2147483648) for _ in range(3)];check(rng.randrange(256),*vals)
 result=dict(reference_sha256=EXPECTED,reference_function=hex(start),cases=cases,passed=True,seed=hex(start),coverage=['all 256 direction bytes','simultaneous-direction precedence','caller bounds -4..-1 and 1..4','upper==1 special branch','reversed bounds','signed extremes and arithmetic wrap','random signed inputs','stack unchanged'],limitation='Selection transition only; controller ownership and CPU mode meanings not yet validated.')
 (ROOT/'selection-step-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

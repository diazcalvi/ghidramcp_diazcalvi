"""Defined-index differential tests for mode callback configuration, not callback execution."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_ECX,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());start=0xa69760
 s=next(s for s in info['sections'] if int(s['address'],16)<=start<int(s['address'],16)+s['file_size']);o=s['file_offset']+start-int(s['address'],16)
 lib=ROOT/'libpes6_mode_advance.so';subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_mode_advance.c'),str(ROOT/'pes6_mode_state.c'),str(ROOT/'pes6_mode_callbacks.c'),'-o',str(lib)],check=True)
 fn=ctypes.CDLL(str(lib)).pes6_pc_mode_advance;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint32];fn.restype=ctypes.c_uint32
 top=ctypes.CDLL(str(lib)).pes6_pc_mode_advance_top;top.argtypes=[ctypes.c_void_p];top.restype=ctypes.c_uint32
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a,n in [(start&~4095,4096),(0xa4b000,4096),(0xa4c000,4096),(0x3a8a000,4096),(0x1fff000,8192),(0x1000000,4096)]:m.mem_map(a,n)
 
 for va,n in [(0xa4c3b0,0x113),(0xa69760,0x1a),(0xa4b6c0,0x1d)]:
  ps=next(s for s in info['sections'] if int(s['address'],16)<=va<int(s['address'],16)+s['file_size']);po=ps['file_offset']+va-int(ps['address'],16);m.mem_write(va,raw[po:po+n])
 rng=random.Random(start);cases=34000
 for i in range(cases):
  wrapper=i>=24000;mode=0 if wrapper else i%4;value=[0xffffffff,(i//4)%11][(i//4)%2] if mode==0 else rng.getrandbits(32);offset=16;block=bytearray(rng.randbytes(128));field=[0,1,0xffffffff,0x80000000][(i//12)%4];struct.pack_into('<I',block,offset+0x34,field)
  struct.pack_into('<I',block,offset+mode*4,value)
  if mode>0 and i%8<4:struct.pack_into('<I',block,offset+0x0c+mode*4,struct.unpack_from('<I',block,offset+(mode-1)*4)[0])
  m.mem_write(0x3a8aae8,bytes(block));m.mem_write(0x2000000,struct.pack('<2I',0x1000000,rng.getrandbits(32) if wrapper else mode));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_EAX,0x3a8aae8+offset);m.reg_write(UC_X86_REG_ECX,mode);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(0xa4b6d0 if wrapper else start,0x1000000,count=150)
  assert m.reg_read(UC_X86_REG_ESP)==0x2000004
  buffer=(ctypes.c_uint8*128).from_buffer_copy(block);returned=top(ctypes.addressof(buffer)+offset) if wrapper else fn(ctypes.addressof(buffer)+offset,mode)
  assert returned==0 and m.reg_read(UC_X86_REG_EAX)==0
  if wrapper:assert bytes(m.mem_read(0x2000004,4))==bytes(4)
  assert bytes(buffer)==bytes(m.mem_read(0x3a8aae8,128)),i
 result=dict(reference_sha256=EXPECTED,reference_functions=['0xa69760','0xa4b6d0'],cases=cases,passed=True,seed=hex(start),coverage=['all four state levels','all defined next top-level modes','counter overflow to zero','forced index0 wrapper and ignored arg','matching/mismatched gates','lower counter reset','real original callback configurator','fixed original context mapping','full-buffer guards','return stack'],limitation='Defined state levels 0..3 and top-level modes 0..11 only; configured gameplay callbacks are not executed.')
 (ROOT/'mode-advance-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

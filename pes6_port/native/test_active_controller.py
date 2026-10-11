"""Compare menu active-controller selection with real mode getters and signed preference."""
import ctypes,hashlib,json,random,struct,subprocess
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EAX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EFLAGS
ROOT=Path(__file__).resolve().parent
EXPECTED='f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a'
def main():
 raw=(ROOT.parent/'windows/nocd/pes6.exe').read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 info=json.loads((ROOT.parent/'windows/pe-inventory.json').read_text());lib=ROOT/'libpes6_active_controller.so'
 subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(ROOT/'pes6_active_controller.c'),'-o',str(lib)],check=True)
 fn=ctypes.CDLL(str(lib)).pes6_pc_active_controller;fn.argtypes=[ctypes.c_uint8]*3+[ctypes.c_int8,ctypes.c_uint32,ctypes.c_void_p];fn.restype=ctypes.c_uint32
 m=Uc(UC_ARCH_X86,UC_MODE_32)
 for a,n in [(0x9c6000,4096),(0x9c2000,4096),(0xa4b000,4096),(0xbaf000,4096),(0x3be1000,4096),(0x3be6000,4096),(0x3a8a000,4096),(0x1fff000,8192),(0x1000000,4096)]:m.mem_map(a,n)
 for va,n in [(0x9c6be0,0x82),(0x9c2e30,0x1e),(0xa4b6e0,8)]:
  s=next(s for s in info['sections'] if int(s['address'],16)<=va<int(s['address'],16)+s['file_size']);o=s['file_offset']+va-int(s['address'],16);m.mem_write(va,raw[o:o+n])
 rng=random.Random(0x9c6be0);cases=65536+20000
 for i in range(cases):
  mode=[0,1,128,255][i%4];game=(i//256)%256;preferred=i%256;enabled=[0,1,2,255][(i//4)%4];connected=rng.getrandbits(32)
  if i>=65536:game=rng.randrange(256);preferred=rng.randrange(256);enabled=rng.randrange(3);mode=rng.randrange(256)
  masks=[rng.getrandbits(32) for _ in range(256)]
  if i%3==0: masks=[0]*256;masks[128+(i%8)]=1;connected=1
  table=struct.pack('<256I',*masks);m.mem_write(0xbaf7d4,table);m.mem_write(0x3be6bc0,struct.pack('<I',connected));m.mem_write(0x3a8ab28,bytes([mode]));m.mem_write(0x3be12c9,bytes([game]));m.mem_write(0x3be1475,bytes([enabled,preferred]));m.mem_write(0x2000000,struct.pack('<I',0x1000000));m.reg_write(UC_X86_REG_ESP,0x2000000);m.reg_write(UC_X86_REG_ESI,0x12345678);m.reg_write(UC_X86_REG_EDI,0xabcdef01);m.reg_write(UC_X86_REG_EFLAGS,2);m.emu_start(0x9c6be0,0x1000000,count=150)
  arr=(ctypes.c_uint32*256)(*masks);signed=preferred if preferred<128 else preferred-256
  assert fn(mode,game,enabled,signed,connected,ctypes.addressof(arr))==m.reg_read(UC_X86_REG_EAX),(i,mode,game,enabled,signed)
  assert m.reg_read(UC_X86_REG_ESP)==0x2000004 and m.reg_read(UC_X86_REG_ESI)==0x12345678 and m.reg_read(UC_X86_REG_EDI)==0xabcdef01
  assert bytes(m.mem_read(0xbaf7d4,1024))==table
 result=dict(reference_sha256=EXPECTED,reference_function='0x9c6be0',cases=cases,passed=True,seed='0x9c6be0',coverage=['all mode IDs and signed preference bytes','real mode and game-mode callees','two-slot and eight-slot fallback','preferred selection precedence','nonboolean mode/enable bytes','negative preferred results','random bit tables and connected masks','callee-saved registers and table unchanged'],limitation='Menu active-controller selection; mode byte and gameplay ownership semantics unresolved.')
 (ROOT/'active-controller-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()

#include "pes6_mode_callbacks.h"
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static void put32(uint8_t *p,uint32_t x)
{ p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);p[2]=(uint8_t)(x>>16);p[3]=(uint8_t)(x>>24); }
void pes6_pc_mode_callbacks(uint8_t context[56],uint32_t mode_index)
{
 static const uint32_t ids[12]={0xa4b9c0,0xa4b6d0,0xa4b690,0xa4b6a0,0xa4bb40,0xa4bb80,0xa4bc90,0xa4bdc0,0xa4bfb0,0xa4c260,0xa4b6b0,0xa4c020};
 put32(context+0x20,ids[mode_index]);
 uint32_t second=0xa6f0d0;
 if (mode_index==0 || mode_index==11) second=0x970490;
 else if (mode_index>=6 && mode_index<=8) second=0xa6f9e0;
 put32(context+0x28,second);
 if (!get32(context+0x34)) put32(context+0x24,0x970490);
}

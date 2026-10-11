#include "pes6_mode_state.h"
#include "pes6_mode_callbacks.h"
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static void put32(uint8_t *p,uint32_t x)
{ p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);p[2]=(uint8_t)(x>>16);p[3]=(uint8_t)(x>>24); }
void pes6_pc_mode_state(uint8_t context[56],uint32_t index,uint32_t value)
{
 if (index && get32(context+0x0c+index*4)!=get32(context+(index-1)*4)) return;
 put32(context+index*4,value);
 for (uint32_t i=index+1;i<4;i++) put32(context+i*4,0);
 if (!index) pes6_pc_mode_callbacks(context,value);
}

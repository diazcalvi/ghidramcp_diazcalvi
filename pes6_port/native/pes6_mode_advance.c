#include "pes6_mode_advance.h"
#include "pes6_mode_state.h"
uint32_t pes6_pc_mode_advance(uint8_t context[56],uint32_t index)
{
 const uint8_t *p=context+index*4;
 uint32_t current=(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
 pes6_pc_mode_state(context,index,current+1u);
 return 0;
}
uint32_t pes6_pc_mode_advance_top(uint8_t context[56])
{
 return pes6_pc_mode_advance(context,0);
}

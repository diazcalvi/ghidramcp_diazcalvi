#include "pes6_active_controller.h"
uint32_t pes6_pc_active_controller(uint8_t mode_byte,uint8_t game_mode,
 uint8_t preferred_enabled,int8_t preferred,uint32_t connected,const uint32_t masks[256])
{
 if (preferred_enabled==1 && (masks[128+(int)preferred]&connected)) return (uint32_t)(int32_t)preferred;
 if (game_mode==5 || game_mode==1 || game_mode==4 || game_mode==2 || game_mode==14) return 0;
 unsigned count=mode_byte?2:8;
 for (unsigned i=0;i<count;i++) if (masks[128+i]&connected) return i;
 return 0;
}

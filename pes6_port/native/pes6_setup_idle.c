#include "pes6_setup_idle.h"
uint32_t pes6_pc_setup_idle(const uint8_t statuses[40])
{
 for(unsigned i=1;i<5;i++) {
  const uint8_t *p=statuses+i*8;
  if(p[0]||p[1]||p[2]||p[3])return 0;
 }
 return 1;
}

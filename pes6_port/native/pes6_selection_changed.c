#include "pes6_selection_changed.h"
uint32_t pes6_pc_selection_changed(uint32_t flag,const uint8_t records[416],const uint8_t snapshot[16])
{
 if (flag) return flag;
 for (unsigned i=0;i<8;i++) {
  uint8_t value=records[i*52+1];
  if (records[i*52+2]==0 && (value==1 || value==2 || value==255 || value==254)) {
   if (snapshot[i]!=0 || snapshot[i+8]!=value) flag=1;
  }
 }
 return flag;
}

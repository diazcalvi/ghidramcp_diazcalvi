#include "pes6_controller_snapshot.h"
void pes6_pc_controller_snapshot(uint8_t destination[16],const uint8_t records[416])
{
 for (unsigned i=0;i<8;i++) {
  destination[i]=records[i*52+2];
  destination[i+8]=records[i*52+1];
 }
}

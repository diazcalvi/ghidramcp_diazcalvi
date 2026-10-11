#include "pes6_selection_record.h"
#include "pes6_selection_step.h"
static int signed_byte(uint8_t b) { return b < 128 ? b : (int)b-256; }
void pes6_pc_selection_negative(uint8_t *target,uint8_t directions,const uint8_t *scan)
{
 int v=signed_byte(*target);
 if (v==10) { *target=245; return; }
 if (v==11) { *target=10; return; }
 if (v>=1 && v<=4) { *target=0; return; }
 if (v==0) { *target=255; return; }
 if (v>=-4 && v<=-1) {
  *target=(uint8_t)pes6_pc_selection_step(directions,v,-4,-1);
  if (*target!=252) return;
  for (unsigned i=0;i<8;i++) {
   int other=signed_byte(scan[i*52+1]);
   if (other>=-2 && other<0) return;
  }
  *target=255;
 }
}
void pes6_pc_selection_positive(uint8_t *target,uint8_t directions,const uint8_t *scan)
{
 int v=signed_byte(*target);
 if (v==10) { *target=11; return; }
 if (v==-11) { *target=10; return; }
 if (v>=-4 && v<=-1) { *target=0; return; }
 if (v==0) { *target=1; return; }
 if (v>=1 && v<=4) {
  *target=(uint8_t)pes6_pc_selection_step(directions,v,1,4);
  if (*target!=4) return;
  for (unsigned i=0;i<8;i++) {
   int other=signed_byte(scan[i*52+1]);
   if (other>0 && other<=2) return;
  }
  *target=1;
 }
}

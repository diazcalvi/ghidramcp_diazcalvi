#include "pes6_resource_table.h"
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
uint32_t pes6_pc_resource_handle(const uint8_t *table,int32_t count,int32_t index)
{ return table && index<count ? get32(table+(uint32_t)index*8+4) : 0; }
uint32_t pes6_pc_resource_id(const uint8_t *table,int32_t count,int32_t index)
{ return index<count ? get32(table+(uint32_t)index*8) : UINT32_MAX; }
void pes6_pc_resource_clear(uint8_t *table,int32_t count,int32_t index)
{
 if (index<count) {
  uint8_t *p=table+(uint32_t)index*8;
  for (unsigned i=0;i<4;i++)p[i]=255;
  for (unsigned i=4;i<8;i++)p[i]=0;
 }
}

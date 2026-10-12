#include "pes6_resource_status.h"
uint32_t pes6_pc_resource_status(const uint8_t *table,int32_t count,int32_t index)
{
 if(index>=count)return 0;
 const uint8_t *p=table+(uint32_t)index*8+4;
 return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
uint8_t pes6_pc_resource_ready(const uint8_t *table,int32_t count,int32_t index)
{ return pes6_pc_resource_status(table,count,index)==1; }
void pes6_pc_resource_register(uint8_t *table,int32_t count,int32_t index,uint32_t id,uint32_t status)
{
 if(index>=count)return;
 uint8_t *p=table+(uint32_t)index*8;
 for(unsigned i=0;i<4;i++){p[i]=(uint8_t)(id>>(i*8));p[i+4]=(uint8_t)(status>>(i*8));}
}

#ifndef PES6_RESOURCE_STATUS_H
#define PES6_RESOURCE_STATUS_H
#include <stdint.h>
uint32_t pes6_pc_resource_status(const uint8_t *table,int32_t count,int32_t index);
uint8_t pes6_pc_resource_ready(const uint8_t *table,int32_t count,int32_t index);
void pes6_pc_resource_register(uint8_t *table,int32_t count,int32_t index,uint32_t id,uint32_t status);
/* Nonnegative indices, signed count, sufficient little-endian 8-byte records. */
#endif

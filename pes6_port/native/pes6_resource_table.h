#ifndef PES6_RESOURCE_TABLE_H
#define PES6_RESOURCE_TABLE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC0x8b8ab0/0x8b8ac0/0x8b8b00: little-endian 8-byte records.
 * Nonnegative indices only; sufficient table storage must exist for every
 * accepted index. count is signed as in x86. Original nullable secondary
 * table is represented by NULL. All values are IDs/handles, not pointers.
 */
uint32_t pes6_pc_resource_handle(const uint8_t *table,int32_t count,int32_t index);
uint32_t pes6_pc_resource_id(const uint8_t *table,int32_t count,int32_t index);
void pes6_pc_resource_clear(uint8_t *table,int32_t count,int32_t index);
#ifdef __cplusplus
}
#endif
#endif

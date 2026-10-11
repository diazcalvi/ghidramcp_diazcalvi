#ifndef PES6_CONTROLLER_SNAPSHOT_H
#define PES6_CONTROLLER_SNAPSHOT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x9d5370. Source: eight 52-byte records. Destination: 16 bytes,
 * first eight from record offset +2, next eight from offset +1.
 * Buffers must be disjoint, matching the original fixed memory regions.
 * Byte meanings remain unresolved; signed selections retain their bits.
 */
void pes6_pc_controller_snapshot(uint8_t destination[16],const uint8_t records[416]);
#ifdef __cplusplus
}
#endif
#endif

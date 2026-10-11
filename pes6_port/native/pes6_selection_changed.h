#ifndef PES6_SELECTION_CHANGED_H
#define PES6_SELECTION_CHANGED_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x9d5430: sticky flag retains every nonzero initial value.
 * For a clear flag, only selections +/-1 or +/-2 with record byte +2==0
 * are compared with the 16-byte snapshot produced by 0x9d5370.
 * Arrays are read-only; original fixed memory regions are disjoint.
 */
uint32_t pes6_pc_selection_changed(uint32_t flag,const uint8_t records[416],const uint8_t snapshot[16]);
#ifdef __cplusplus
}
#endif
#endif

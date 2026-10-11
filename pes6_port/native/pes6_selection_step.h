#ifndef PES6_SELECTION_STEP_H
#define PES6_SELECTION_STEP_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x9c2250. Direction mask 0xa0 takes precedence over 0x50.
 * Bounds are signed and may be reversed; upper==1 uses special rules.
 * Return unsigned bits to preserve x86 increment/decrement overflow.
 */
uint32_t pes6_pc_selection_step(uint8_t directions,int32_t value,int32_t lower,int32_t upper);
#ifdef __cplusplus
}
#endif
#endif

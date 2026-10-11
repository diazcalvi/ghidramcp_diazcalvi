#ifndef PES6_MODE_ADVANCE_H
#define PES6_MODE_ADVANCE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0xa69760: index 0..3, increments with 32-bit wrap, applies tested
 * gate/update logic and returns zero even when the gate blocks the write.
 * For index0, incremented mode must be 0..11 (defined configurator domain).
 */
uint32_t pes6_pc_mode_advance(uint8_t context[56],uint32_t index);
/* PC callback0xa4b6d0 always advances index0, ignoring its original arg. */
uint32_t pes6_pc_mode_advance_top(uint8_t context[56]);
#ifdef __cplusplus
}
#endif
#endif

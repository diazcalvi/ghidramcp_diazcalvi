#ifndef PES6_MODE_STATE_H
#define PES6_MODE_STATE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0xa4c470, context >=56 little-endian bytes, indices 0..3.
 * Top-level value (index 0) must be a defined mode 0..11.
 * Gate field at +0x0c+4*index must match preceding counter for index>0.
 * Installs original callback identifiers as data, never host pointers.
 */
void pes6_pc_mode_state(uint8_t context[56],uint32_t index,uint32_t value);
#ifdef __cplusplus
}
#endif
#endif

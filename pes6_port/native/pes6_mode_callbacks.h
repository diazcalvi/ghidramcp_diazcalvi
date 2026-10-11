#ifndef PES6_MODE_CALLBACKS_H
#define PES6_MODE_CALLBACKS_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0xa4c3b0, defined mode indices 0..11 only; context >=56 bytes,
 * little endian, may be unaligned. Stored callbacks are original address
 * identifiers, never callable host pointers. Caller must translate them
 * to recovered native functions before execution.
 */
void pes6_pc_mode_callbacks(uint8_t context[56],uint32_t mode_index);
#ifdef __cplusplus
}
#endif
#endif

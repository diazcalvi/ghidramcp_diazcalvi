#ifndef PES6_ACTIVE_CONTROLLER_H
#define PES6_ACTIVE_CONTROLLER_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x9c6be0. mask_window[128+i] models original bit-table entry i,
 * including signed preferred indices -128..127. Returns signed result
 * bits; zero is also the original fallback when no controller is chosen.
 * mode_byte is an unresolved byte at original 0x3a8ab28, not a CPU flag.
 */
uint32_t pes6_pc_active_controller(uint8_t mode_byte,uint8_t game_mode,
 uint8_t preferred_enabled,int8_t preferred,uint32_t connected,
 const uint32_t mask_window[256]);
#ifdef __cplusplus
}
#endif
#endif

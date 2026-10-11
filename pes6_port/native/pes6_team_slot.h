#ifndef PES6_TEAM_SLOT_H
#define PES6_TEAM_SLOT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x00866d50: select a build-specific 32-bit address from the two
 * original global slots. Values remain integers, never host pointers.
 * Only the low 16 bits of team_id participate. No memory dereference.
 */
uint32_t pes6_pc_team_slot(uint32_t team_id, uint32_t slot_126, uint32_t slot_127);
#ifdef __cplusplus
}
#endif
#endif

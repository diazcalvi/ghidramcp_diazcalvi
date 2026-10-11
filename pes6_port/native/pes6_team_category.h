#ifndef PES6_TEAM_CATEGORY_H
#define PES6_TEAM_CATEGORY_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x866d80. For IDs 0x126/0x127, supply the presence and low-word
 * value at original slot+0x170. Numeric category meanings are unverified.
 */
uint32_t pes6_pc_team_category(uint32_t team_id, uint32_t slot_present, uint16_t referenced_id);
#ifdef __cplusplus
}
#endif
#endif

#ifndef PES6_TEAM_INFO_H
#define PES6_TEAM_INFO_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
 uint32_t slot_present, special_record;
 uint16_t referenced_id;
 uint32_t base_40, base_dd, base_00, base_cc, base_fe;
} pes6_pc_team_context;
/* PC 0x865240. Returns original 32-bit game address, never a host pointer.
 * Ordinary record indices are 0..3. IDs 0x110/0x111 accept any nonnegative
 * signed index, matching the original branch's wrapping arithmetic.
 */
uint32_t pes6_pc_team_info(uint32_t team_id, int32_t index,
 const pes6_pc_team_context *context);
#ifdef __cplusplus
}
#endif
#endif

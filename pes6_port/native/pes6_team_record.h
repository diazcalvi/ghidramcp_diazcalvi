#ifndef PES6_TEAM_RECORD_H
#define PES6_TEAM_RECORD_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x864ef0. Inputs are original 32-bit address values, not host
 * pointers. special_record is the first dword of the selected special
 * slot, when present. All arithmetic wraps modulo 2^32 like x86.
 * The original also invokes the read-only category helper for present
 * special slots; its result is unused by address selection.
 */
uint32_t pes6_pc_team_record(uint32_t team_id, uint32_t slot_present,
    uint32_t special_record, uint32_t base_40, uint32_t base_dd);
#ifdef __cplusplus
}
#endif
#endif

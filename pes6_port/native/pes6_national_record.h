#ifndef PES6_NATIONAL_RECORD_H
#define PES6_NATIONAL_RECORD_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC 0x865100: original address values, never host pointers. */
uint32_t pes6_pc_national_record(uint32_t team_id, uint32_t slot_present,
 uint32_t special_record, uint32_t base_00, uint32_t base_cc, uint32_t base_fe);
#ifdef __cplusplus
}
#endif
#endif

#ifndef PES6_SELECTION_RECORD_H
#define PES6_SELECTION_RECORD_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Original record offset +1 is supplied as target. Scan table holds eight
 * 52-byte records, including their signed selection bytes at offset +1.
 * Target may alias scan table. Scan occurs after target is written.
 */
void pes6_pc_selection_negative(uint8_t *target,uint8_t directions,const uint8_t *scan_table);
void pes6_pc_selection_positive(uint8_t *target,uint8_t directions,const uint8_t *scan_table);
#ifdef __cplusplus
}
#endif
#endif

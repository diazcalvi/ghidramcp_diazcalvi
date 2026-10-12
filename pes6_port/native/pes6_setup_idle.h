#ifndef PES6_SETUP_IDLE_H
#define PES6_SETUP_IDLE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC0x65a6c0: five 8-byte entries, tests first dword of entries1..4.
 * Entry0 and second dwords do not participate. Little-endian, read-only.
 * True means observed status table is clear, not full asset readiness.
 */
uint32_t pes6_pc_setup_idle(const uint8_t statuses[40]);
#ifdef __cplusplus
}
#endif
#endif

#ifndef PES6_PLAYER_FIELDS_H
#define PES6_PLAYER_FIELDS_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Port of PES6 PC function 0x00a4b040 in SHA256
 * f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a.
 * Destination requires 44 bytes; source requires 64 bytes. Byte order is
 * little endian. Overlap follows the original forward 32-bit copy order.
 * Attribute meanings are intentionally unspecified pending semantic review.
 * Assumes the x86 direction flag is clear, as required by the calling ABI.
 */
uint8_t *pes6_pc_copy_player_fields(uint8_t *destination,
                                    const uint8_t *source, uint16_t player_id);
#ifdef __cplusplus
}
#endif
#endif

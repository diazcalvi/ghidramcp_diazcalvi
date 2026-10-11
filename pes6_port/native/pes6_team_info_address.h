#ifndef PES6_TEAM_INFO_ADDRESS_H
#define PES6_TEAM_INFO_ADDRESS_H
#include <stdint.h>

#if defined(_WIN32)
#define PES6_PORT_API __declspec(dllexport)
#else
#define PES6_PORT_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* PC 0x00864fb0: IDs 0xfe..0x10d map to 0x160-byte records.
 * The table base is explicit state from global 0x01132068; addresses remain
 * uint32_t values and are never converted to host pointers.
 */
PES6_PORT_API uint32_t pes6_pc_team_info_address(uint32_t team_id,
    uint32_t table_base);

#ifdef __cplusplus
}
#endif
#endif

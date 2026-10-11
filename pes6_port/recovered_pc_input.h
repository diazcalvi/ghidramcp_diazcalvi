/* Recovered PES6 PC input table layout, not a gameplay implementation.
 * Evidence: kitserver/kitserver6 src/input.h, input.cpp, hook.cpp;
 * instruction reads at 0x009cd4f2 in executable SHA256
 * f61dc6f07401b8bc383d4bb69c001a6bf38f6557eeec7a9c261b581a4effdc1a.
 * Eight controller slots are represented; this does not establish how teams
 * are assigned to controllers or how CPU control is selected.
 */
#ifndef PES6_RECOVERED_PC_INPUT_H
#define PES6_RECOVERED_PC_INPUT_H
#include <stdint.h>
#include <stddef.h>

typedef struct Pes6PcInputTable {
    uint32_t directional_pressed[8];
    uint32_t directional_released[8];
    uint32_t functional[8];
} Pes6PcInputTable;

enum Pes6PcDirectionalBits {
    PES6_PC_UP = 0x10, PES6_PC_DOWN = 0x20,
    PES6_PC_LEFT = 0x40, PES6_PC_RIGHT = 0x80
};
enum Pes6PcFunctionalBits {
    PES6_PC_CROSS = 0x01, PES6_PC_TRIANGLE = 0x02,
    PES6_PC_SQUARE = 0x04, PES6_PC_CIRCLE = 0x08,
    PES6_PC_L1 = 0x100, PES6_PC_R1 = 0x200,
    PES6_PC_L2 = 0x1000, PES6_PC_R2 = 0x2000,
    PES6_PC_SELECT = 0x10000, PES6_PC_START = 0x400000
};

#ifdef __cplusplus
static_assert(sizeof(Pes6PcInputTable) == 96, "Unexpected input-table ABI");
static_assert(offsetof(Pes6PcInputTable, functional) == 64, "Unexpected input offset");
#else
_Static_assert(sizeof(Pes6PcInputTable) == 96, "Unexpected input-table ABI");
_Static_assert(offsetof(Pes6PcInputTable, functional) == 64, "Unexpected input offset");
#endif

/* Original guest memory uses little-endian 32-bit words. Deserialize when
 * inspecting guest bytes on other-endian hosts; do not cast arbitrary buffers.
 */
#define PES6_PC_INPUT_TABLE_VA UINT32_C(0x03a71254)
#define PES6_PC_INPUT_CLEAR_SITE_VA UINT32_C(0x009cd4f2)
#endif

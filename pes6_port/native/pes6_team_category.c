#include "pes6_team_category.h"
uint32_t pes6_pc_team_category(uint32_t team_id, uint32_t slot_present, uint16_t referenced_id)
{
    uint16_t id = (uint16_t)team_id;
    if (id == 0x126 || id == 0x127) {
        if (!slot_present || referenced_id == 0x126 || referenced_id == 0x127) return 3;
        id = referenced_id;
    }
    if (id <= 0x38 || (id >= 0xcc && id <= 0xdc)) return 0;
    if (id <= 0x3f) return 2;
    if (id <= 0x118 || (id >= 0x11e && id <= 0x125)) return 3;
    return 0;
}

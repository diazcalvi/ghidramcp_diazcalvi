#include "pes6_team_record.h"
uint32_t pes6_pc_team_record(uint32_t team_id, uint32_t slot_present,
    uint32_t special_record, uint32_t base_40, uint32_t base_dd)
{
    uint16_t id = (uint16_t)team_id;
    if ((id == 0x126 || id == 0x127) && slot_present) {
        uint32_t address = special_record + UINT32_C(0x58);
        if (address) return address;
    }
    if (id >= 0x40 && id <= 0xcb)
        return base_40 + (uint32_t)(id - 0x40) * UINT32_C(0x220);
    if (id >= 0xdd && id <= 0xfd)
        return base_dd + (uint32_t)(id - 0xdd) * UINT32_C(0x220);
    if (id >= 0x10e && id <= 0x10f)
        return UINT32_C(0x1132098) + (uint32_t)(id - 0x10e) * UINT32_C(0x220);
    return 0;
}

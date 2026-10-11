#include "pes6_team_slot.h"
uint32_t pes6_pc_team_slot(uint32_t team_id, uint32_t slot_126, uint32_t slot_127)
{
    uint16_t id = (uint16_t)team_id;
    if (id == 0x126) return slot_126;
    if (id == 0x127) return slot_127;
    return 0;
}

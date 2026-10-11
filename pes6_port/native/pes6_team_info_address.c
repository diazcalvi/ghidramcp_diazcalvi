#include "pes6_team_info_address.h"

uint32_t pes6_pc_team_info_address(uint32_t team_id, uint32_t table_base)
{
    uint16_t id = (uint16_t)team_id;
    if (id < 0x00fe || id > 0x010d || table_base == 0) return 0;
    return table_base + (uint32_t)(id - 0x00fe) * 0x160u;
}

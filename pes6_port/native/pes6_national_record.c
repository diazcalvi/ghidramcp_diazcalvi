#include "pes6_national_record.h"
#include "pes6_team_info_address.h"
uint32_t pes6_pc_national_record(uint32_t team_id, uint32_t slot_present,
 uint32_t special_record, uint32_t base_00, uint32_t base_cc, uint32_t base_fe)
{
 uint16_t id = (uint16_t)team_id;
 if ((id == 0x126 || id == 0x127) && slot_present) {
  uint32_t address = special_record + UINT32_C(0x58);
  if (address) return address;
 }
 if (id <= 0x3f) return base_00 + (uint32_t)id * UINT32_C(0x160);
 if (id >= 0xcc && id <= 0xdc)
  return base_cc + (uint32_t)(id - 0xcc) * UINT32_C(0x160);
 uint32_t address = pes6_pc_team_info_address(team_id, base_fe);
 return address ? address : UINT32_C(0xc97340);
}

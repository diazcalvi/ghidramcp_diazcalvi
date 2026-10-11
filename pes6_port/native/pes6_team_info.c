#include "pes6_team_info.h"
#include "pes6_team_category.h"
#include "pes6_team_record.h"
#include "pes6_national_record.h"
uint32_t pes6_pc_team_info(uint32_t team_id, int32_t index,
 const pes6_pc_team_context *c)
{
 if (index < 0) return 0;
 uint16_t id = (uint16_t)team_id;
 uint32_t category = pes6_pc_team_category(team_id,c->slot_present,c->referenced_id);
 uint32_t address;
 if ((id < 0xfe || id > 0x10d) && category == 3) {
  address = pes6_pc_team_record(id,c->slot_present,c->special_record,c->base_40,c->base_dd);
  if (!address && id >= 0x10e && id <= 0x10f)
   address = UINT32_C(0x1132098)+(uint32_t)(id-0x10e)*UINT32_C(0x220);
  if (!address && id >= 0x110 && id <= 0x111)
   return UINT32_C(0x11324d8)+((uint32_t)index+(uint32_t)(id-0x110)*4u)*62u;
 } else {
  address = pes6_pc_national_record(team_id,c->slot_present,c->special_record,c->base_00,c->base_cc,c->base_fe);
 }
 return address && index < 4 ? address+(uint32_t)index*62u : 0;
}

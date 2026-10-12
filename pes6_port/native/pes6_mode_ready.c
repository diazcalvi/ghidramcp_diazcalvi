#include "pes6_mode_ready.h"
#include "pes6_mode_advance.h"
uint32_t pes6_pc_mode_ready(uint8_t context[56],uint32_t index)
{
 /* Exact pinned predicate returns1; no unresolved call is stubbed. */
 return pes6_pc_mode_advance(context,index);
}
uint32_t pes6_pc_mode_ready_top(uint8_t context[56])
{
 return pes6_pc_mode_ready(context,0);
}

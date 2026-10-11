#include "pes6_selection_step.h"
uint32_t pes6_pc_selection_step(uint8_t directions,int32_t value,int32_t lower,int32_t upper)
{
 if (directions & 0xa0) {
  if (upper == 1) {
   if (value == 1) return 1;
   if (value > 1) return (uint32_t)lower;
  } else if (value >= upper) return (uint32_t)lower;
  return (uint32_t)value + 1u;
 }
 if (directions & 0x50) {
  if (upper == 1) {
   if (value == lower) return (uint32_t)value;
   if (value < lower) return 1;
  } else if (value <= lower) return (uint32_t)upper;
  return (uint32_t)value - 1u;
 }
 return (uint32_t)value;
}

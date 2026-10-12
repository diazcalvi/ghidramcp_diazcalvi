#ifndef PES6_MODE_READY_H
#define PES6_MODE_READY_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* PC0xa9de10 calls predicate0xaed890, which is exactly return1 in the
 * pinned build, then advances state. Defined index/domain inherited from
 * pes6_pc_mode_advance. Must revalidate predicate for other executables.
 */
uint32_t pes6_pc_mode_ready(uint8_t context[56],uint32_t index);
/* Callback0xa4b6b0 forces index0 via forwarding thunk0xa69740. */
uint32_t pes6_pc_mode_ready_top(uint8_t context[56]);
#ifdef __cplusplus
}
#endif
#endif

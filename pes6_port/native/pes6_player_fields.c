#include "pes6_player_fields.h"

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void write_le32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16); p[3] = (uint8_t)(value >> 24);
}

uint8_t *pes6_pc_copy_player_fields(uint8_t *dst, const uint8_t *src,
                                    uint16_t player_id) {
    for (unsigned i = 0; i < 9; ++i)
        write_le32(dst + i * 4, read_le32(src + i * 4));
    uint32_t x = read_le32(src + 0x3c) << 8;
    uint32_t y = read_le32(dst + 0x24);
    y ^= (x ^ y) & UINT32_C(0x0001ff00);
    write_le32(dst + 0x24, y);

    x = read_le32(src + 0x3c) << 7;
    uint32_t z = read_le32(dst + 0x28);
    uint32_t saved24 = read_le32(dst + 0x24);
    z ^= (x ^ z) & UINT32_C(0x001f0000);
    write_le32(dst + 0x28, z);

    x = read_le32(src + 0x24);
    z ^= (x ^ z) & UINT32_C(0x00007f00);
    write_le32(dst + 0x28, z);

    x = read_le32(src + 0x24) << 2;
    y = saved24 ^ ((x ^ saved24) & UINT32_C(0x000000fc));
    write_le32(dst + 0x24, y);
    uint32_t field9 = (y >> 8) & UINT32_C(0x1ff);
    uint32_t flags = (field9 == 26 ? UINT32_C(1) << 21 : 0) |
                     (field9 <= 30 ? UINT32_C(1) << 15 : 0);
    z = (read_le32(dst + 0x28) & UINT32_C(0xffdf7fff)) | flags;
    write_le32(dst + 0x28, z);
    if (player_id != UINT16_C(0x04cc) && player_id != UINT16_C(0x0ea8))
        write_le32(dst + 0x24, read_le32(dst + 0x24) & UINT32_C(0xfffffffe));
    else
        write_le32(dst + 0x24, read_le32(dst + 0x24) | UINT32_C(1));
    return dst;
}

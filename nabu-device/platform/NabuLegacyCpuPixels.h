// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>

static inline bool nabu_cpu_rows(uint32_t width, uint32_t height,
    uint64_t stride, uint64_t bytes) {
    return width && height && width <= 16384 && height <= 16384 &&
        stride >= (uint64_t)width * 4 && stride <= UINT64_MAX / height &&
        bytes >= stride * height;
}

static inline bool nabu_cpu_single_layer(uint32_t updated, uint32_t disabled,
    uint32_t background, bool blank) {
    const uint32_t known = 0x8000000fU;
    if (((updated | disabled) & ~known) || (disabled & ~updated)) return false;
    if (blank ? (!updated || updated != disabled) : ((updated & ~disabled) != 1)) return false;
    if (updated & 0x80000000U)
        return (disabled & 0x80000000U) && background == 0xff000000U;
    return background == 0;
}

static inline bool nabu_cpu_destination(volatile void *destination,
    uint64_t bytes, uint64_t stride, uint32_t width, uint32_t height) {
    uintptr_t address = (uintptr_t)destination;
    return address && !(address & 3) && !(stride & 3) &&
        nabu_cpu_rows(width, height, stride, bytes) &&
        bytes <= UINTPTR_MAX && address <= UINTPTR_MAX - bytes;
}

static inline bool nabu_cpu_copy_bgra(volatile void *destination,
    uint64_t destinationBytes, uint64_t destinationStride, const void *source,
    uint64_t sourceBytes, uint64_t sourceStride, uint32_t width, uint32_t height) {
    uintptr_t src = (uintptr_t)source, dst = (uintptr_t)destination;
    if (!nabu_cpu_destination(destination, destinationBytes, destinationStride, width, height) ||
        !src || !nabu_cpu_rows(width, height, sourceStride, sourceBytes) ||
        sourceBytes > UINTPTR_MAX || src > UINTPTR_MAX - sourceBytes) return false;
    // As UniXNU native_legacy_copy_pixels: BGRA words move unchanged; aligned 64-bit
    // device stores (four per iteration) when base and stride allow, else 32-bit.
    bool wide = !(dst & 7) && !(destinationStride & 7);
    for (uint32_t y = 0; y < height; ++y) {
        const unsigned char *in = (const unsigned char *)(src + y * sourceStride);
        volatile uint32_t *out = (volatile uint32_t *)(dst + y * destinationStride);
        uint32_t x = 0;
        if (wide) {
            volatile uint64_t *out64 = (volatile uint64_t *)out;
            for (; x + 8 <= width; x += 8) {
                uint64_t a, b, c, d;
                __builtin_memcpy(&a, in + (uint64_t)x * 4, 8); __builtin_memcpy(&b, in + (uint64_t)x * 4 + 8, 8);
                __builtin_memcpy(&c, in + (uint64_t)x * 4 + 16, 8); __builtin_memcpy(&d, in + (uint64_t)x * 4 + 24, 8);
                out64[x / 2] = a; out64[x / 2 + 1] = b; out64[x / 2 + 2] = c; out64[x / 2 + 3] = d;
            }
        }
        for (; x < width; ++x) {
            uint32_t value;
            __builtin_memcpy(&value, in + (uint64_t)x * 4, 4);
            out[x] = value;
        }
    }
    return true;
}

static inline bool nabu_cpu_black(volatile void *destination, uint64_t bytes,
    uint64_t stride, uint32_t width, uint32_t height) {
    if (!nabu_cpu_destination(destination, bytes, stride, width, height)) return false;
    for (uint32_t y = 0; y < height; ++y) {
        volatile uint32_t *out = (volatile uint32_t *)((uintptr_t)destination + y * stride);
        for (uint32_t x = 0; x < width; ++x) out[x] = 0xff000000U;
    }
    return true;
}

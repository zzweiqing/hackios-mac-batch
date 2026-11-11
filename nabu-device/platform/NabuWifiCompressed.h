/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_COMPRESSED_H
#define NABU_WIFI_COMPRESSED_H
#include "NabuWifiBundle.h"

namespace nabu_wifi {
struct CompressedFirmware {
    const uint8_t *packed;
    size_t packed_bytes, raw_bytes;
    uint8_t raw_digest[32];

    static bool inspect(const uint8_t *data, size_t bytes, const uint8_t expected[32],
                        DigestFn digest, CompressedFirmware *out) {
        if (!out) return false;
        *out = CompressedFirmware{};
        if (!data || !expected || !digest || bytes <= FirmwareBundle::kBlock ||
            bytes > FirmwareBundle::kMaxBytes || bytes > UINTPTR_MAX - reinterpret_cast<uintptr_t>(data) ||
            memcmp(data, "NWIFIZ01", 8)) return false;
        uint8_t actual[32];
        digest(data, bytes, actual);
        if (memcmp(actual, expected, 32) || u32(data + 8) != 1 || u32(data + 12) != FirmwareBundle::kBlock)
            return false;
        const uint64_t raw = u64(data + 16), packed = u64(data + 24);
        if (raw < FirmwareBundle::kBlock || raw > FirmwareBundle::kMaxBytes ||
            packed != bytes - FirmwareBundle::kBlock) return false;
        for (size_t i = 64; i < FirmwareBundle::kBlock; ++i) if (data[i]) return false;
        out->packed = data + FirmwareBundle::kBlock;
        out->packed_bytes = static_cast<size_t>(packed);
        out->raw_bytes = static_cast<size_t>(raw);
        memcpy(out->raw_digest, data + 32, 32);
        return true;
    }
private:
    static uint32_t u32(const uint8_t *p) {
        return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
    }
    static uint64_t u64(const uint8_t *p) { return u32(p) | uint64_t(u32(p + 4)) << 32; }
};
} // namespace nabu_wifi
#endif

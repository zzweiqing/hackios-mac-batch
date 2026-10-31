/* SPDX-License-Identifier: MIT */
/* Closed ABI1 probe addon, with an optional owner-signed launchd job cache and,
 * with that cache, an optional owner-signed Turnip library for the Vulkan known-image test. */
#ifndef NABU_GPU_USERPROBE_ADDON_H
#define NABU_GPU_USERPROBE_ADDON_H
#include <stdint.h>
#include <string.h>

/* Without the Turnip library the bound stays 1 MiB; with it, the packed addon (zlib) stays within the
 * 16 MiB DarwinBoot ADT sidecar read and the library itself within 32 MiB. */
#define NABU_GPU_USERPROBE_ADDON_MAX 1048576u
#define NABU_GPU_USERPROBE_TURNIP_ADDON_MAX 12582912u
#define NABU_GPU_USERPROBE_TURNIP_MAX 33554432u
#define NABU_GPU_USERPROBE_EXE_MAX 131072u
#define NABU_GPU_USERPROBE_PLIST_MAX 4096u
#define NABU_GPU_USERPROBE_CACHE_MAX 2097152u
#define NABU_GPU_USERPROBE_SIGNATURE_MAX 65536u

static inline uint32_t nabu_probe_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t nabu_probe_u64(const uint8_t *p)
{
    return (uint64_t)nabu_probe_u32(p) | ((uint64_t)nabu_probe_u32(p + 4) << 32);
}

static inline int nabu_probe_zero(const uint8_t *p, uint64_t bytes)
{
    for (uint64_t i = 0; i < bytes; ++i) if (p[i]) return 0;
    return 1;
}

static inline int nabu_gpu_userprobe_addon_valid(const uint8_t *data, uint64_t bytes)
{
    static const char executable[] = "bin/nabu-gpu-userprobe";
    static const char job[] = "daemons/org.hackios.nabu-gpu-userprobe.plist";
    static const char cache[] = "cache/launchd.plist";
    static const char signature[] = "cache/launchd.plist.sig";
    static const char turnip[] = "bin/libvulkan_freedreno.dylib";
    if (!data || bytes < 24 || memcmp(data, "NGPUADD2", 8) ||
        nabu_probe_u32(data + 12) || nabu_probe_u64(data + 16) != bytes) return 0;
    const unsigned count=nabu_probe_u32(data + 8);
    if(count!=2 && count!=4 && count!=5)return 0;
    const uint64_t limit = count == 5 ? NABU_GPU_USERPROBE_TURNIP_ADDON_MAX : NABU_GPU_USERPROBE_ADDON_MAX;
    if (bytes > limit) return 0;
    uint64_t at = 24;
    unsigned seen = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (at > bytes || bytes - at < 24) return 0;
        const uint32_t name_bytes = nabu_probe_u32(data + at);
        const uint32_t mode = nabu_probe_u32(data + at + 4);
        const uint64_t size = nabu_probe_u64(data + at + 8);
        const uint64_t packed = nabu_probe_u64(data + at + 16);
        at += 24;
        if (name_bytes < 2 || name_bytes > 160 || !packed || packed > limit) return 0;
        const uint64_t name_padded = ((uint64_t)name_bytes + 7) & ~UINT64_C(7);
        const uint64_t packed_padded = (packed + 7) & ~UINT64_C(7);
        if (bytes - at < name_padded || bytes - at - name_padded < packed_padded) return 0;
        unsigned kind = 0;
        if (name_bytes == sizeof(executable) && !memcmp(data + at, executable, sizeof(executable)) &&
            mode == 0755 && size && size <= NABU_GPU_USERPROBE_EXE_MAX) kind = 1;
        if (name_bytes == sizeof(job) && !memcmp(data + at, job, sizeof(job)) &&
            mode == 0644 && size && size <= NABU_GPU_USERPROBE_PLIST_MAX) kind = 2;
        if (count>=4 && name_bytes == sizeof(cache) && !memcmp(data + at, cache, sizeof(cache)) &&
            mode == 0644 && size && size <= NABU_GPU_USERPROBE_CACHE_MAX) kind = 4;
        if (count>=4 && name_bytes == sizeof(signature) && !memcmp(data + at, signature, sizeof(signature)) &&
            mode == 0644 && size && size <= NABU_GPU_USERPROBE_SIGNATURE_MAX) kind = 8;
        if (count==5 && name_bytes == sizeof(turnip) && !memcmp(data + at, turnip, sizeof(turnip)) &&
            mode == 0644 && size && size <= NABU_GPU_USERPROBE_TURNIP_MAX) kind = 16;
        if (!kind || (seen & kind) ||
            !nabu_probe_zero(data + at + name_bytes, name_padded - name_bytes) ||
            !nabu_probe_zero(data + at + name_padded + packed, packed_padded - packed)) return 0;
        seen |= kind;
        at += name_padded + packed_padded;
    }
    return seen == (count==5?31u:count==4?15u:3u) && at == bytes;
}
#endif

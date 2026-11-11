/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_INFLATE_H
#define NABU_WIFI_INFLATE_H
#include "NabuWifiCompressed.h"
#ifdef NABU_WIFI_INFLATE_HOST_TEST
#include <zlib.h>
#else
#include <libkern/zlib.h>
#endif

namespace nabu_wifi {
struct InflateAllocator {
    void *(*allocate)(size_t);
    void (*release)(void *, size_t);
};
struct InflateResult {
    int initialized, status, ended;
    uint64_t input_bytes, output_bytes;
    bool valid;
};
inline void *inflateAllocate(void *ctx, unsigned items, unsigned size) {
    const size_t bytes = size_t(items) * size;
    if (!bytes || (size && bytes / size != items) || bytes > 1024 * 1024) return nullptr;
    InflateAllocator *allocator = static_cast<InflateAllocator *>(ctx);
    size_t *allocation = static_cast<size_t *>(allocator->allocate(bytes + sizeof(size_t)));
    if (!allocation) return nullptr;
    *allocation = bytes + sizeof(size_t);
    memset(allocation + 1, 0, bytes);
    return allocation + 1;
}
inline void inflateRelease(void *ctx, void *address) {
    if (!address) return;
    InflateAllocator *allocator = static_cast<InflateAllocator *>(ctx);
    size_t *allocation = static_cast<size_t *>(address) - 1;
    allocator->release(allocation, *allocation);
}
inline InflateResult inflateFirmware(const CompressedFirmware &input, uint8_t *raw, size_t bytes,
                                     InflateAllocator allocator) {
    InflateResult result{};
    if (!raw || bytes != input.raw_bytes || !input.packed || !input.packed_bytes ||
        input.packed_bytes > FirmwareBundle::kMaxBytes || bytes > FirmwareBundle::kMaxBytes ||
        !allocator.allocate || !allocator.release) return result;
    z_stream stream{};
    stream.opaque = &allocator;
    stream.zalloc = inflateAllocate;
    stream.zfree = inflateRelease;
    stream.next_in = const_cast<uint8_t *>(input.packed);
    stream.avail_in = static_cast<unsigned>(input.packed_bytes);
    stream.next_out = raw;
    stream.avail_out = static_cast<unsigned>(bytes);
    result.initialized = inflateInit(&stream);
    result.status = result.initialized;
    if (result.initialized == Z_OK) result.status = inflate(&stream, Z_FINISH);
    result.input_bytes = stream.total_in;
    result.output_bytes = stream.total_out;
    const bool complete = result.status == Z_STREAM_END && stream.avail_in == 0 &&
        stream.total_in == input.packed_bytes && stream.total_out == bytes;
    result.ended = result.initialized == Z_OK ? inflateEnd(&stream) : result.initialized;
    result.valid = complete && result.ended == Z_OK;
    return result;
}
} // namespace nabu_wifi
#endif

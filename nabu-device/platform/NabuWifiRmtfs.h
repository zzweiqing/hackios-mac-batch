/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * RAM-only backing for the future nabu MPSS RMTFS service. The modem needs
 * writable EFS semantics to keep its WLAN user-PD alive. These operations
 * modify a private RAM copy of the four saved NV partitions; this type has
 * no block-device, filesystem or arbitrary physical-memory access hooks.
 *
 * Single wireless executor only. This is the storage backend, not a QMI
 * service or an MPSS boot implementation. Keep its arena alive until the
 * modem is stopped and any shared-memory users are quiescent.
 */
#ifndef NABU_WIFI_RMTFS_H
#define NABU_WIFI_RMTFS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace nabu_wifi {

class RmtfsRamStore {
public:
    enum { kPartitionCount = 4, kSectorBytes = 512 };
    /* Index order is modemst1, modemst2, fsg, fsc. Wire handles are 1..4. */
    struct Seed { const uint8_t *data; size_t bytes; };
    struct Stats { uint64_t reads, writes, read_bytes, written_bytes; };

    RmtfsRamStore() : arena_(nullptr), arena_bytes_(0), ready_(false), stats_{} {
        memset(parts_, 0, sizeof(parts_));
        memset(seeds_, 0, sizeof(seeds_));
    }
    RmtfsRamStore(const RmtfsRamStore &) = delete;
    RmtfsRamStore &operator=(const RmtfsRamStore &) = delete;

    bool initialize(const Seed (&seeds)[kPartitionCount], void *arena, size_t arena_bytes) {
        if (ready_ || !validSpan(arena, arena_bytes)) return false;
        size_t total = 0;
        for (unsigned i = 0; i < kPartitionCount; ++i) {
            if (!validSpan(seeds[i].data, seeds[i].bytes) || seeds[i].bytes % kSectorBytes ||
                seeds[i].bytes > arena_bytes - total ||
                overlaps(arena, arena_bytes, seeds[i].data, seeds[i].bytes)) return false;
            total += seeds[i].bytes;
        }
        uint8_t *cursor = static_cast<uint8_t *>(arena);
        for (unsigned i = 0; i < kPartitionCount; ++i) {
            seeds_[i] = seeds[i];
            parts_[i] = Part{cursor, seeds[i].bytes};
            memcpy(cursor, seeds[i].data, seeds[i].bytes);
            cursor += seeds[i].bytes;
        }
        arena_ = static_cast<uint8_t *>(arena);
        arena_bytes_ = total;
        ready_ = true;
        return true;
    }

    bool read(unsigned handle, uint64_t sector, uint64_t count,
              void *shared_buffer, size_t shared_bytes) {
        size_t offset, bytes;
        if (!request(handle, sector, count, shared_buffer, shared_bytes, &offset, &bytes)) return false;
        /* Even a bad transport adapter cannot overwrite the original seed. */
        for (unsigned i = 0; i < kPartitionCount; ++i)
            if (overlaps(shared_buffer, bytes, seeds_[i].data, seeds_[i].bytes)) return false;
        memcpy(shared_buffer, parts_[handle - 1].data + offset, bytes);
        ++stats_.reads;
        stats_.read_bytes += bytes;
        return true;
    }

    bool write(unsigned handle, uint64_t sector, uint64_t count,
               const void *shared_buffer, size_t shared_bytes) {
        size_t offset, bytes;
        if (!request(handle, sector, count, shared_buffer, shared_bytes, &offset, &bytes)) return false;
        memcpy(parts_[handle - 1].data + offset, shared_buffer, bytes);
        ++stats_.writes;
        stats_.written_bytes += bytes;
        return true;
    }

    bool ready() const { return ready_; }
    Stats stats() const { return stats_; }

    /* Caller must first stop/quiet the modem; this never reclaims TZ memory. */
    void clear() {
        if (arena_) {
            volatile uint8_t *cursor = arena_;
            for (size_t i = 0; i < arena_bytes_; ++i) cursor[i] = 0;
        }
        memset(parts_, 0, sizeof(parts_));
        memset(seeds_, 0, sizeof(seeds_));
        arena_ = nullptr;
        arena_bytes_ = 0;
        ready_ = false;
        stats_ = Stats{};
    }

private:
    struct Part { uint8_t *data; size_t bytes; };
    Part parts_[kPartitionCount];
    Seed seeds_[kPartitionCount];
    uint8_t *arena_;
    size_t arena_bytes_;
    bool ready_;
    Stats stats_;

    static bool validSpan(const void *data, size_t bytes) {
        return data && bytes && bytes <= UINTPTR_MAX - reinterpret_cast<uintptr_t>(data);
    }
    static bool overlaps(const void *a, size_t an, const void *b, size_t bn) {
        const uintptr_t ap = reinterpret_cast<uintptr_t>(a), bp = reinterpret_cast<uintptr_t>(b);
        return ap < bp + bn && bp < ap + an;
    }
    bool request(unsigned handle, uint64_t sector, uint64_t count,
                 const void *buffer, size_t buffer_bytes, size_t *offset, size_t *bytes) const {
        if (!ready_ || handle < 1 || handle > kPartitionCount || !count ||
            !validSpan(buffer, buffer_bytes)) return false;
        const Part &part = parts_[handle - 1];
        const uint64_t sectors = part.bytes / kSectorBytes;
        /* Subtract before multiplying: neither sector+count nor count*512
         * may wrap when decoding an untrusted modem request. */
        if (sector > sectors || count > sectors - sector || count > buffer_bytes / kSectorBytes) return false;
        *offset = static_cast<size_t>(sector) * kSectorBytes;
        *bytes = static_cast<size_t>(count) * kSectorBytes;
        return !overlaps(buffer, *bytes, arena_, arena_bytes_);
    }
};

} // namespace nabu_wifi
#endif

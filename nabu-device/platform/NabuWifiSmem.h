/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SMEM v12 host-pair/global partitions, word-access device mappings only.
 * Layout/protocol reference: ios-flame 745c434 phone/wifi/smem.c, Linux SMEM.
 * The caller owns these mappings and keeps them alive through modem shutdown.
 */
#ifndef NABU_WIFI_SMEM_H
#define NABU_WIFI_SMEM_H
#include "NabuWifiProtocol.h"

namespace nabu_wifi {
class Smem {
public:
    struct Mapping {
        volatile uint8_t *memory, *ipc, *mutex;
        uint64_t memory_phys, ipc_phys, mutex_phys;
        size_t memory_bytes;
    };
    struct Item { uint32_t offset, bytes; };
    enum Result { Ok, Missing, Invalid, LockTimeout, NoSpace };
    Smem() : map_{}, parts_{}, count_(0), ready_(false) {}
    static void barrier() {
#if defined(__aarch64__) || defined(__arm64__)
        __asm__ volatile("dsb sy" ::: "memory");
#else
        __sync_synchronize();
#endif
    }
    Result initialize(const Mapping &mapping) {
        if (ready_ || !mapping.memory || !mapping.ipc || !mapping.mutex ||
            (reinterpret_cast<uintptr_t>(mapping.memory) & 3) ||
            (reinterpret_cast<uintptr_t>(mapping.ipc) & 3) ||
            (reinterpret_cast<uintptr_t>(mapping.mutex) & 3) ||
            mapping.memory_phys != 0x86000000ull || mapping.memory_bytes != 0x200000 ||
            mapping.ipc_phys != 0x17c0000c || mapping.mutex_phys != 0x1f43000) return Invalid;
        map_ = mapping;
        const uint32_t toc = uint32_t(map_.memory_bytes - 4096);
        if (read(toc) != 0x434f5424 || read(toc + 4) != 1) return Invalid;
        const uint32_t entries = read(toc + 8);
        if (entries > 32 || 32 + entries * 48 > 4096) return Invalid;
        for (unsigned i = 0; i < entries; ++i) {
            const uint32_t at = toc + 32 + i * 48;
            const uint32_t offset = read(at), bytes = read(at + 4), hosts = read(at + 12);
            const uint16_t h0 = uint16_t(hosts), h1 = uint16_t(hosts >> 16);
            if (!offset && !bytes) continue;
            /* Never touch partitions owned solely by other remote processors. */
            if (!(h0 == 0xfffe && h1 == 0xfffe) && !((h0 == 0 && h1 == 1) || (h0 == 1 && h1 == 0))) continue;
            const uint32_t line = read(at + 16);
            if (offset < 4096 || (offset & 7) || bytes < 32 || (bytes & 7) ||
                offset > toc || bytes > toc - offset || line < 16 || line > 4096 || (line & (line - 1))) return Invalid;
            for (unsigned j = 0; j < count_; ++j)
                if ((parts_[j].host0 == h0 && parts_[j].host1 == h1) || (parts_[j].host0 == h1 && parts_[j].host1 == h0) ||
                    (offset < parts_[j].offset + parts_[j].bytes && parts_[j].offset < offset + bytes)) return Invalid;
            if (read(offset) != 0x54525024 || read(offset + 4) != hosts || read(offset + 8) != bytes) return Invalid;
            parts_[count_++] = Part{offset, bytes, line, h0, h1};
        }
        ready_ = count_ != 0;
        return ready_ ? Ok : Invalid;
    }
    Result get(uint16_t item, Item &out) const {
        if (!ready_) return Invalid;
        for (unsigned pass = 0; pass < 2; ++pass) {
            for (unsigned i = 0; i < count_; ++i) {
                const bool global = parts_[i].host0 == 0xfffe;
                if (global != (pass == 1)) continue;
                const Result result = find(parts_[i], item, out);
                if (result != Missing) return result;
            }
        }
        return Missing;
    }
    Result allocate(uint16_t item, uint32_t bytes, Item &out, bool &created) {
        created = false;
        Result result = get(item, out);
        if (result == Ok) return out.bytes >= bytes ? Ok : Invalid;
        if (result != Missing || !bytes || bytes > 0x10000) return Invalid;
        bool locked = false;
        for (unsigned attempt = 0; attempt < 100000; ++attempt) {
            *reinterpret_cast<volatile uint32_t *>(map_.mutex) = 1;
            barrier();
            if (*reinterpret_cast<volatile uint32_t *>(map_.mutex) == 1) { locked = true; break; }
        }
        if (!locked) return LockTimeout;
        barrier();
        result = get(item, out);
        if (result == Missing) {
            const Part *part = nullptr;
            for (unsigned i = 0; i < count_; ++i) if (parts_[i].host0 != 0xfffe) part = &parts_[i];
            if (!part) result = Invalid;
            else {
                const uint32_t unc = read(part->offset + 12), cached = read(part->offset + 16);
                const uint32_t aligned = (bytes + 7) & ~7u;
                if (unc < 32 || (unc & 7) || unc > cached || cached > part->bytes) result = Invalid;
                else if (16 + aligned > cached - unc) result = NoSpace;
                else {
                    const uint32_t at = part->offset + unc;
                    write(at, 0xa5a5u | uint32_t(item) << 16); write(at + 4, aligned);
                    write(at + 8, aligned - bytes); write(at + 12, 0);
                    for (uint32_t n = 0; n < aligned; n += 4) write(at + 16 + n, 0);
                    barrier(); write(part->offset + 12, unc + 16 + aligned); barrier();
                    out = Item{at + 16, bytes}; created = true; result = Ok;
                }
            }
        } else if (result == Ok && out.bytes < bytes) result = Invalid;
        barrier(); *reinterpret_cast<volatile uint32_t *>(map_.mutex) = 0;
        return result;
    }
    uint32_t read(uint32_t offset) const { return *reinterpret_cast<volatile uint32_t *>(map_.memory + offset); }
    void write(uint32_t offset, uint32_t value) { *reinterpret_cast<volatile uint32_t *>(map_.memory + offset) = value; }
    void kick(unsigned bit) { barrier(); *reinterpret_cast<volatile uint32_t *>(map_.ipc) = uint32_t(1) << bit; }
    void copyOut(uint32_t offset, void *output, size_t bytes) const {
        uint8_t *p = static_cast<uint8_t *>(output);
        for (size_t i = 0; i < bytes; ++i) p[i] = uint8_t(read((offset + uint32_t(i)) & ~3u) >> (8 * ((offset + i) & 3)));
    }
private:
    struct Part { uint32_t offset, bytes, line; uint16_t host0, host1; };
    Mapping map_;
    Part parts_[32];
    unsigned count_;
    bool ready_;
    Result find(const Part &part, uint16_t item, Item &out) const {
        const uint32_t unc = read(part.offset + 12), cached = read(part.offset + 16);
        barrier();
        if (unc < 32 || unc > cached || cached > part.bytes || (unc & 7)) return Invalid;
        for (uint32_t at = 32; at < unc;) {
            if (unc - at < 16) return Invalid;
            const uint32_t entry = part.offset + at, tag = read(entry), bytes = read(entry + 4), padding = read(entry + 8);
            const uint32_t pad_data = padding & 0xffff, pad_header = padding >> 16;
            if (uint16_t(tag) != 0xa5a5 || pad_data > bytes || pad_header > unc - at - 16 ||
                bytes > unc - at - 16 - pad_header || ((16 + pad_header + bytes) & 7)) return Invalid;
            if (uint16_t(tag >> 16) == item) { out = Item{entry + 16 + pad_header, bytes - pad_data}; return Ok; }
            at += 16 + pad_header + bytes;
        }
        const uint32_t header = (16 + part.line - 1) & ~(part.line - 1);
        if (part.bytes - cached < header) return part.bytes == cached ? Missing : Invalid;
        uint32_t end = part.bytes;
        while (end > cached) {
            if (end - cached < header) return Invalid;
            const uint32_t at = end - header, entry = part.offset + at;
            const uint32_t tag = read(entry), bytes = read(entry + 4), padding = read(entry + 8);
            if (uint16_t(tag) != 0xa5a5 || (padding & 0xffff) > bytes || bytes > at - cached ||
                (padding >> 16) > header - 16 || (bytes & (part.line - 1))) return Invalid;
            if (uint16_t(tag >> 16) == item) { out = Item{entry - bytes, bytes - (padding & 0xffff)}; return Ok; }
            end = at - bytes;
        }
        return Missing;
    }
};
} // namespace nabu_wifi
#endif

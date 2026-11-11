/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_BUNDLE_H
#define NABU_WIFI_BUNDLE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace nabu_wifi {

/* The platform supplies its existing SHA-256 implementation. This parser is
 * shared by the actual kernel loader and the portable malformed-input harness. */
typedef void (*DigestFn)(const void *, size_t, uint8_t[32]);
class FirmwareBundle {
public:
    static constexpr size_t kBlock = 4096;
    static constexpr size_t kEntry = 160;
    static constexpr size_t kMaxBytes = 64 * 1024 * 1024;
    FirmwareBundle() : data_(nullptr), count_(0) {}

    bool open(const uint8_t *data, size_t bytes, const uint8_t expected[32], DigestFn digest) {
        data_ = nullptr;
        count_ = 0;
        if (!data || !expected || !digest || bytes < kBlock || bytes > kMaxBytes ||
            bytes > UINTPTR_MAX - reinterpret_cast<uintptr_t>(data)) return false;
        if (!hashMatches(data, bytes, expected, digest) || memcmp(data, "NWIFIPK1", 8) ||
            u32(data + 8) != 1 || u32(data + 12) != kBlock || u64(data + 16) != bytes ||
            !u32(data + 24) || u32(data + 24) > 256 || u32(data + 28) != kEntry ||
            u64(data + 32) != kBlock || !zero(data + 144, kBlock - 144)) return false;
        const uint32_t count = u32(data + 24);
        const size_t table_end = kBlock + count * kEntry;
        size_t cursor = align(table_end);
        if (u64(data + 40) != cursor || cursor > bytes ||
            !hashMatches(data + kBlock, count * kEntry, data + 80, digest) ||
            !zero(data + table_end, cursor - table_end)) return false;
        for (uint32_t i = 0; i < count; ++i) {
            const uint8_t *entry = data + kBlock + i * kEntry;
            if (!pathValid(entry) || !zero(entry + 144, 16)) return false;
            for (uint32_t j = 0; j < i; ++j) {
                if (!memcmp(entry, data + kBlock + j * kEntry, 96)) return false;
            }
            const uint64_t offset = u64(entry + 96), length = u64(entry + 104);
            if (offset != cursor || !length || offset > bytes || length > bytes - offset ||
                !hashMatches(data + cursor, static_cast<size_t>(length), entry + 112, digest)) return false;
            const size_t end = cursor + static_cast<size_t>(length);
            cursor = align(end);
            if (cursor > bytes || !zero(data + end, cursor - end)) return false;
        }
        if (cursor != bytes) return false;
        data_ = data;
        count_ = count;
        static const char *required[] = {
            "firmware/modem.mdt", "firmware/wlanmdsp.mbn", "firmware/modemr.jsn", "firmware/modemuw.jsn",
            "rmtfs-seed/modemst1.img", "rmtfs-seed/modemst2.img", "rmtfs-seed/fsg.img", "rmtfs-seed/fsc.img",
            "configuration/board-contract.json"
        };
        for (const char *path : required) {
            const uint8_t *content;
            size_t length;
            if (!getFile(path, &content, &length)) { data_ = nullptr; count_ = 0; return false; }
        }
        const uint8_t *board;
        size_t board_bytes;
        getFile("configuration/board-contract.json", &board, &board_bytes);
        if (!hashMatches(board, board_bytes, data + 112, digest)) { data_ = nullptr; count_ = 0; return false; }
        return true;
    }

    bool getFile(const char *path, const uint8_t **content, size_t *bytes) const {
        if (content) *content = nullptr;
        if (bytes) *bytes = 0;
        if (!data_ || !path || !content || !bytes) return false;
        for (uint32_t i = 0; i < count_; ++i) {
            const uint8_t *entry = data_ + kBlock + i * kEntry;
            if (!strcmp(path, reinterpret_cast<const char *>(entry))) {
                *content = data_ + u64(entry + 96);
                *bytes = static_cast<size_t>(u64(entry + 104));
                return true;
            }
        }
        return false;
    }
    uint32_t fileCount() const { return count_; }
    const uint8_t *bundleId() const { return data_ ? data_ + 48 : nullptr; }

private:
    const uint8_t *data_;
    uint32_t count_;
    static uint32_t u32(const uint8_t *p) {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }
    static uint64_t u64(const uint8_t *p) { return u32(p) | (uint64_t(u32(p + 4)) << 32); }
    static size_t align(size_t value) { return (value + kBlock - 1) & ~(kBlock - 1); }
    static bool zero(const uint8_t *p, size_t bytes) {
        for (size_t i = 0; i < bytes; ++i) if (p[i]) return false;
        return true;
    }
    static bool hashMatches(const void *p, size_t bytes, const uint8_t expected[32], DigestFn digest) {
        uint8_t actual[32];
        digest(p, bytes, actual);
        return !memcmp(actual, expected, sizeof(actual));
    }
    static bool pathValid(const uint8_t *p) {
        size_t length = 0;
        while (length < 96 && p[length]) ++length;
        if (!length || length == 96 || !zero(p + length, 96 - length)) return false;
        const char *path = reinterpret_cast<const char *>(p);
        if (!strcmp(path, "configuration/board-contract.json") ||
            !strcmp(path, "rmtfs-seed/modemst1.img") || !strcmp(path, "rmtfs-seed/modemst2.img") ||
            !strcmp(path, "rmtfs-seed/fsg.img") || !strcmp(path, "rmtfs-seed/fsc.img")) return true;
        if (length <= 9 || memcmp(p, "firmware/", 9)) return false;
        for (size_t i = 9; i < length; ++i) {
            const uint8_t c = p[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.')) return false;
        }
        return true;
    }
};

} // namespace nabu_wifi
#endif

/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_VOLUME_H
#define NABU_WIFI_VOLUME_H
#include <stddef.h>
#include "NabuLogVolume.h"

/* Independent read-only media proof. The log writer's token, allocation, and
 * boot flag are absent from this interface. Shared endian/CRC/FAT primitives
 * retain their existing logging behavior. Allocate this state off the stack. */
struct nabu_wifi_volume {
    nb_log_volume media;
    uint32_t owners[262144];
    uint32_t file_bytes, owner_count;
    const char *failure;
};
static inline int nwv_fail(nabu_wifi_volume *v, const char *reason) {
    v->failure = reason;
    return 0;
}
static inline int nwv_read(nabu_wifi_volume *v, uint64_t lba, uint32_t blocks, uint8_t *data) {
    nb_log_volume *m = &v->media;
    if (!blocks || !data || lba >= m->lun_blocks || blocks > m->lun_blocks - lba ||
        ++m->reads > 131072) return nwv_fail(v, "read-range-budget");
    if (!m->read(m->context, lba, blocks, data)) return nwv_fail(v, "read-transport");
    return 1;
}
static inline int nwv_dir(nabu_wifi_volume *v, uint32_t cluster) {
    nb_log_volume *m = &v->media;
    return nb_cluster_ok(m, cluster) &&
        nwv_read(v, m->esp_first + m->data_first + cluster - 2, 1, m->scratch);
}
static inline int nwv_header(nabu_wifi_volume *v, uint64_t lba, uint64_t alternate,
                             uint64_t *table, uint32_t *count, uint32_t *array_crc,
                             uint64_t *first, uint64_t *last, uint8_t guid[16]) {
    nb_log_volume *m = &v->media;
    if (!nwv_read(v, lba, 1, m->scratch)) return 0;
    uint8_t *p = m->scratch;
    const uint32_t size = nb_le32(p + 12), crc = nb_le32(p + 16);
    *count = nb_le32(p + 80);
    *table = nb_le64(p + 72);
    *first = nb_le64(p + 40);
    *last = nb_le64(p + 48);
    *array_crc = nb_le32(p + 88);
    if (!nb_equal(p, "EFI PART", 8) || nb_le32(p + 8) != 0x10000 || size < 92 || size > 4096 ||
        nb_le32(p + 20) || nb_le64(p + 24) != lba || nb_le64(p + 32) != alternate ||
        *first < 2 || *first > *last || *last >= m->lun_blocks - 1 ||
        !*count || *count > 128 || nb_le32(p + 84) != 128) return nwv_fail(v, "gpt-header");
    nb_put32(p + 16, 0);
    if (nb_crc(p, size) != crc) return nwv_fail(v, "gpt-header-crc");
    nb_copy(guid, p + 56, 16);
    const uint64_t blocks = (*count * 128 + 4095) / 4096;
    if (lba == 1) {
        if (*table < 2 || *table >= *first || blocks > *first - *table) return nwv_fail(v, "gpt-primary-table-range");
    } else {
        if (*table <= *last || *table >= lba || blocks > lba - *table) return nwv_fail(v, "gpt-backup-table-range");
    }
    return 1;
}
static inline int nwv_claim(nabu_wifi_volume *v, uint32_t first, uint32_t minimum_blocks) {
    nb_log_volume *m = &v->media;
    uint32_t cluster = first, blocks = 0;
    const uint32_t owner = ++v->owner_count;
    for (uint32_t step = 0; step < m->clusters; ++step) {
        if (!nb_cluster_ok(m, cluster) || v->owners[cluster]) return nwv_fail(v, "fat-chain-cycle-alias");
        v->owners[cluster] = owner;
        ++blocks;
        const uint32_t next = nb_fat(m, cluster);
        if (next >= 0x0ffffff8) return blocks >= minimum_blocks ? 1 : nwv_fail(v, "fat-short-file");
        cluster = next;
    }
    return nwv_fail(v, "fat-chain-budget");
}
static inline int nwv_ownership(nabu_wifi_volume *v) {
    nb_log_volume *m = &v->media;
    unsigned head = 0, tail = 1, found = 0;
    m->directories[0] = m->root;
    if (!nwv_claim(v, m->root, 1)) return 0;
    while (head < tail) {
        const uint32_t initial = m->directories[head++];
        uint32_t cluster = initial;
        bool done = false;
        for (uint32_t step = 0; step < m->clusters && !done; ++step) {
            if (!nwv_dir(v, cluster)) return 0;
            for (unsigned at = 0; at < 4096; at += 32) {
                const uint8_t *entry = m->scratch + at;
                if (!entry[0]) { done = true; break; }
                if (entry[0] == 0xe5 || entry[11] == 15 || (entry[11] & 8) || entry[0] == '.') continue;
                const uint32_t first = nb_entry_cluster(entry), bytes = nb_le32(entry + 28);
                const bool directory = (entry[11] & 16) != 0;
                const bool target = initial == m->root && nb_equal(entry, "NWIFI   BIN", 11);
                if (target) {
                    if (directory || (entry[11] & 0xc0) || ++found != 1 || bytes < 4096 || bytes > 64u * 1024u * 1024u)
                        return nwv_fail(v, "package-root-entry");
                    m->file_cluster = first;
                    v->file_bytes = bytes;
                }
                if (!first) {
                    if (directory || bytes) return nwv_fail(v, "fat-empty-entry");
                    continue;
                }
                if (!nwv_claim(v, first, directory ? 1 : (bytes + 4095ULL) / 4096)) return 0;
                if (directory) {
                    if (tail == 1024) return nwv_fail(v, "fat-directory-budget");
                    m->directories[tail++] = first;
                }
            }
            if (done) break;
            const uint32_t next = nb_fat(m, cluster);
            if (next >= 0x0ffffff8) { done = true; break; }
            cluster = next;
        }
        if (!done) return nwv_fail(v, "fat-directory-chain");
    }
    if (found != 1) return nwv_fail(v, "package-missing");
    /* Reject an orphan allocation that points into a reachable chain too. */
    for (uint32_t cluster = 2; cluster < m->clusters + 2; ++cluster) {
        const uint32_t next = nb_fat(m, cluster);
        if (nb_cluster_ok(m, next) && v->owners[next] && v->owners[cluster] != v->owners[next])
            return nwv_fail(v, "fat-incoming-alias");
    }
    return 1;
}
static inline int nwv_open(nabu_wifi_volume *v, nb_log_read_fn read, void *ctx, uint64_t lun_blocks) {
    static const uint8_t esp_type[16] = {0x28,0x73,0x2a,0xc1,0x1f,0xf8,0xd2,0x11,0xba,0x4b,0,0xa0,0xc9,0x3e,0xc9,0x3b};
    nb_zero(v, sizeof(*v));
    nb_log_volume *m = &v->media;
    m->read = read;
    m->context = ctx;
    m->lun_blocks = lun_blocks;
    v->failure = "none";
    if (!read || lun_blocks < 8 || lun_blocks > 0xffffffffULL) return nwv_fail(v, "lun-size");
    uint64_t table, first, last, mirror_table, mirror_first, mirror_last;
    uint32_t count, array_crc, mirror_count, mirror_crc;
    uint8_t guid[16], mirror_guid[16];
    if (!nwv_header(v, 1, lun_blocks - 1, &table, &count, &array_crc, &first, &last, guid) ||
        !nwv_header(v, lun_blocks - 1, 1, &mirror_table, &mirror_count, &mirror_crc,
                    &mirror_first, &mirror_last, mirror_guid)) return 0;
    if (first != mirror_first || last != mirror_last || count != mirror_count || array_crc != mirror_crc ||
        !nb_equal(guid, mirror_guid, 16)) return nwv_fail(v, "gpt-metadata-mirror");
    const uint32_t blocks = (count * 128 + 4095) / 4096;
    if (!nwv_read(v, table, blocks, m->entries) || nb_crc(m->entries, count * 128) != array_crc)
        return nwv_fail(v, "gpt-entries-crc");
    for (unsigned i = 0; i < blocks; ++i) {
        if (!nwv_read(v, mirror_table + i, 1, m->scratch)) return 0;
        const unsigned bytes = count * 128 - i * 4096;
        if (!nb_equal(m->entries + i * 4096, m->scratch, bytes < 4096 ? bytes : 4096))
            return nwv_fail(v, "gpt-entries-mirror");
    }
    uint8_t zero[16] = {0};
    for (unsigned i = 0; i < count; ++i) {
        const uint8_t *entry = m->entries + i * 128;
        if (nb_equal(entry, zero, 16)) continue;
        const uint64_t start = nb_le64(entry + 32), end = nb_le64(entry + 40);
        if (start < first || end > last || start > end || nb_equal(entry + 16, zero, 16))
            return nwv_fail(v, "gpt-partition-range-guid");
        for (unsigned j = 0; j < i; ++j) {
            const uint8_t *other = m->entries + j * 128;
            if (nb_equal(other, zero, 16)) continue;
            if ((start <= nb_le64(other + 40) && nb_le64(other + 32) <= end) || nb_equal(entry + 16, other + 16, 16))
                return nwv_fail(v, "gpt-partition-alias");
        }
        if (nb_equal(entry, esp_type, 16)) {
            if (m->esp_first || !nb_equal(entry + 56, "e\0s\0p\0\0\0", 8)) return nwv_fail(v, "gpt-esp-identity");
            m->esp_first = start;
            m->esp_blocks = end - start + 1;
        }
    }
    if (!m->esp_first || !nwv_read(v, m->esp_first, 1, m->scratch)) return nwv_fail(v, "esp-missing-read");
    uint8_t *p = m->scratch;
    const uint32_t bps = p[11] | (uint32_t(p[12]) << 8), reserved = p[14] | (uint32_t(p[15]) << 8);
    const uint32_t total = nb_le32(p + 32), fat = nb_le32(p + 36);
    const uint8_t media_byte = p[21];
    if (bps != 4096 || p[13] != 1 || p[16] != 2 || !reserved || !fat || fat > 256 ||
        total != m->esp_blocks || reserved + 2ULL * fat >= total || p[40] || p[41] ||
        p[17] || p[18] || p[19] || p[20] || p[22] || p[23] || p[42] || p[43] ||
        p[510] != 0x55 || p[511] != 0xaa || !nb_equal(p + 82, "FAT32", 5)) return nwv_fail(v, "esp-geometry");
    m->fat_first = reserved;
    m->fat_blocks = fat;
    m->data_first = reserved + 2 * fat;
    m->clusters = total - m->data_first;
    m->root = nb_le32(p + 44);
    if (m->clusters < 65525 || (m->clusters + 2ULL) * 4 > fat * 4096ULL || !nb_cluster_ok(m, m->root))
        return nwv_fail(v, "esp-cluster-geometry");
    for (unsigned i = 0; i < fat; ++i) {
        if (!nwv_read(v, m->esp_first + reserved + i, 1, m->fat + 4096 * i) ||
            !nwv_read(v, m->esp_first + reserved + fat + i, 1, p) || !nb_equal(p, m->fat + 4096 * i, 4096))
            return nwv_fail(v, "fat-mirror");
    }
    if ((nb_fat(m, 0) & 0xff) != media_byte ||
        nb_fat(m, 0) < 0x0ffffff0 || nb_fat(m, 1) < 0x0ffffff8) return nwv_fail(v, "fat-reserved");
    return nwv_ownership(v);
}
static inline int nwv_copy_file(nabu_wifi_volume *v, uint8_t *data, size_t bytes) {
    if (!data || bytes != v->file_bytes) return nwv_fail(v, "file-output-range");
    nb_log_volume *m = &v->media;
    uint32_t cluster = m->file_cluster;
    for (size_t offset = 0; offset < bytes; offset += 4096) {
        if (!nb_cluster_ok(m, cluster)) return nwv_fail(v, "file-chain");
        const size_t remaining = bytes - offset;
        uint8_t *output = remaining < 4096 ? m->scratch : data + offset;
        if (!nwv_read(v, m->esp_first + m->data_first + cluster - 2, 1, output)) return 0;
        if (remaining < 4096) nb_copy(data + offset, output, static_cast<unsigned>(remaining));
        cluster = nb_fat(m, cluster);
    }
    return 1;
}
#endif

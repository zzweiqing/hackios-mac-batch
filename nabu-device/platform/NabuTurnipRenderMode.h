// SPDX-License-Identifier: MIT
// The eight-word tu_render_mode_stats ABI in UniXNU cd2dd1bd's recorded Mesa
// patch series. These are process-wide, independently read counters of recorded
// render passes, NOT GPU completions or displayed frames. No GPU work is run here.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace nabu_turnip_mode {
using ReadStats = void (*)(uint64_t *);

inline char mode(const char *debug) {
    if (debug && !std::strcmp(debug, "sysmem,nocb")) return 's';
    if (debug && !std::strcmp(debug, "gmem,nocb")) return 'g';
    return '?';
}

// RM1: g=GMEM, a=autotuned SYSMEM, s=other SYSMEM, u=GMEM passes
// requiring unpadded imported-attachment handling. Counts are hexadecimal so
// even four UINT64_MAX values fit the installed writer's 90-character row.
// Missing symbols are explicitly unavailable, never reported as zero passes.
inline bool formatRow(char *out, size_t capacity, const char *debug, ReadStats read) {
    if (!out || !capacity) return false;
    out[0] = 0;
    const char selected = mode(debug);
    char text[96];
    int length;
    if (!read) {
        length = std::snprintf(text, sizeof text, "RM1 m=%c unavailable", selected);
    } else {
        uint64_t counts[8] = {};
        read(counts);
        length = std::snprintf(text, sizeof text, "RM1 m=%c hex g%llx a%llx s%llx u%llx", selected,
            static_cast<unsigned long long>(counts[0]),
            static_cast<unsigned long long>(counts[2]),
            static_cast<unsigned long long>(counts[4]),
            static_cast<unsigned long long>(counts[6]));
    }
    if (length < 0 || static_cast<size_t>(length) >= capacity || length > 90) {
        out[0] = 0;
        return false;
    }
    std::memcpy(out, text, static_cast<size_t>(length) + 1);
    return true;
}
} // namespace nabu_turnip_mode

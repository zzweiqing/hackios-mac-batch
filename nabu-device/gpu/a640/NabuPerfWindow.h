/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NABU_PERF_WINDOW_H
#define NABU_PERF_WINDOW_H
#include <stdint.h>

/* Compact per-submission record copied out of the NativeAdrenoSubmit profile
 * ring; field names mirror ProfileSample. */
struct NabuPerfWindowSample {
    uint32_t seq, fence, complete;
    uint32_t latencyUs, submitCpuUs, retireUs, tlbUs, ringUs, cacheUs, publishUs;
    uint32_t clientHash;
    uint64_t submitUs, completeUs, mapUs, freeUs, allocUs;
};

struct NabuPerfWindowStats {
    uint32_t n;
    uint64_t latSum, latMax, cpuSum;
    uint64_t mapUs, freeUs, allocUs, tlbUs, ringUs, retireUs;
    uint32_t latAvg, latP50, latP95, cpuAvg;
    uint32_t distinctClients;
};

static const uint64_t NabuPerfWindowStallUs = 2000000;
static const unsigned NabuPerfWindowCapacity = 256;

/* Copies the contiguous prefix of completed samples with seq > *cursor,
 * oldest first, up to capacity (clamped to 256). Advances *cursor past every
 * consumed seq, including incomplete records older than the stall bound which
 * are counted as stalled. *lost receives the number of seq values between
 * *cursor and the oldest available record. Returns emitted | stalled << 16. */
template <typename At>
inline unsigned nabuPerfWindowCollect(uint32_t *cursor, NabuPerfWindowSample *out,
                                      unsigned capacity, uint32_t *lost,
                                      uint64_t nowUs, unsigned count, At at)
{
    if (capacity > NabuPerfWindowCapacity) capacity = NabuPerfWindowCapacity;
    if (!cursor || !out || !lost) return 0;
    if (!count) { *lost = 0; return 0; }
    const uint64_t oldest = at(0).seq;
    const uint64_t behind = oldest > uint64_t(*cursor) + 1 ? oldest - uint64_t(*cursor) - 1 : 0;
    *lost = behind > 0xffffffffULL ? 0xffffffffu : uint32_t(behind);
    unsigned emitted = 0, stalled = 0;
    for (unsigned i = 0; i < count; ++i) {
        const NabuPerfWindowSample sample = at(i);
        if (!sample.seq || sample.seq <= *cursor) continue;
        if (sample.complete) {
            if (emitted >= capacity) break;
            out[emitted++] = sample;
            *cursor = sample.seq;
        } else {
            const uint64_t age = nowUs > sample.submitUs ? nowUs - sample.submitUs : 0;
            if (age <= NabuPerfWindowStallUs) break;
            ++stalled;
            *cursor = sample.seq;
        }
    }
    return emitted | (stalled << 16);
}

inline void nabuPerfWindowAggregate(const NabuPerfWindowSample *samples, unsigned n,
                                    NabuPerfWindowStats *out)
{
    *out = {};
    if (!samples || !out) return;
    if (n > NabuPerfWindowCapacity) n = NabuPerfWindowCapacity;
    out->n = n;
    if (!n) return;
    uint32_t lat[NabuPerfWindowCapacity];
    for (unsigned i = 0; i < n; ++i) {
        const NabuPerfWindowSample &s = samples[i];
        lat[i] = s.latencyUs;
        out->latSum += s.latencyUs;
        if (s.latencyUs > out->latMax) out->latMax = s.latencyUs;
        out->cpuSum += s.submitCpuUs;
        out->mapUs += s.mapUs;
        out->freeUs += s.freeUs;
        out->allocUs += s.allocUs;
        out->tlbUs += s.tlbUs;
        out->ringUs += s.ringUs;
        out->retireUs += s.retireUs;
    }
    for (unsigned i = 1; i < n; ++i) {
        const uint32_t value = lat[i];
        unsigned j = i;
        while (j && lat[j - 1] > value) { lat[j] = lat[j - 1]; --j; }
        lat[j] = value;
    }
    out->latAvg = uint32_t(out->latSum / n);
    out->cpuAvg = uint32_t(out->cpuSum / n);
    const unsigned p50 = (n * 50 + 99) / 100;
    const unsigned p95 = (n * 95 + 99) / 100;
    out->latP50 = lat[p50 ? p50 - 1 : 0];
    out->latP95 = lat[p95 ? p95 - 1 : 0];
    uint32_t seen[8];
    unsigned distinct = 0;
    for (unsigned i = 0; i < n; ++i) {
        const uint32_t hash = samples[i].clientHash;
        unsigned j = 0;
        while (j < distinct && seen[j] != hash) ++j;
        if (j < distinct) continue;
        if (distinct < 8) seen[distinct++] = hash;
    }
    out->distinctClients = distinct;
}

#endif

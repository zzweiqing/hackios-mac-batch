/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NABU_PERF_CONFIG_H
#define NABU_PERF_CONFIG_H
#include <stddef.h>
#include <stdint.h>

/* nabu-perf boot-arg knobs, all default-off. GPU levels follow the SM8150
 * kgsl OPP/RPMh table captured on nabu: HFI index is 1-based ascending
 * frequency with 0=off; each entry pairs the ARC regulator level, the
 * msm-bus usecase and the DDR vote for that frequency. */
struct NabuPerfGpuLevel {
    uint32_t freqKHz;
    uint32_t arcLevel;
    uint32_t bwCase;
    uint32_t ddrKbps;
};
static const NabuPerfGpuLevel nabuPerfGpuLevels[6] = {
    {257000,64,3,1799000},
    {345000,128,4,2183000},
    {427000,192,6,3067000},
    {499200,224,9,6215000},
    {585000,256,10,7211000},
    {675000,320,11,8363000},
};

/* Sentinel MHz for the schedule "max" atom: the OSM pick rule caps it at the
 * highest LUT entry, so no real frequency is privileged. */
#define NABU_PERF_MAX_MHZ 0xffffffffu
#define NABU_PERF_MAX_STEPS 16

struct NabuPerfStep {
    uint32_t baseline;    /* 1 = atom 0: restore everything, set nothing */
    uint32_t gpuLevel;    /* 0 none, else 1..6 HFI index */
    uint32_t gpuReqMHz;
    uint32_t cpuMHz[3];   /* little, mid, prime; 0 = restore/untouched */
    uint32_t l3MHz;
};

struct NabuPerfConfig {
    uint32_t observe;
    uint32_t malformed;
    uint32_t gpuLevel;        /* 1..6 HFI index, 0 = legacy/none */
    uint32_t gpuReqMHz;       /* parsed g operand */
    uint32_t cpuTargetMHz[3]; /* little, mid, prime; 0 = untouched */
    uint32_t l3TargetMHz;     /* 0 = untouched */
    uint32_t schedStartSec;   /* a<sec> kernel uptime start, 0 = unset */
    uint32_t stepSec;         /* t<sec> 1..600, default 40 */
    uint32_t stepCount;       /* r steps, 0 = no schedule */
    uint32_t tableLevel;      /* highest GPU level needed by static g or any step */
    NabuPerfStep steps[NABU_PERF_MAX_STEPS];
};

/* First nabu-perf= argument wins; the value ends at space or NUL. */
inline const char *nabuPerfBootValue(const char *args)
{
    static const char key[] = "nabu-perf=";
    if (!args) return nullptr;
    for (const char *p = args; *p;) {
        while (*p == ' ') ++p;
        if (!*p) break;
        unsigned i = 0;
        for (; i < sizeof(key) - 1 && p[i] == key[i]; ++i) {}
        if (i == sizeof(key) - 1) return p + i;
        while (*p && *p != ' ') ++p;
    }
    return nullptr;
}

inline bool nabuPerfDigits(const char *s, size_t n, uint32_t *out)
{
    if (!n) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        const unsigned c = uint8_t(s[i]);
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
        if (v > 0xffffffffULL) return false;
    }
    *out = uint32_t(v);
    return true;
}

/* Lowest level whose frequency covers mhz; 0 stays legacy, overshoot clamps
 * to the top level. */
inline uint32_t nabuPerfGpuLevelIndex(uint32_t mhz)
{
    if (!mhz) return 0;
    const uint64_t target = uint64_t(mhz) * 1000;
    for (unsigned i = 0; i < 6; ++i)
        if (uint64_t(nabuPerfGpuLevels[i].freqKHz) >= target) return i + 1;
    return 6;
}

/* The level actually in force after buildTables: the requested level only
 * when the multi-level table was published (performance[0] > 2), else the
 * legacy level 1 so a knob-triggered ARC fallback can never wedge the GMU
 * startup vote. */
inline uint32_t nabuPerfEffectiveLevel(uint32_t performanceCount, uint32_t requested)
{
    if (performanceCount <= 2) return 1;
    return requested > 6 ? 6 : requested;
}

/* Parse one schedule atom (0/m/g/c/l) into a step; returns false on malformed. */
inline bool nabuPerfParseAtom(const char *p, size_t n, NabuPerfStep &step)
{
    if (!n) return false;
    if (n == 1 && p[0] == '0') { step.baseline = 1; return true; }
    if (n == 1 && p[0] == 'm') {
        for (unsigned i = 0; i < 3; ++i) step.cpuMHz[i] = NABU_PERF_MAX_MHZ;
        step.l3MHz = NABU_PERF_MAX_MHZ;
        return true;
    }
    uint32_t number = 0;
    if (p[0] == 'g') {
        if (!nabuPerfDigits(p + 1, n - 1, &number)) return false;
        step.gpuReqMHz = number;
        step.gpuLevel = nabuPerfGpuLevelIndex(number);
        return true;
    }
    if (p[0] == 'l') {
        if (!nabuPerfDigits(p + 1, n - 1, &number)) return false;
        step.l3MHz = number;
        return true;
    }
    if (p[0] == 'c') {
        const char *colon[2];
        unsigned ncolon = 0;
        for (size_t i = 1; i < n; ++i) {
            if (p[i] != ':') continue;
            if (ncolon == 2) return false;
            colon[ncolon++] = p + i;
        }
        if (ncolon != 2) return false;
        const char *begin[3] = {p + 1, colon[0] + 1, colon[1] + 1};
        const char *finish[3] = {colon[0], colon[1], p + n};
        for (unsigned i = 0; i < 3; ++i) {
            if (begin[i] == finish[i]) continue;
            if (!nabuPerfDigits(begin[i], size_t(finish[i] - begin[i]), &number)) return false;
            step.cpuMHz[i] = number;
        }
        return true;
    }
    return false;
}

/* Parse r<steps>: steps split on '/', atoms on '+'. At most 16 steps. */
inline bool nabuPerfParseSteps(const char *p, size_t n, NabuPerfConfig &config)
{
    if (!n || config.stepCount) return false;
    const char *end = p + n;
    const char *stepBegin = p;
    unsigned count = 0;
    while (stepBegin <= end) {
        const char *slash = stepBegin;
        while (slash < end && *slash != '/') ++slash;
        const size_t sn = size_t(slash - stepBegin);
        if (!sn || count == NABU_PERF_MAX_STEPS) return false;
        NabuPerfStep &step = config.steps[count];
        const char *atom = stepBegin;
        const char *atomEnd = stepBegin;
        bool any = false;
        while (atomEnd <= slash) {
            if (atomEnd == slash || *atomEnd == '+') {
                if (!nabuPerfParseAtom(atom, size_t(atomEnd - atom), step)) return false;
                any = true;
                atom = atomEnd + 1;
            }
            ++atomEnd;
        }
        if (!any) return false;
        ++count;
        if (slash == end) break;
        stepBegin = slash + 1;
    }
    if (count > NABU_PERF_MAX_STEPS) return false;
    config.stepCount = count;
    return true;
}

inline NabuPerfConfig nabuPerfParse(const char *args)
{
    NabuPerfConfig config = {};
    config.stepSec = 40;
    const char *value = nabuPerfBootValue(args);
    if (!value) return config;
    const char *end = value;
    while (*end && *end != ' ') ++end;
    bool bad = false, hasA = false, hasR = false, hasT = false;
    const char *p = value;
    while (p < end) {
        const char *comma = p;
        while (comma < end && *comma != ',') ++comma;
        const size_t n = size_t(comma - p);
        uint32_t number = 0;
        if (!n) {
            bad = true;
        } else if (p[0] == 'o') {
            if (n == 2 && p[1] == '1') config.observe = 1; else bad = true;
        } else if (p[0] == 'g') {
            if (!nabuPerfDigits(p + 1, n - 1, &number)) bad = true;
            else { config.gpuReqMHz = number; config.gpuLevel = nabuPerfGpuLevelIndex(number); }
        } else if (p[0] == 'l') {
            if (!nabuPerfDigits(p + 1, n - 1, &number)) bad = true;
            else config.l3TargetMHz = number;
        } else if (p[0] == 'c') {
            const char *colon[2];
            unsigned ncolon = 0;
            for (const char *q = p + 1; q < comma; ++q) {
                if (*q != ':') continue;
                if (ncolon == 2) { ncolon = 3; break; }
                colon[ncolon++] = q;
            }
            if (ncolon != 2) bad = true;
            else {
                const char *begin[3] = {p + 1, colon[0] + 1, colon[1] + 1};
                const char *finish[3] = {colon[0], colon[1], comma};
                for (unsigned i = 0; i < 3 && !bad; ++i) {
                    if (begin[i] == finish[i]) continue;
                    if (!nabuPerfDigits(begin[i], size_t(finish[i] - begin[i]), &number)) { bad = true; break; }
                    config.cpuTargetMHz[i] = number;
                }
            }
        } else if (p[0] == 'a') {
            if (!nabuPerfDigits(p + 1, n - 1, &number) || hasA) bad = true;
            else { hasA = true; config.schedStartSec = number; }
        } else if (p[0] == 't') {
            if (!nabuPerfDigits(p + 1, n - 1, &number) || number < 1 || number > 600 || hasT) bad = true;
            else { hasT = true; config.stepSec = number; }
        } else if (p[0] == 'r') {
            if (!nabuPerfParseSteps(p + 1, n - 1, config)) bad = true;
            else hasR = true;
        } else {
            bad = true;
        }
        p = comma < end ? comma + 1 : end;
    }
    if (end > value && end[-1] == ',') bad = true; // trailing empty token
    if ((hasA || hasT) && !hasR) bad = true;  // a/t require r
    if (hasR && !hasA) bad = true;           // r requires a
    if (bad) {
        config.malformed = 1;
        config.gpuLevel = 0;
        config.gpuReqMHz = 0;
        for (unsigned i = 0; i < 3; ++i) config.cpuTargetMHz[i] = 0;
        config.l3TargetMHz = 0;
        config.schedStartSec = 0;
        config.stepSec = 40;
        config.stepCount = 0;
        for (unsigned i = 0; i < NABU_PERF_MAX_STEPS; ++i) config.steps[i] = {};
    }
    config.tableLevel = config.gpuLevel;
    for (unsigned i = 0; i < config.stepCount; ++i)
        if (config.steps[i].gpuLevel > config.tableLevel)
            config.tableLevel = config.steps[i].gpuLevel;
    return config;
}

#endif

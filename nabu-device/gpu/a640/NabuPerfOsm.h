/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NABU_PERF_OSM_H
#define NABU_PERF_OSM_H
#include "NabuPerfConfig.h"
#include <stdint.h>

/* nabu OSM (on-chip speed switch) observation and static perf-state votes.
 * Register layout follows Linux v6.12: drivers/cpufreq/qcom-cpufreq-hw.c
 * blob 900d6844c43d3f0f1337029f641bddb45b5f839f (qcom_soc_data: reg_enable
 * 0x0, reg_freq_lut 0x110, reg_current_vote 0x704, reg_perf_state 0x920,
 * lut_row_size 32) and drivers/interconnect/qcom/osm-l3.c blob
 * 61a8695a9adc73b0bf0dc47f1232c03da7a1a52d (REG_ENABLE 0x0,
 * OSM_REG_FREQ_LUT 0x110, OSM_REG_PERF_STATE 0x920, OSM_LUT_ROW_SIZE 32;
 * qcom,sm8150-osm-l3 uses the osm_l3 descriptor). LUT word: src bits 31:30,
 * lval bits 7:0; decoded kHz = src ? 19200*lval : 300000 (xo 19.2 MHz,
 * alternate/2 = 300 MHz). The table ends at the first repeated frequency,
 * at most 40 rows. */
namespace nabu_perf_osm_detail {
/* l3, little (cpu0-3), mid (cpu4-6), prime (cpu7) from the nabu
 * qcom,clk-cpu-osm DT regions, each 0x1400 bytes. */
static const uint64_t kPhysical[4] = {0x18321000, 0x18323000, 0x18325800, 0x18327800};
static const char *const kNames[4] = {"l3", "little", "mid", "prime"};
}

struct NabuPerfOsmIO {
    void *cookie;
    volatile uint32_t *(*map)(void *, uint64_t, uint32_t);
    void (*barrier)(void *);
    uint64_t (*nowUs)(void *);
    void (*log)(void *, const char *);
};

class NabuPerfOsm {
public:
    void begin(const NabuPerfConfig &config, const NabuPerfOsmIO &io)
    {
        io_ = &io;
        observe_ = config.observe;
        lines_ = 0;
        active_ = 0;
        const uint64_t now = io.nowUs ? io.nowUs(io.cookie) : 0;
        startedUs_ = lastAssertUs_ = lastObserveUs_ = now;
        bool anyTarget = false;
        for (unsigned d = 0; d < 4; ++d) {
            const uint32_t target = d ? config.cpuTargetMHz[d - 1] : config.l3TargetMHz;
            if (target) anyTarget = true;
            Domain &domain = domains_[d];
            domain.physical = nabu_perf_osm_detail::kPhysical[d];
            domain.targetMHz = target;
            domain.regs = nullptr;
            domain.lutCount = 0;
            domain.lutValid = 0;
            domain.enable = 0;
            domain.targetIndex = -1;
        }
        if (!observe_ && !anyTarget) return;
        active_ = 1;
        for (unsigned d = 0; d < 4; ++d) {
            Domain &domain = domains_[d];
            if (io.map) domain.regs = io.map(io.cookie, domain.physical, kRegionSize);
            if (!domain.regs) {
                snprintf(line_, sizeof(line_), "NabuPerf: osm dom=%s phase=map-failed\n",
                         nabu_perf_osm_detail::kNames[d]);
                emit();
                continue;
            }
            domain.enable = domain.regs[0] & 1;
            uint32_t previous = 0;
            domain.lutValid = 1;
            domain.initialIndex = -1;
            domain.stepIndex = -1;
            for (unsigned i = 0; i < 40; ++i) {
                const uint32_t word = domain.regs[kLutWord + i * kLutStride];
                const uint32_t freq = (word >> 30) ? 19200u * (word & 0xff) : 300000u;
                if (i && freq == previous) break;
                if (domain.lutCount && freq <= domain.lut[domain.lutCount - 1]) domain.lutValid = 0;
                domain.lut[domain.lutCount++] = freq;
                previous = freq;
            }
            if (domain.lutCount < 2) domain.lutValid = 0;
            size_t used = snprintf(line_, sizeof(line_), "NabuPerf: osm lut dom=%s n=%u khz=",
                                   nabu_perf_osm_detail::kNames[d], domain.lutCount);
            for (unsigned i = 0; i < domain.lutCount && used + 12 < sizeof(line_); ++i)
                used += snprintf(line_ + used, sizeof(line_) - used, "%s%u", i ? "," : "", domain.lut[i]);
            snprintf(line_ + used, sizeof(line_) - used, "\n");
            emit();
            const uint32_t state = domain.regs[kPerfStateWord];
            domain.initialIndex = int32_t(state);
            const uint32_t khz = domain.lutValid && state < domain.lutCount ? domain.lut[state] : 0;
            const int vote = d ? int(domain.regs[kCurrentVoteWord] & 0x3ff) : -1;
            snprintf(line_, sizeof(line_),
                     "NabuPerf: osm dom=%s phase=init enable=%u state=%u vote=%d khz=%u\n",
                     nabu_perf_osm_detail::kNames[d], domain.enable, state, vote, khz);
            emit();
            if (!domain.targetMHz) continue;
            if (!domain.lutValid) {
                snprintf(line_, sizeof(line_), "NabuPerf: osm dom=%s phase=refuse reason=lut\n",
                         nabu_perf_osm_detail::kNames[d]);
                emit();
                continue;
            }
            if (!domain.enable) {
                snprintf(line_, sizeof(line_), "NabuPerf: osm dom=%s phase=refuse reason=enable\n",
                         nabu_perf_osm_detail::kNames[d]);
                emit();
                continue;
            }
            const uint64_t targetKHz = uint64_t(domain.targetMHz) * 1000;
            unsigned index = domain.lutCount - 1;
            for (unsigned i = 0; i < domain.lutCount; ++i) {
                if (uint64_t(domain.lut[i]) >= targetKHz) { index = i; break; }
            }
            domain.regs[kPerfStateWord] = index;
            if (io.barrier) io.barrier(io.cookie);
            const uint32_t readback = domain.regs[kPerfStateWord];
            domain.targetIndex = int(index);
            snprintf(line_, sizeof(line_), "NabuPerf: osm dom=%s phase=apply target=%u state=%u\n",
                     nabu_perf_osm_detail::kNames[d], index, readback);
            emit();
        }
    }

    /* Apply one schedule step's CPU/L3 targets. MHz==0 restores the domain's
     * initial index when a previous step changed it, else does nothing. Step
     * lines bypass the periodic line budget. */
    void retarget(const uint32_t cpuMHz[3], uint32_t l3MHz, unsigned stepNumber)
    {
        if (!active_ || !io_) return;
        for (unsigned d = 0; d < 4; ++d) {
            const uint32_t target = d ? cpuMHz[d - 1] : l3MHz;
            Domain &domain = domains_[d];
            if (!domain.regs) continue;
            if (!target) {
                if (domain.stepIndex < 0) continue;      /* nothing to restore */
                applyIndex(d, domain, domain.initialIndex, "step", stepNumber);
                domain.stepIndex = -1;                  /* stop re-asserting */
                continue;
            }
            if (!domain.lutValid || !domain.enable) {
                snprintf(line_, sizeof(line_),
                         "NabuPerf: osm dom=%s phase=step n=%u refuse reason=%s\n",
                         nabu_perf_osm_detail::kNames[d], stepNumber,
                         domain.lutValid ? "enable" : "lut");
                emitStep();
                continue;
            }
            const uint64_t targetKHz = uint64_t(target) * 1000;
            unsigned index = domain.lutCount - 1;
            for (unsigned i = 0; i < domain.lutCount; ++i) {
                if (uint64_t(domain.lut[i]) >= targetKHz) { index = i; break; }
            }
            applyIndex(d, domain, int32_t(index), "step", stepNumber);
            domain.stepIndex = int32_t(index);
        }
    }

    /* Schedule finished: restore every domain a step changed to its initial index. */
    void restoreAll(unsigned stepNumber)
    {
        if (!active_ || !io_) return;
        for (unsigned d = 0; d < 4; ++d) {
            Domain &domain = domains_[d];
            if (!domain.regs || domain.stepIndex < 0) continue;
            applyIndex(d, domain, domain.initialIndex, "restore", stepNumber);
            domain.stepIndex = -1;
        }
    }

    void tick(uint64_t nowUs)
    {
        if (!active_ || !io_) return;
        if (nowUs >= lastAssertUs_ + 2000000) {
            lastAssertUs_ = nowUs;
            for (unsigned d = 0; d < 4; ++d) {
                Domain &domain = domains_[d];
                const int32_t want = domain.stepIndex >= 0 ? domain.stepIndex : domain.targetIndex;
                if (want < 0 || !domain.regs) continue;
                if (domain.regs[kPerfStateWord] == uint32_t(want)) continue;
                domain.regs[kPerfStateWord] = uint32_t(want);
                if (io_->barrier) io_->barrier(io_->cookie);
                snprintf(line_, sizeof(line_), "NabuPerf: osm dom=%s phase=assert target=%d state=%u\n",
                         nabu_perf_osm_detail::kNames[d], want,
                         domain.regs[kPerfStateWord]);
                emit();
            }
        }
        if (!observe_) return;
        const uint64_t elapsed = nowUs > startedUs_ ? nowUs - startedUs_ : 0;
        const uint64_t interval = elapsed < 900000000ULL ? 10000000ULL : 60000000ULL;
        if (nowUs < lastObserveUs_ + interval) return;
        lastObserveUs_ = nowUs;
        for (unsigned d = 0; d < 4; ++d) {
            const Domain &domain = domains_[d];
            if (!domain.regs) continue;
            const uint32_t state = domain.regs[kPerfStateWord];
            const uint32_t khz = domain.lutValid && state < domain.lutCount ? domain.lut[state] : 0;
            const int vote = d ? int(domain.regs[kCurrentVoteWord] & 0x3ff) : -1;
            snprintf(line_, sizeof(line_),
                     "NabuPerf: osm dom=%s phase=state enable=%u state=%u vote=%d khz=%u\n",
                     nabu_perf_osm_detail::kNames[d], domain.enable, state, vote, khz);
            emit();
        }
    }

private:
    struct Domain {
        uint64_t physical;
        volatile uint32_t *regs;
        uint32_t lut[40];
        uint32_t lutCount;
        uint32_t lutValid;
        uint32_t enable;
        uint32_t targetMHz;
        int32_t targetIndex;
        int32_t initialIndex;   /* perf_state captured at begin(), before any vote */
        int32_t stepIndex;      /* last schedule-applied index, -1 = none */
    };

    static const uint32_t kRegionSize = 0x1400;
    static const uint32_t kLutWord = 0x110 / 4, kLutStride = 32 / 4;
    static const uint32_t kCurrentVoteWord = 0x704 / 4, kPerfStateWord = 0x920 / 4;
    static const uint32_t kLineCap = 600;

    Domain domains_[4]{};
    const NabuPerfOsmIO *io_ = nullptr;
    char line_[640]{};
    uint64_t startedUs_ = 0, lastAssertUs_ = 0, lastObserveUs_ = 0;
    uint32_t observe_ = 0, lines_ = 0, active_ = 0;

    /* Write perf_state + barrier + readback and log the step/restore line. */
    void applyIndex(unsigned d, Domain &domain, int32_t index, const char *phase,
                    unsigned stepNumber)
    {
        if (index < 0 || !domain.regs) return;
        domain.regs[kPerfStateWord] = uint32_t(index);
        if (io_->barrier) io_->barrier(io_->cookie);
        const uint32_t readback = domain.regs[kPerfStateWord];
        snprintf(line_, sizeof(line_),
                 "NabuPerf: osm dom=%s phase=%s n=%u target=%d state=%u\n",
                 nabu_perf_osm_detail::kNames[d], phase, stepNumber, index, readback);
        emitStep();
    }

    void emit()
    {
        if (lines_ < kLineCap && io_ && io_->log) {
            io_->log(io_->cookie, line_);
            ++lines_;
        }
    }

    /* Schedule step/restore lines are never subject to the periodic budget. */
    void emitStep()
    {
        if (io_ && io_->log) io_->log(io_->cookie, line_);
    }
};

#endif

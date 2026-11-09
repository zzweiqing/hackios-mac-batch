/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NABU_PERF_SCHEDULE_H
#define NABU_PERF_SCHEDULE_H
#include "NabuPerfConfig.h"
#include <stdint.h>

/* Time-based step schedule for the nabu-perf experiment. Never counts ticks:
 * step n (1-based) is active during [a+(n-1)*t, a+n*t) of kernel uptime.
 * tick() reports a step change exactly once per boundary actually crossed —
 * a late tick jumps to the step current NOW and reports only that step — and
 * one finished action after the last step. Clock regressions are ignored. */
struct NabuPerfScheduleAction {
    uint32_t stepChanged;
    uint32_t finished;
    uint32_t step; /* 1-based active step, 0 before start / after finish */
};

class NabuPerfSchedule {
public:
    void begin(const NabuPerfConfig &config)
    {
        active_ = config.stepCount ? 1 : 0;
        startUs_ = uint64_t(config.schedStartSec) * 1000000ULL;
        stepUs_ = uint64_t(config.stepSec) * 1000000ULL;
        stepCount_ = config.stepCount;
        lastUs_ = 0;
        haveUs_ = 0;
        started_ = 0;
        done_ = 0;
        lastStep_ = 0;
    }

    NabuPerfScheduleAction tick(uint64_t nowUs)
    {
        NabuPerfScheduleAction action = {};
        if (!active_) return action;
        if (haveUs_ && nowUs < lastUs_) return action; /* clock went backwards */
        lastUs_ = nowUs;
        haveUs_ = 1;
        if (nowUs < startUs_) return action;            /* before a*1e6 us */
        const uint64_t into = nowUs - startUs_;
        const uint64_t index = stepUs_ ? into / stepUs_ : 0;
        if (index >= stepCount_) {
            if (!done_) {
                done_ = 1;
                started_ = 0;
                lastStep_ = 0;
                action.stepChanged = 1;
                action.finished = 1;
                action.step = 0;
            }
            return action;
        }
        started_ = 1;
        const uint32_t current = uint32_t(index) + 1;
        if (current != lastStep_) {
            lastStep_ = current;
            action.stepChanged = 1;
            action.step = current;
        }
        return action;
    }

    unsigned currentStep() const
    {
        return (active_ && started_ && !done_) ? lastStep_ : 0;
    }

private:
    uint64_t startUs_ = 0, stepUs_ = 0, lastUs_ = 0;
    uint32_t stepCount_ = 0;
    uint32_t active_ = 0, haveUs_ = 0, started_ = 0, done_ = 0, lastStep_ = 0;
};

#endif

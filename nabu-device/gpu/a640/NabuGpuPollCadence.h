#pragma once
#include <stdint.h>

class NabuGpuPollCadence {
    uint64_t healthAt_=0,activityAt_=0;
    uint32_t submitted_=0,completed_=0;
    bool healthSeen_=false,activitySeen_=false;

    static uint64_t elapsed(uint64_t current,uint64_t previous) {
        return current>=previous?current-previous:UINT64_MAX;
    }
public:
    static constexpr unsigned ActiveMs=1,IdleMs=10;
    static constexpr uint64_t HealthUs=10000,ActiveTailUs=50000;

    bool healthDue(uint64_t current) {
        if(healthSeen_ && elapsed(current,healthAt_)<HealthUs)return false;
        healthSeen_=true;healthAt_=current;
        return true;
    }

    unsigned delayAfterProgress(uint64_t current,uint32_t submitted,uint32_t completed) {
        if(submitted!=completed || submitted!=submitted_ || completed!=completed_) {
            activityAt_=current;activitySeen_=true;
        }
        submitted_=submitted;completed_=completed;
        return activitySeen_ && elapsed(current,activityAt_)<ActiveTailUs?ActiveMs:IdleMs;
    }
};

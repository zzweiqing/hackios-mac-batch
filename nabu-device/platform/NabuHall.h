// SPDX-License-Identifier: BSD-2-Clause-Patent
// GPIO9 SW_LID sampling for nabu. All methods run on one polling worker.
#pragma once
#include <stdint.h>

namespace nabu_hall {

constexpr unsigned DebounceMs = 15;
constexpr unsigned PollMs = 16;
constexpr uint32_t InputConfigMask = (15u << 2) | (1u << 9);
constexpr const char *StateProperty = "nabu-hall-closed";
constexpr const char *FdtProperty = "nabu-hall-source-fdt-sha256";

inline bool inputConfigUsable(uint32_t config)
{
    return (config & InputConfigMask) == 0;
}

class State {
    bool sampled_ = false;
    bool candidateClosed_ = false;
    bool ready_ = false;
    bool closed_ = false;
    bool published_ = false;
    uint64_t sinceMs_ = 0;
    uint64_t lastMs_ = 0;

public:
    // A true result remains pending until acknowledge() succeeds. Restarting
    // debounce on a new level also prevents a stale failed report being sent.
    bool sample(uint32_t inout, uint64_t nowMs)
    {
        const bool closed = (inout & 1u) == 0;
        const bool clockReset = sampled_ && nowMs < lastMs_;
        if (!sampled_ || clockReset || candidateClosed_ != closed) {
            sampled_ = true;
            candidateClosed_ = closed;
            sinceMs_ = nowMs;
        }
        if (clockReset) {
            ready_ = false;
            published_ = false;
        }
        lastMs_ = nowMs;
        if (nowMs - sinceMs_ < DebounceMs) { return false; }
        if (!ready_ || closed_ != closed) {
            ready_ = true;
            closed_ = closed;
            published_ = false;
        }
        return !published_;
    }

    bool closed() const { return closed_; }
    void acknowledge(bool success) { published_ = success; }
};

} // namespace nabu_hall

// Returns true when the optional worker has been scheduled or is running.
// Enable compilation with XNU_NABU_HALL=1, then request nabu-hall=1 at boot.
extern "C" bool nabu_hall_start(void);

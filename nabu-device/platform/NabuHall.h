// SPDX-License-Identifier: BSD-2-Clause-Patent
// GPIO9 SW_LID sampling for nabu. All methods run on one polling worker.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

enum CoverMissing : uint32_t {
    NativeClassBinding = 1u << 0,
    EventServiceMatching = 1u << 1,
    CurrentStateQuery = 1u << 2,
    InitialDiscovery = 1u << 3,
    TerminationSemantics = 1u << 4,
    CompiledOut = 1u << 5,
};
constexpr uint32_t NativeCoverMissing = NativeClassBinding | EventServiceMatching |
    CurrentStateQuery | InitialDiscovery | TerminationSemantics;

enum class CoverStatus : uint32_t {
    Inactive, Unqualified, SourceMismatch, InvalidOps, AlreadySubscribed,
    Subscribed, Pending, Delivered, Withdrawn, WithdrawFailed, Disabled
};

/* Physical state candidate for a qualified HES provider. The provider maps
 * these samples through the original service and report contract before
 * native subscription can be qualified. */
struct CoverSample {
    uint64_t generation;
    uint64_t sequence;
    uint64_t timeMs;
    bool closed;
    bool initial;
};
struct CoverOps {
    void *context;
    int (*publish)(void *, const CoverSample *);
    int (*withdraw)(void *);
};

/* Single-executor lifecycle candidate. A zero missing-mask is supplied only
 * by a qualified provider, or explicitly by the synthetic host harness.
 * Native APIs below use NativeCoverMissing and refuse the current route. */
class CoverPublisher {
    State state_;
    CoverOps ops_{};
    CoverSample pending_{};
    bool active_ = false;
    bool retained_ = false;
    bool pendingValid_ = false;
    bool delivered_ = false;
    uint64_t generation_ = 0;
    uint64_t sequence_ = 0;
    uint64_t lastMs_ = 0;
    int error_ = 0;

public:
    CoverPublisher() = default;
    CoverPublisher(const CoverPublisher &) = delete;
    CoverPublisher &operator=(const CoverPublisher &) = delete;

    CoverStatus subscribe(const CoverOps &ops, const uint8_t source[32],
                          const uint8_t expected[32], uint32_t missing)
    {
        if (missing) return CoverStatus::Unqualified;
        if (!source || !expected || memcmp(source, expected, 32)) return CoverStatus::SourceMismatch;
        if (!ops.publish || !ops.withdraw) return CoverStatus::InvalidOps;
        if (active_ || retained_) return CoverStatus::AlreadySubscribed;
        ops_ = ops;
        state_ = State{};
        active_ = true;
        pendingValid_ = delivered_ = false;
        ++generation_;
        error_ = 0;
        return CoverStatus::Subscribed;
    }

    CoverStatus observe(uint32_t inout, uint64_t nowMs)
    {
        if (!active_) return CoverStatus::Inactive;
        if (nowMs < lastMs_) pendingValid_ = false;
        lastMs_ = nowMs;
        if (!state_.sample(inout, nowMs)) return CoverStatus::Pending;
        if (!pendingValid_ || pending_.closed != state_.closed()) {
            pending_ = {generation_, ++sequence_, nowMs, state_.closed(), !delivered_};
            pendingValid_ = true;
        }
        error_ = ops_.publish(ops_.context, &pending_);
        if (error_) return CoverStatus::Pending;
        state_.acknowledge(true);
        pendingValid_ = false;
        delivered_ = true;
        return CoverStatus::Delivered;
    }

    CoverStatus unsubscribe()
    {
        if (!active_ && !retained_) return CoverStatus::Inactive;
        active_ = false;
        error_ = ops_.withdraw(ops_.context);
        if (error_) {
            retained_ = true;
            return CoverStatus::WithdrawFailed;
        }
        retained_ = false;
        pendingValid_ = false;
        ops_ = {};
        return CoverStatus::Withdrawn;
    }

    int lastError() const { return error_; }
    bool retainedOwner() const { return retained_; }
};

} // namespace nabu_hall

// Returns true when the optional worker has been scheduled or is running.
// Enable compilation with XNU_NABU_HALL=1, then request nabu-hall=1 at boot.
extern "C" bool nabu_hall_start(void);
/* Reports concrete unresolved native HES qualifications. Subscription never
 * succeeds while this mask is nonzero. Existing property sampling is separate. */
extern "C" uint32_t nabu_hall_hes_missing(void);
extern "C" nabu_hall::CoverStatus nabu_hall_hes_subscribe(
    const nabu_hall::CoverOps *, const uint8_t sourceFdtSha256[32]);
extern "C" nabu_hall::CoverStatus nabu_hall_hes_unsubscribe(void);
extern "C" nabu_hall::CoverStatus nabu_hall_hes_status(void);

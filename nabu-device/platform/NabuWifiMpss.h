/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_MPSS_H
#define NABU_WIFI_MPSS_H

#include <stddef.h>
#include <stdint.h>
#include "../gpu/a640/NabuScmCall.h"

namespace NabuWifiMpss {

constexpr uint64_t MpssBase = UINT64_C(0x8e000000);
constexpr size_t MpssBytes = 0x9600000;
constexpr uint64_t SmemBase = UINT64_C(0x86000000);
constexpr size_t SmemBytes = 0x200000;
/* Trusted nabu /chosen DRAM envelope. gPhysBase/gPhysSize describe the
 * loader-selected kernel-managed subwindow, not this entire envelope. */
constexpr uint64_t XnuBase = UINT64_C(0xc0000000);
constexpr uint64_t XnuBytes = UINT64_C(0x140000000);
constexpr uint32_t PasId = 4;
constexpr uint32_t ProxyLevel = 385;
constexpr uint32_t ReadyBit = 1u << 1;
constexpr uint32_t FatalBit = 1u;
constexpr uint64_t ReadyTimeoutUs = UINT64_C(30000000);
constexpr size_t RmtfsSharedBytes = 0x200000;

enum class Stage : uint32_t {
    Idle, ValidateOps, ValidateResources, ReadMdt, ValidateMdt, ReadSegments,
    MapSmem, PrepareSmp2p, VoteCx, VoteMss, EnableXo, ProbeScm64, ProbeScm32,
    AllocateMetadata, PublishMetadata, PasInitImage, PasMemSetup,
    MapMpss, LoadSegments, PublishSegments, SignalAop, PasAuthAndReset,
    WaitReady, Ready, AllocateShared, PublishShared, AssignShared, SharedReady
};

enum class Error : uint32_t {
    None, AlreadyAttempted, MissingOps, InvalidResources, Provider,
    InvalidMdt, SegmentSize, SegmentRange, SegmentOverlap, Mapping,
    Allocation, Cache, Smp2p, AlreadyRunning, Power, ScmConvention,
    ScmTransport, ScmSecure, ScmIncomplete, Aop, Clock, Wait,
    Fatal, ReadyTimeout
};

struct Result {
    Stage stage = Stage::Idle;
    Error error = Error::None;
    int status = 0;
    uint32_t segment = UINT32_MAX;
    uint32_t smp2pState = 0;
    uint32_t scmFunction = 0;
    uint32_t scmArgInfo = 0;
    uint64_t scmArgs[4]{};
    uint32_t scmConvention = 0;
    NabuScmReply scm;
    uint64_t loadedBytes = 0;
    uint64_t metadataPhysical = 0;
    size_t metadataBytes = 0;
    bool pasSubmitted = false;
    bool authenticated = false;
    bool readyObserved = false;
    bool metadataRetained = false;
    bool assignmentSubmitted = false;
    bool sharedAssigned = false;
    uint64_t sharedPhysical = 0;
    size_t sharedBytes = 0;
    uint64_t managedBase = 0;
    uint64_t managedBytes = 0;
};

struct Region {
    void *handle = nullptr;
    uint8_t *data = nullptr;
    uint64_t physical = 0;
    size_t bytes = 0;
};

/* Production uses nativePlatform(), implemented with IOKit mappings, owned
 * prepared IOBufferMemoryDescriptor pages, and the real SMC instruction.
 * An injected platform lets a host harness execute the same start() code.
 * allocate must provide exclusive, physically contiguous, page-aligned,
 * non-cacheable storage with no SHM bridge. map is non-cacheable reserved RAM.
 * publish completes CPU stores before secure world / MPSS can observe them.
 */
struct Platform {
    void *ctx = nullptr;
    int (*managedWindow)(void *, uint64_t *, uint64_t *) = nullptr;
    int (*claimColdBoot)(void *) = nullptr;
    int (*map)(void *, uint64_t, size_t, Region *) = nullptr;
    void (*unmap)(void *, Region *) = nullptr;
    int (*allocate)(void *, size_t, unsigned, Region *) = nullptr;
    void (*release)(void *, Region *) = nullptr;
    int (*publish)(void *, const Region *, size_t, size_t) = nullptr;
    NabuScmIo scm{};
    int (*claimShared)(void *) = nullptr;
};

struct Smp2pObservation {
    bool negotiated = false;
    bool entryPresent = false;
    /* Must describe a remote publication in this attempt's generation.
     * A surviving SMEM ready bit from an earlier boot is insufficient. */
    bool fresh = false;
    uint32_t state = 0;
};

struct Ops {
    void *ctx = nullptr;
    /* All returned bytes must already pass the independent package digest
     * checks and remain immutable/pinned until start() returns. Paths include
     * firmware/modem.mdt and firmware/modem.bNN (original PHDR index).
     * Zero is success. Errors are retained verbatim in Result::status. */
    int (*getFile)(void *, const char *, const uint8_t **, size_t *) = nullptr;
    void (*log)(void *, const Result *) = nullptr;
    /* Shared RPMh/AOP owners supply these operations. ARC level is a voltage
     * level to resolve through this board's command DB, not a raw ARC index.
     * vote and XO remain held for the lifetime of this one attempt, including
     * error paths after PAS submission. No recovery/unvote is implied. */
    int (*vote)(void *, const char *, uint32_t) = nullptr;
    int (*enableXo)(void *) = nullptr;
    int (*setModemLoadState)(void *) = nullptr;
    /* The transport owner initializes only AP-owned SMP2P entries, using
     * items 435/428, AP PID 0, modem PID 1 and IPC bit 14 on this board.
     * It must reject an active/unknown owner. Incoming modem entries must
     * never be cleared to manufacture a new ready edge. The SMEM mapping is
     * borrowed and remains retained for the boot after this callback. */
    int (*prepareSmp2p)(void *, const Region *, Smp2pObservation *) = nullptr;
    int (*pollSmp2p)(void *, Smp2pObservation *) = nullptr;
    const Platform *platform = nullptr;
};

const char *stageName(Stage);
const char *errorName(Error);
const Platform &nativePlatform();
/* Nonempty, nonoverflowing subwindow of trusted high RAM, disjoint from
 * MPSS and SMEM. Owned pages must additionally fit this actual window. */
bool managedWindowValid(uint64_t base, uint64_t bytes);

/* Owns a below-4-GiB contiguous 2 MiB buffer, retained guard pages, and an
 * independent SCM parameter/extended-argument page. Assigns HLOS (3) to
 * HLOS (3) + MSS_MSA (15), RW (6), using service 0xc command 0x16.
 * initialize returns the recorded result on subsequent calls. Failed or
 * interrupted assignment retains all allocations and never reassigns.
 */
class RmtfsShared final {
public:
    RmtfsShared() = default;
    RmtfsShared(const RmtfsShared &) = delete;
    RmtfsShared &operator=(const RmtfsShared &) = delete;
    Result initialize(const Ops &);
    bool region(Region *) const;
private:
    uint32_t attempted_ = 0;
    Region storage_, parameters_, shared_;
    Result result_;
};

/* Native singleton returns its original assignment failure and exposes a
 * Region only on success. sync matches Control::Resources::sync and accepts
 * only pointers inside that shared region. Both acquire/release use the
 * non-cacheable mapping's required CPU/device barrier. */
Result nativeRmtfsSharedRegion(Region *);
int nativeRmtfsSharedSync(void *, void *, size_t, bool publish);

/* Caller retains one owner for the boot. start is synchronous and makes one
 * cold-start attempt. It never creates a thread or retries the PAS sequence.
 * Metadata submitted to PAS is retained even on an incomplete SMC/error.
 * SMEM stays mapped for the transport owner. A new Mpss object cannot bypass
 * the native platform's boot-wide claim. */
class Mpss final {
public:
    Mpss() = default;
    Mpss(const Mpss &) = delete;
    Mpss &operator=(const Mpss &) = delete;
    Result start(const Ops &);

private:
    uint32_t attempted_ = 0;
    Region metadata_;
    Region smem_;
};

} // namespace NabuWifiMpss
#endif

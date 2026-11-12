/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_POWER_H
#define NABU_WIFI_POWER_H
#include <stddef.h>
#include <stdint.h>
#include "NabuWifiMpss.h"

namespace NabuWifiPower {

enum class Domain {CommandDbInfo, CommandDb, Rpmh, Qmp, Doorbell};
enum class Stage {Idle, CommandDb, VoteCx, VoteMss, EnableXo, TcsPrepare,
    TcsSubmit, TcsComplete, QmpOpen, QmpSubmit, QmpComplete, Released, WlanSupplies};
enum class Error {None, MissingIo, AlreadyAttempted, Resource, Io, Busy,
    Timeout, Clock, Level, Sequence};
struct Report {
    struct WlanSupply {
        uint32_t address = 0;
        /* Bits 0/1/2 describe voltage/mode/enable. submitted is recorded
         * before the TCS trigger attempt, acknowledged after its real ACK. */
        uint32_t submitted = 0, acknowledged = 0;
    };
    Stage stage = Stage::Idle;
    Error error = Error::None;
    Domain domain = Domain::CommandDbInfo;
    uint32_t offset = 0, value = 0, expected = 0, mask = 0;
    uint32_t resourceAddress = 0, requestedLevel = 0, levelIndex = 0;
    int status = 0;
    bool pending = false;
    /* QDSS may be held once its mailbox submission is attempted. This boot
     * has no PAS-stop/off path, so the pending vote survives a successful ACK
     * as well as submission/ACK failures. pending above tracks mailbox work. */
    bool wlanQdssPending = false, wlanQdssAccepted = false;
    bool wlanSuppliesRequested = false, wlanSuppliesReady = false;
    /* Ordered ldoa1, ldoa7, ldoc2, ldoc11. Votes survive this boot. */
    WlanSupply wlanSupplies[4]{};
    uint64_t managedBase = 0, managedBytes = 0;
};
struct Io {
    void *ctx = nullptr;
    int (*read32)(void *, Domain, uint32_t, uint32_t *) = nullptr;
    int (*write32)(void *, Domain, uint32_t, uint32_t) = nullptr;
    int (*nowUs)(void *, uint64_t *) = nullptr;
    int (*waitUs)(void *, unsigned) = nullptr;
    void (*log)(void *, const Report *) = nullptr;
};

/* Cold-candidate configuration is nabu-wifi=2/3, nabu-gpu=0. The native
 * beginBeforeGpu validates both arguments before mapping/writing registers.
 * GPU stays disabled throughout that boot and all Wi-Fi owners remain held.
 * Mode 1 is input-only and does not call this owner. The atomic operation
 * guard serializes this owner's calls. Any occupied active TCS returns Busy
 * before a write to either slot, with the exact occupied register preserved.
 *
 * Future serialized GPU handoff requires the coordinator to join the Wi-Fi
 * worker, completeBeforeGpu successfully, and mergeArcVote on later GPU
 * votes. An incomplete TCS/QMP prevents that handoff. APPS DRV2 has one vote
 * per ARC resource, so the merge preserves the CX floor and XO enable.
 */
class Power final {
public:
    /* Native passes the observed kernel-managed window. Existing injected
     * I/O callers default to the trusted board envelope. */
    int beginBeforeGpu(const Io &, uint64_t managedBase = NabuWifiMpss::XnuBase,
                       uint64_t managedBytes = NabuWifiMpss::XnuBytes);
    int vote(const char *, uint32_t);
    int enableXo();
    int setModemLoadState();
    /* Explicit mode-3 caller enables QDSS before PAS. Requires this owner to
     * have begun. A submitted vote is retained for the boot, with no retry. */
    int setWlanQdss();
    /* Explicit mode-3 operation, after begin and before QDSS/PAS. Validate
     * the entire command DB before voting on any WLAN VRM resource. */
    int enableWlanSupplies();
    bool completeBeforeGpu();
    uint32_t mergeArcVote(uint32_t address, uint32_t value) const;
    const Report &report() const { return report_; }

private:
    struct Resource {
        uint32_t address = 0;
        uint16_t levels[256]{};
        size_t count = 0;
        uint32_t heldIndex = 0;
        bool held = false;
    };
    Io io_;
    Report report_;
    Resource cx_, mss_, xo_;
    uint32_t attempted_ = 0, operation_ = 0;
    bool begun_ = false, released_ = false, xoEnabled_ = false;
    bool loadStateOn_ = false, linkUp_ = false;
    uint32_t mailboxOffset_ = 0, mailboxBytes_ = 0;
    int fail(Error, int = 0);
    int read(Domain, uint32_t, uint32_t *);
    int write(Domain, uint32_t, uint32_t);
    int poll(Domain, uint32_t, uint32_t, uint32_t, uint64_t);
    int findResources();
    int findWlanResources();
    int submitVote(uint32_t, uint32_t, Report::WlanSupply * = nullptr, uint32_t command = 0);
    int openQmp(bool rejectBusy = false);
    int ring();
    int sendQmp(const char *, size_t messageBytes, uint32_t paddedBytes, bool wlanQdss);
    void log();
};

/* Native functions use retained IOKit maps in the GPU-disabled first round.
 * Their callback cookie is ignored
 * so they can be installed directly into a composite NabuWifiMpss::Ops.
 * Native begin validates the command DB pointer is 0x85f20000. It maps only
 * command DB, APPS DRV2, QMP 0x0c300000 and doorbell 0x17c0000c resources.
 */
int beginBeforeGpu();
int vote(void *, const char *, uint32_t);
int enableXo(void *);
int setModemLoadState(void *);
int setWlanQdss(void *);
int enableWlanSupplies(void *);
bool completeBeforeGpu();
uint32_t mergeArcVote(uint32_t address, uint32_t value);

} // namespace NabuWifiPower
#endif

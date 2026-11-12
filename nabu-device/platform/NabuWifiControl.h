/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef NABU_WIFI_CONTROL_H
#define NABU_WIFI_CONTROL_H
#include "NabuWifiSmem.h"
#include "NabuWifiRmtfs.h"

namespace nabu_wifi {

struct FileProvider {
    void *ctx;
    /* True is success. Only digest-verified, immutable, pinned bundle files.
     * Canonical paths are firmware/<name> and rmtfs-seed/<partition>.img. */
    bool (*getFile)(void *ctx, const char *path, const uint8_t **data, size_t *bytes);
};

class Control final {
public:
    enum class Stage { Empty, Inputs, Smp2pPrepared, WaitReady, Glink, Services,
                       WaitWlfw, Capability, Complete, PdFailureAck, Failed };
    enum class Error { None, InvalidResources, Provider, Registry, Smem, AlreadyRunning,
                       NotPrepared, Clock, Smp2p, Fatal, Restart, QueueFull, Protocol,
                       GlinkTimeout, IntentTimeout, ServiceTimeout, QmiTimeout, QmiResult,
                       CapabilityFields, TransferTimeout, PdFailure, RmtfsIo };
    struct Event {
        Stage stage;
        Error error;
        uint32_t generation;
        const char *operation; /* Borrowed until the synchronous log call returns. */
        uint64_t a, b;
        int status;
    };
    struct Resources {
        Smem::Mapping smem;
        void *ctx;
        void (*log)(void *, const Event *);
        uint64_t (*nowMs)(void *);
        void (*waitMs)(void *, unsigned);
        /* Separate private seed arena and owned, contiguous MPSS buffer.
         * shared must already be assigned to HLOS+MSS_MSA, retained on errors.
         * sync is an acquire/invalidate (publish=false) or release/clean
         * (publish=true) with the platform's required CPU/device barriers. */
        uint8_t *rmtfs_arena;
        size_t rmtfs_arena_bytes;
        uint8_t *shared;
        uint64_t shared_phys;
        size_t shared_bytes;
        int (*sync)(void *, void *, size_t, bool publish);
    };
    struct Smp2pObservation { bool negotiated, entryPresent, fresh; uint32_t state; };
    struct Status {
        Stage stage;
        Error error;
        int detail;
        uint32_t generation, smp2p_state, server_node, server_port, capability_generation;
        wire::Capability capability;
        uint64_t rmtfs_requests, pd_requests, tftp_requests, packets;
    };

    /* Allocate this object off the kernel stack. Approximately 1 MiB of
     * bounded protocol/RAM-file storage, no internal allocator or thread.
     * initialize runs before PAS, writes AP-owned outbound SMP2P only.
     * RMTFS requires 25,427,968 bytes of private seed arena plus a separate 2 MiB
     * shared buffer (actual arena requirement comes from the four seed files).
     * No SMEM/MPSS-owned memory is released by this type on failure. */
    Control();
    Control(const Control &) = delete;
    Control &operator=(const Control &) = delete;
    bool initialize(const Resources &, const FileProvider &);
    bool pollSmp2p(Smp2pObservation &);
    /* Call exactly once after this boot's PAS authenticated reset. */
    bool startAfterPas(uint64_t now_ms);
    /* True means the bounded iteration can continue, including PdFailureAck
     * draining the existing send queue. PD diagnostics log up to 256 bytes
     * per field as hex, with original/captured lengths in Event a/b and
     * status -1 for an absent TLV. Full ACK submission ends in Failed /
     * PdFailure. A send/transport error retains PdFailure and logs its cause
     * Error in Event a, alongside the operation and platform detail.
     * Pending ACKs keep the 32-command RX budget even at the queue high-water
     * mark. QRTR restarts invalidate their generation. Remaining RX defers
     * TX while enforcing the existing queue deadline; new service work and
     * HELLO advertisements are suppressed during this terminal phase.
     * Complete keeps handling traffic indefinitely, with per-transaction /
     * transfer deadlines and remote fatal/ready-loss/restart monitoring.
     * False means a retained Failed state. A first capability remains bound
     * to capability_generation even after a later transport failure. */
    bool poll(uint64_t now_ms);
    /* Synchronous executor for a thread created by the coordinator. Returns
     * at capability success or a retained failure. No PAS operation here. */
    Status run();
    const Status &status() const { return status_; }
    static const char *stageName(Stage);
    static const char *errorName(Error);

private:
    enum { kQueue = 16, kIntents = 8, kRemoteIntents = 128, kTransfers = 8,
           kRamFiles = 8, kRamFileBytes = 65536, kRegistry = 32, kBlockBytes = 1024,
           kPdDiagnosticBytes = 256 };
    struct Packet {
        uint8_t data[wire::kPacketBytes];
        uint32_t bytes, offset, iid, generation;
        uint64_t deadline;
        bool intent_requested, intent_assigned;
    };
    // Remote IID zero is valid. A nonzero byte capacity marks a populated slot.
    struct Intent { uint32_t iid, bytes; bool busy; uint64_t deadline; };
    struct Receive { uint8_t data[wire::kPacketBytes]; uint32_t bytes, remaining, iid; bool active, advertised; uint64_t deadline; };
    struct Registry { char service[80], domain[80]; uint32_t instance, data; bool valid; };
    struct RamFile { char path[160]; uint8_t data[kRamFileBytes]; size_t bytes; bool used, writing; unsigned readers; };
    struct Transaction {
        uint8_t request[4096], response[1024];
        uint32_t node, port, local_port, generation;
        uint16_t id, txn;
        size_t request_bytes, response_bytes;
        uint64_t expires;
        bool used;
    };
    struct Transfer {
        bool used, write, final;
        uint32_t node, port, generation, block, acknowledged, window_end, next_block, block_bytes, window;
        uint64_t deadline, retry_at;
        unsigned retries, timeout_ms;
        const uint8_t *file;
        size_t file_bytes, seek, length;
        int ram_file;
        uint8_t initial[512];
        size_t initial_bytes;
    };
    Resources resources_;
    FileProvider provider_;
    Smem smem_;
    Smem::Item outbound_, descriptors_, tx_, rx_;
    RmtfsRamStore store_;
    size_t part_bytes_[4];
    uint32_t handle_node_[4];
    bool handle_open_[4];
    Status status_;
    uint64_t now_, stage_deadline_, incomplete_since_;
    bool attempted_, inbound_seen_, restart_flag_, fresh_ready_, version_, open_sent_, open_ack_, remote_open_, intents_sent_, services_sent_;
    uint16_t remote_channel_, transaction_;
    uint32_t features_, queue_head_, queue_count_, registry_count_, rx_cursor_, next_local_iid_;
    bool qmi_pending_;
    uint64_t qmi_deadline_;
    uint32_t qmi_node_, qmi_port_, qmi_generation_;
    uint32_t cache_next_, cache_active_;
    Transaction transactions_[8];
    Packet queue_[kQueue];
    Intent remote_intents_[kRemoteIntents];
    Receive receive_[kIntents];
    Registry registry_[kRegistry];
    Transfer transfers_[kTransfers];
    RamFile ram_files_[kRamFiles];
    uint8_t scratch_[wire::kPacketBytes];

    void event(const char *, uint64_t = 0, uint64_t = 0, int = 0);
    bool fail(Error, const char *, int = 0);
    void stage(Stage, uint64_t timeout);
    bool registryFile(const char *);
    bool domain(wire::Json &, char *, uint32_t &);
    bool serviceList(wire::Json &, Registry *, unsigned &);
    bool prepareSmp2p();
    void logModemReason(const char *operation);
    bool attachGlink();
    bool command(uint16_t, uint16_t, uint32_t, const void * = nullptr, size_t = 0);
    bool commandSpace(uint32_t);
    bool receiveOne();
    void peek(uint32_t off, void *, size_t);
    bool flush(bool transmit = true);
    bool send(uint32_t, uint32_t, uint32_t, uint32_t, const void *, size_t);
    bool advertise(uint32_t node);
    bool packet(const uint8_t *, size_t);
    bool controlPacket(const wire::QrtrPacket &);
    bool rmtfs(const wire::QrtrPacket &, const wire::QmiMessage &);
    bool pdmapper(const wire::QrtrPacket &, const wire::QmiMessage &);
    void pdFailureDiagnostic(const wire::QmiMessage &, uint8_t, const char *);
    bool wlfw(const wire::QrtrPacket &, const wire::QmiMessage &);
    bool tftp(const wire::QrtrPacket &);
    bool transferRequest(const wire::QrtrPacket &);
    bool transferPoll();
    bool transferBlock(unsigned, uint32_t);
    void closeTransfer(unsigned);
    bool transferError(uint32_t, uint32_t, uint32_t, uint16_t, const char *);
    bool reply(const wire::QrtrPacket &, wire::QmiBuilder &);
    bool serviceRequest(const wire::QrtrPacket &, const wire::QmiMessage &);
};
} // namespace nabu_wifi
#endif

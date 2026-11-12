/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Polled MPSS firmware-service executor. Wire layouts follow fixed ios-flame
 * 745c4341af86089efb0df851fa8a27fb8face624 and upstream Qualcomm protocols.
 * This implementation supplies bounded ownership, parser, queue and epoch
 * handling for nabu. It does not call PAS or create an execution thread.
 */
#include "NabuWifiControl.h"

namespace nabu_wifi {
using namespace wire;

static bool span(const void *p, size_t n) {
    return p && n && n <= UINTPTR_MAX - reinterpret_cast<uintptr_t>(p);
}
static bool overlap(const void *a, size_t an, const void *b, size_t bn) {
    const uintptr_t av = reinterpret_cast<uintptr_t>(a), bv = reinterpret_cast<uintptr_t>(b);
    return av < bv + bn && bv < av + an;
}
static bool join(char *out, size_t capacity, const char *a, const char *b) {
    const size_t an = strlen(a), bn = strlen(b);
    if (an + bn + 2 > capacity) return false;
    memcpy(out, a, an); out[an] = '/'; memcpy(out + an + 1, b, bn + 1);
    return true;
}

Control::Control() : resources_{}, provider_{}, smem_{}, outbound_{}, descriptors_{}, tx_{}, rx_{},
    store_{}, part_bytes_{}, handle_node_{}, handle_open_{}, status_{}, now_(0), stage_deadline_(0),
    incomplete_since_(0), attempted_(false), inbound_seen_(false), restart_flag_(false), fresh_ready_(false), version_(false),
    open_sent_(false), open_ack_(false), remote_open_(false), intents_sent_(false), services_sent_(false),
    remote_channel_(0), transaction_(1), features_(0), queue_head_(0), queue_count_(0), registry_count_(0),
    rx_cursor_(0), next_local_iid_(9), qmi_pending_(false), qmi_deadline_(0), qmi_node_(0), qmi_port_(0), qmi_generation_(0),
    cache_next_(0), cache_active_(UINT32_MAX), transactions_{}, queue_{}, remote_intents_{}, receive_{}, registry_{}, transfers_{}, ram_files_{}, scratch_{} {}

const char *Control::stageName(Stage value) {
    switch (value) {
    case Stage::Empty: return "empty"; case Stage::Inputs: return "inputs";
    case Stage::Smp2pPrepared: return "smp2p-prepared"; case Stage::WaitReady: return "wait-ready";
    case Stage::Glink: return "glink"; case Stage::Services: return "services";
    case Stage::WaitWlfw: return "wait-wlfw"; case Stage::Capability: return "capability";
    case Stage::Complete: return "complete"; case Stage::Failed: return "failed";
    case Stage::PdFailureAck: return "pd-failure-ack";
    }
    return "invalid";
}
const char *Control::errorName(Error value) {
    switch (value) {
    case Error::None: return "none"; case Error::InvalidResources: return "invalid-resources";
    case Error::Provider: return "provider"; case Error::Registry: return "registry";
    case Error::Smem: return "smem"; case Error::AlreadyRunning: return "already-running";
    case Error::NotPrepared: return "not-prepared"; case Error::Clock: return "clock";
    case Error::Smp2p: return "smp2p"; case Error::Fatal: return "fatal";
    case Error::Restart: return "restart"; case Error::QueueFull: return "queue-full";
    case Error::Protocol: return "protocol"; case Error::GlinkTimeout: return "glink-timeout";
    case Error::IntentTimeout: return "intent-timeout"; case Error::ServiceTimeout: return "service-timeout";
    case Error::QmiTimeout: return "qmi-timeout"; case Error::QmiResult: return "qmi-result";
    case Error::CapabilityFields: return "capability-fields"; case Error::TransferTimeout: return "transfer-timeout";
    case Error::PdFailure: return "pd-failure"; case Error::RmtfsIo: return "rmtfs-io";
    }
    return "invalid";
}
void Control::event(const char *operation, uint64_t a, uint64_t b, int detail) {
    if (resources_.log) {
        const Event value{status_.stage, status_.error, status_.generation, operation, a, b, detail};
        resources_.log(resources_.ctx, &value);
    }
}
bool Control::fail(Error error, const char *operation, int detail) {
    if (status_.stage != Stage::Failed) {
        // A transport failure while draining the ACK is secondary to the
        // recorded PD failure. Keep both the primary error and this cause.
        const bool pd_failure = status_.error == Error::PdFailure;
        if (!pd_failure) status_.error = error;
        status_.detail = detail;
        event(operation, pd_failure ? uint64_t(error) : 0, 0, detail);
        status_.stage = Stage::Failed;
        qmi_pending_ = false; queue_count_ = 0;
    }
    return false;
}
void Control::stage(Stage value, uint64_t timeout) {
    status_.stage = value; stage_deadline_ = timeout ? now_ + timeout : 0; event(stageName(value));
}

bool Control::domain(Json &json, char *out, uint32_t &instance) {
    if (!json.take('{')) return false;
    char soc[24] = {}, name[24] = {}, sub[40] = {}, key[80]; unsigned seen = 0;
    do {
        if (!json.text(key, sizeof(key)) || !json.take(':')) return false;
        unsigned bit = 0;
        if (!strcmp(key, "soc")) { bit = 1; if (!json.text(soc, sizeof(soc))) return false; }
        else if (!strcmp(key, "domain")) { bit = 2; if (!json.text(name, sizeof(name))) return false; }
        else if (!strcmp(key, "subdomain")) { bit = 4; if (!json.text(sub, sizeof(sub))) return false; }
        else if (!strcmp(key, "qmi_instance_id")) { bit = 8; if (!json.number(instance)) return false; }
        else if (!json.skip()) return false;
        if (bit & seen) return false;
        seen |= bit;
        if (json.take('}')) break;
        if (!json.take(',')) return false;
    } while (true);
    char prefix[56];
    return seen == 15 && soc[0] && name[0] && sub[0] && instance <= 0xffff &&
        join(prefix, sizeof(prefix), soc, name) && join(out, 80, prefix, sub);
}
bool Control::serviceList(Json &json, Registry *entries, unsigned &count) {
    if (!json.take('[')) return false;
    count = 0;
    if (json.take(']')) return true;
    do {
        if (count == kRegistry || !json.take('{')) return false;
        char provider[40] = {}, service_name[40] = {}, key[80];
        uint32_t valid = 0, data = 0; unsigned seen = 0;
        do {
            if (!json.text(key, sizeof(key)) || !json.take(':')) return false;
            unsigned bit = 0;
            if (!strcmp(key, "provider")) { bit = 1; if (!json.text(provider, sizeof(provider))) return false; }
            else if (!strcmp(key, "service")) { bit = 2; if (!json.text(service_name, sizeof(service_name))) return false; }
            else if (!strcmp(key, "service_data_valid")) { bit = 4; if (!json.number(valid) || valid > 1) return false; }
            else if (!strcmp(key, "service_data")) { bit = 8; if (!json.number(data)) return false; }
            else if (!json.skip()) return false;
            if (bit & seen) return false;
            seen |= bit;
            if (json.take('}')) break;
            if (!json.take(',')) return false;
        } while (true);
        if (seen != 15 || !provider[0] || !service_name[0] ||
            !join(entries[count].service, sizeof(entries[count].service), provider, service_name)) return false;
        entries[count].valid = valid != 0; entries[count].data = data; ++count;
        if (json.take(']')) return true;
        if (!json.take(',')) return false;
    } while (true);
}
bool Control::registryFile(const char *path) {
    const uint8_t *data = nullptr; size_t bytes = 0;
    const bool result = provider_.getFile(provider_.ctx, path, &data, &bytes);
    if (!result || !span(data, bytes) || bytes > 16384) return fail(Error::Provider, path);
    Json json(data, bytes); char key[80], domain_name[80] = {}; uint32_t instance = 0;
    Registry entries[kRegistry]{}; unsigned count = 0, seen = 0;
    if (!json.take('{')) return fail(Error::Registry, path);
    do {
        if (!json.text(key, sizeof(key)) || !json.take(':')) return fail(Error::Registry, path);
        unsigned bit = 0;
        if (!strcmp(key, "sr_domain")) { bit = 1; if (!domain(json, domain_name, instance)) return fail(Error::Registry, path); }
        else if (!strcmp(key, "sr_service")) { bit = 2; if (!serviceList(json, entries, count)) return fail(Error::Registry, path); }
        else if (!json.skip()) return fail(Error::Registry, path);
        if (bit & seen) return fail(Error::Registry, path);
        seen |= bit;
        if (json.take('}')) break;
        if (!json.take(',')) return fail(Error::Registry, path);
    } while (true);
    if (!json.end() || seen != 3 || count > kRegistry - registry_count_) return fail(Error::Registry, path);
    for (unsigned i = 0; i < count; ++i) {
        memcpy(entries[i].domain, domain_name, strlen(domain_name) + 1); entries[i].instance = instance;
        for (unsigned j = 0; j < registry_count_; ++j)
            if (!strcmp(entries[i].service, registry_[j].service) && !strcmp(entries[i].domain, registry_[j].domain))
                return fail(Error::Registry, "duplicate-registry-entry");
        registry_[registry_count_++] = entries[i];
    }
    event(path, count, instance); return true;
}

bool Control::initialize(const Resources &resources, const FileProvider &provider) {
    if (attempted_) return false;
    attempted_ = true; resources_ = resources; provider_ = provider;
    status_.generation = 1; status_.stage = Stage::Inputs;
    if (!provider.getFile || !resources.nowMs || !resources.waitMs || !resources.log || !resources.sync ||
        !span(resources.rmtfs_arena, resources.rmtfs_arena_bytes) || !span(resources.shared, resources.shared_bytes) ||
        resources.shared_bytes != 0x200000 || (resources.shared_phys & 4095) || !resources.shared_phys ||
        resources.shared_phys > UINT64_MAX - resources.shared_bytes ||
        ((resources.shared_phys & 0xffffffffull) + resources.shared_bytes > 0x100000000ull) ||
        overlap(resources.rmtfs_arena, resources.rmtfs_arena_bytes, resources.shared, resources.shared_bytes) ||
        overlap(this, sizeof(*this), resources.shared, resources.shared_bytes) ||
        overlap(this, sizeof(*this), resources.rmtfs_arena, resources.rmtfs_arena_bytes))
        return fail(Error::InvalidResources, "resources");
    const void *mapped = const_cast<const uint8_t *>(resources.smem.memory);
    if (!span(mapped, resources.smem.memory_bytes) || overlap(mapped, resources.smem.memory_bytes, this, sizeof(*this)) ||
        overlap(mapped, resources.smem.memory_bytes, resources.rmtfs_arena, resources.rmtfs_arena_bytes) ||
        overlap(mapped, resources.smem.memory_bytes, resources.shared, resources.shared_bytes)) return fail(Error::InvalidResources, "smem-alias");
    now_ = resources.nowMs(resources.ctx);
    if (now_ > UINT64_MAX - 180000) return fail(Error::Clock, "clock-range");
    if (!registryFile("firmware/modemr.jsn") || !registryFile("firmware/modemuw.jsn")) return false;
    static const char *const paths[4] = {"rmtfs-seed/modemst1.img", "rmtfs-seed/modemst2.img", "rmtfs-seed/fsg.img", "rmtfs-seed/fsc.img"};
    RmtfsRamStore::Seed seeds[4]{};
    for (unsigned i = 0; i < 4; ++i) {
        const bool result = provider.getFile(provider.ctx, paths[i], &seeds[i].data, &seeds[i].bytes);
        if (!result || !span(seeds[i].data, seeds[i].bytes) ||
            overlap(seeds[i].data, seeds[i].bytes, resources.shared, resources.shared_bytes)) return fail(Error::Provider, paths[i]);
        part_bytes_[i] = seeds[i].bytes;
    }
    if (!store_.initialize(seeds, resources.rmtfs_arena, resources.rmtfs_arena_bytes)) return fail(Error::InvalidResources, "rmtfs-arena");
    const Smem::Result result = smem_.initialize(resources.smem);
    if (result != Smem::Ok) return fail(Error::Smem, "smem-layout", result);
    logModemReason("modem-reason-before-pas");
    return prepareSmp2p();
}
void Control::logModemReason(const char *operation) {
    // SM8150 MPSS uses global SMEM item 421 for its crash reason.
    // Read the pre-PAS value too, so retained text can be identified.
    Smem::Item item{};
    const Smem::Result result = smem_.get(421, item, true);
    if (result != Smem::Ok) { event(operation, 0, 0, result); return; }
    uint8_t value[256];
    const size_t limit = item.bytes < sizeof(value) ? item.bytes : sizeof(value);
    Smem::barrier();
    smem_.copyOut(item.offset, value, limit);
    char diagnostic[sizeof("modem-reason-before-pas hex=") + 2 * sizeof(value)]{};
    size_t cursor = strlen(operation), captured = 0;
    memcpy(diagnostic, operation, cursor);
    memcpy(diagnostic + cursor, " hex=", 5); cursor += 5;
    static const char hex[] = "0123456789abcdef";
    while (captured < limit && value[captured]) {
        diagnostic[cursor++] = hex[value[captured] >> 4];
        diagnostic[cursor++] = hex[value[captured] & 15];
        ++captured;
    }
    event(diagnostic, item.bytes, captured);
}
bool Control::prepareSmp2p() {
    Smp2pObservation incoming{};
    if (!pollSmp2p(incoming)) return false;
    if (incoming.entryPresent && (incoming.state & 3)) return fail(Error::AlreadyRunning, "pre-pas-modem-state", int(incoming.state));
    bool created = false;
    const Smem::Result result = smem_.allocate(428, 340, outbound_, created);
    if (result != Smem::Ok) return fail(Error::Smem, "smp2p-allocate", result);
    /* Retained AP-owned headers may be reused only with a quiescent modem.
     * Clearing remote headers/state is never part of this operation. */
    if (!created && smem_.read(outbound_.offset) != 0 && smem_.read(outbound_.offset) != 0x504d5324)
        return fail(Error::Smp2p, "outbound-magic");
    smem_.write(outbound_.offset + 4, 0); Smem::barrier();
    smem_.write(outbound_.offset + 8, 1u << 16);
    smem_.write(outbound_.offset + 12, 16u | (1u << 16));
    smem_.write(outbound_.offset + 16, 0);
    const uint8_t name[16] = {'m','a','s','t','e','r','-','k','e','r','n','e','l',0,0,0};
    for (unsigned i = 0; i < 16; i += 4) smem_.write(outbound_.offset + 20 + i, le32(name + i));
    smem_.write(outbound_.offset + 36, 0); smem_.write(outbound_.offset, 0x504d5324);
    Smem::barrier(); smem_.write(outbound_.offset + 4, 1u | (1u << 8)); smem_.kick(14);
    stage(Stage::Smp2pPrepared, 0); return true;
}
bool Control::pollSmp2p(Smp2pObservation &out) {
    out = Smp2pObservation{};
    if (status_.stage == Stage::Failed) return false;
    Smem::Item item{}; const Smem::Result result = smem_.get(435, item);
    if (result == Smem::Missing) {
        if (fresh_ready_) { ++status_.generation; return fail(Error::Restart, "smp2p-item-lost"); }
        return true;
    }
    if (result != Smem::Ok || item.bytes < 20) return fail(Error::Smp2p, "inbound-item", result);
    const uint32_t version = smem_.read(item.offset + 4);
    Smem::barrier();
    if (!(version & 0xff)) {
        if (fresh_ready_) { ++status_.generation; return fail(Error::Restart, "smp2p-negotiation-lost"); }
        return true;
    }
    const uint32_t counts = smem_.read(item.offset + 12);
    const unsigned total = counts & 0xffff, valid = counts >> 16;
    if (smem_.read(item.offset) != 0x504d5324 || (version & 0xff) != 1 ||
        smem_.read(item.offset + 8) != 1 || total > 16 || valid > total ||
        20 + total * 20 > item.bytes) return fail(Error::Smp2p, "inbound-header");
    out.negotiated = true;
    const bool restart = (smem_.read(item.offset + 16) & 1) != 0;
    if (inbound_seen_ && restart != restart_flag_ && (fresh_ready_ || status_.stage >= Stage::WaitReady)) {
        ++status_.generation;
        if (outbound_.bytes) { smem_.write(outbound_.offset + 16, restart ? 2 : 0); smem_.kick(14); }
        return fail(Error::Restart, "smp2p-restart");
    }
    restart_flag_ = restart;
    for (unsigned i = 0; i < valid; ++i) {
        char name[17] = {}; const uint32_t at = item.offset + 20 + i * 20;
        smem_.copyOut(at, name, 16);
        if (strcmp(name, "slave-kernel")) continue;
        if (out.entryPresent) return fail(Error::Smp2p, "duplicate-slave-kernel");
        out.entryPresent = true; out.state = smem_.read(at + 16);
    }
    if (outbound_.bytes && (version & 0x100)) {
        const uint32_t flags = smem_.read(outbound_.offset + 16), want = restart ? 2 : 0;
        if ((flags & 2) != want) { smem_.write(outbound_.offset + 16, (flags & ~2u) | want); smem_.kick(14); }
    }
    if (out.entryPresent && status_.stage != Stage::Inputs && !(status_.smp2p_state & 2) && (out.state & 2)) fresh_ready_ = true;
    out.fresh = fresh_ready_ && out.entryPresent && (out.state & 2);
    if (out.entryPresent) {
        if (!inbound_seen_ || status_.smp2p_state != out.state) event("smp2p-state", out.state, out.fresh);
        status_.smp2p_state = out.state; inbound_seen_ = true;
        if ((out.state & 1) && status_.stage != Stage::Inputs) {
            logModemReason("modem-reason-at-fatal");
            return fail(Error::Fatal, "smp2p-fatal", int(out.state));
        }
    }
    if (fresh_ready_ && (!out.entryPresent || !(out.state & 2))) {
        ++status_.generation; return fail(Error::Restart, "smp2p-ready-lost");
    }
    return true;
}
bool Control::startAfterPas(uint64_t now_ms) {
    if (status_.stage != Stage::Smp2pPrepared) return fail(Error::NotPrepared, "start-after-pas");
    if (now_ms < now_ || now_ms > UINT64_MAX - 180000) return fail(Error::Clock, "pas-clock");
    now_ = now_ms; stage(Stage::WaitReady, 30000); return true;
}
bool Control::attachGlink() {
    bool created;
    Smem::Result result = smem_.allocate(478, 32, descriptors_, created);
    if (result != Smem::Ok) return fail(Error::Smem, "glink-descriptors", result);
    result = smem_.allocate(479, 16384, tx_, created);
    if (result != Smem::Ok) return fail(Error::Smem, "glink-tx", result);
    result = smem_.get(480, rx_);
    if (result == Smem::Missing) return true;
    if (result != Smem::Ok || tx_.bytes < 32 || tx_.bytes > 0x10000 || rx_.bytes < 32 || rx_.bytes > 0x10000 ||
        (tx_.bytes & 7) || (rx_.bytes & 7) || smem_.read(descriptors_.offset) >= tx_.bytes ||
        smem_.read(descriptors_.offset + 12) >= rx_.bytes) return fail(Error::Smem, "glink-fifo", result);
    smem_.write(descriptors_.offset + 4, 0); smem_.write(descriptors_.offset + 8, 0); Smem::barrier();
    stage(Stage::Glink, 10000); event("glink-fifos", tx_.bytes, rx_.bytes);
    return command(Version, 1, 1);
}
bool Control::command(uint16_t cmd, uint16_t p1, uint32_t p2, const void *data, size_t bytes) {
    if (bytes > sizeof(scratch_) - 8 || (bytes && !data)) return fail(Error::Protocol, "glink-send-size");
    const uint32_t padded = uint32_t((bytes + 15) & ~size_t(7));
    const uint32_t head = smem_.read(descriptors_.offset + 4), tail = smem_.read(descriptors_.offset);
    Smem::barrier();
    if (head >= tx_.bytes || tail >= tx_.bytes || (head & 7) || (tail & 7)) return fail(Error::Protocol, "glink-tx-index");
    const uint32_t free = tail <= head ? tx_.bytes - head + tail : tail - head;
    if (padded + 16 > free) return false;
    uint32_t cursor = head;
    const uint32_t header[2] = { uint32_t(cmd) | uint32_t(p1) << 16, p2 };
    const uint8_t *payload = static_cast<const uint8_t *>(data);
    for (uint32_t at = 0; at < padded; at += 4) {
        uint32_t value = 0;
        if (at < 8) value = header[at / 4];
        else {
            for (unsigned i = 0; i < 4 && at + i - 8 < bytes; ++i) value |= uint32_t(payload[at + i - 8]) << (8 * i);
        }
        smem_.write(tx_.offset + cursor, value); cursor = (cursor + 4) % tx_.bytes;
    }
    Smem::barrier(); smem_.write(descriptors_.offset + 4, cursor); smem_.kick(12); return true;
}
bool Control::commandSpace(uint32_t bytes) {
    const uint32_t head = smem_.read(descriptors_.offset + 4), tail = smem_.read(descriptors_.offset);
    Smem::barrier();
    if (head >= tx_.bytes || tail >= tx_.bytes || (head & 7) || (tail & 7)) return fail(Error::Protocol, "glink-tx-index");
    const uint32_t free = tail <= head ? tx_.bytes - head + tail : tail - head;
    return bytes + 16 <= free;
}
void Control::peek(uint32_t off, void *data, size_t bytes) {
    uint8_t *p = static_cast<uint8_t *>(data);
    uint32_t at = (rx_cursor_ + off) % rx_.bytes;
    for (size_t i = 0; i < bytes; ++i) { p[i] = uint8_t(smem_.read(rx_.offset + (at & ~3u)) >> (8 * (at & 3))); at = (at + 1) % rx_.bytes; }
}
bool Control::receiveOne() {
    const uint32_t head = smem_.read(descriptors_.offset + 12);
    rx_cursor_ = smem_.read(descriptors_.offset + 8); Smem::barrier();
    if (head >= rx_.bytes || rx_cursor_ >= rx_.bytes || (head & 7) || (rx_cursor_ & 7)) return fail(Error::Protocol, "glink-rx-index");
    const uint32_t available = head < rx_cursor_ ? rx_.bytes - rx_cursor_ + head : head - rx_cursor_;
    if (available < 8) return false;
    uint8_t header[16]; peek(0, header, 8);
    const uint16_t cmd = le16(header), channel = le16(header + 2); const uint32_t value = le32(header + 4);
    uint32_t bytes = 8;
    if (cmd == Open) {
        if (!value || value > 64) return fail(Error::Protocol, "glink-open-name");
        bytes += (value + 7) & ~7u;
    } else if (cmd == wire::Intent) {
        if (value > kRemoteIntents) return fail(Error::Protocol, "glink-intent-count");
        bytes += value * 8;
    } else if (cmd == TxData || cmd == TxDataCont) {
        if (available < 16) {
            if (!incomplete_since_) incomplete_since_ = now_;
            else if (now_ - incomplete_since_ >= 3000) return fail(Error::Protocol, "glink-incomplete-timeout");
            return false;
        }
        peek(8, header + 8, 8); const uint32_t chunk = le32(header + 8);
        if (chunk > 8192) return fail(Error::Protocol, "glink-chunk-size");
        bytes = 16 + ((chunk + 7) & ~7u);
    }
    if (bytes >= rx_.bytes) return fail(Error::Protocol, "glink-frame-size");
    if (bytes > available) {
        if (!incomplete_since_) incomplete_since_ = now_;
        else if (now_ - incomplete_since_ >= 3000) return fail(Error::Protocol, "glink-incomplete-timeout");
        return false;
    }
    incomplete_since_ = 0;
    switch (cmd) {
    case Version:
        if (channel != 1) return fail(Error::Protocol, "glink-version", channel);
        if (!command(VersionAck, 1, value & 1)) return false;
        break;
    case VersionAck:
        if (channel != 1 || (value & ~1u)) return fail(Error::Protocol, "glink-version-ack", channel);
        version_ = true; features_ = value; event("glink-version", channel, value); break;
    case Open: {
        char name[65] = {}; peek(8, name, value);
        if (name[value - 1] || strlen(name) + 1 != value || !channel) return fail(Error::Protocol, "glink-channel-name");
        if (!strcmp(name, "IPCRTR") && remote_open_ && remote_channel_ != channel) {
            ++status_.generation; return fail(Error::Restart, "glink-channel-replaced");
        }
        if (!command(OpenAck, channel, 0)) return false;
        if (!strcmp(name, "IPCRTR")) { remote_channel_ = channel; remote_open_ = true; event("glink-remote-open", channel); }
        break;
    }
    case OpenAck:
        if (channel == 1 && open_sent_) open_ack_ = true;
        break;
    case Close:
        if (!command(CloseAck, channel, 0)) return false;
        if (channel == remote_channel_) { ++status_.generation; return fail(Error::Restart, "glink-close"); }
        break;
    case CloseAck: break;
    case wire::Intent:
        if (channel == remote_channel_ && remote_open_) {
            unsigned new_items = 0;
            for (uint32_t i = 0; i < value; ++i) {
                uint8_t intent[8]; peek(8 + i * 8, intent, 8);
                const uint32_t intent_bytes = le32(intent), iid = le32(intent + 4);
                if (!intent_bytes) {
                    event("glink-intent-rejected", intent_bytes, iid);
                    return fail(Error::Protocol, "glink-invalid-intent");
                }
                for (unsigned j = 0; j < kRemoteIntents; ++j)
                    if (remote_intents_[j].bytes && remote_intents_[j].iid == iid)
                        return fail(Error::Protocol, "glink-duplicate-intent");
                for (uint32_t j = 0; j < i; ++j) {
                    uint8_t previous[8]; peek(8 + j * 8, previous, 8);
                    if (le32(previous + 4) == iid) return fail(Error::Protocol, "glink-duplicate-intent");
                }
                ++new_items;
            }
            unsigned free = 0; for (const Intent &intent : remote_intents_) if (!intent.bytes) ++free;
            if (new_items > free) return fail(Error::Protocol, "glink-intent-capacity");
            for (uint32_t i = 0; i < value; ++i) {
                uint8_t intent[8]; peek(8 + i * 8, intent, 8);
                for (Intent &slot : remote_intents_) if (!slot.bytes) {
                    slot = Intent{le32(intent + 4), le32(intent), false, 0};
                    event("glink-intent", slot.bytes, slot.iid);
                    break;
                }
            }
        }
        break;
    case RxDone: case RxDoneReuse:
        if (channel == remote_channel_) {
            bool found = false;
            for (Intent &intent : remote_intents_) if (intent.bytes && intent.iid == value) {
                if (!intent.busy) return fail(Error::Protocol, "glink-unowned-rx-done");
                if (queue_count_ && queue_[queue_head_].intent_assigned && queue_[queue_head_].iid == value &&
                    queue_[queue_head_].offset < queue_[queue_head_].bytes)
                    return fail(Error::Protocol, "glink-early-rx-done");
                if (cmd == RxDoneReuse && !(features_ & 1)) return fail(Error::Protocol, "glink-unnegotiated-reuse");
                if (cmd == RxDone) intent = Intent{};
                else { intent.busy = false; intent.deadline = 0; }
                found = true; break;
            }
            if (!found) return fail(Error::Protocol, "glink-unknown-rx-done");
        }
        break;
    case IntentRequest: {
        Receive *available = nullptr;
        if (channel == remote_channel_ && value && value <= kPacketBytes && intents_sent_)
            for (Receive &receive : receive_) if (!receive.advertised && !receive.active) { available = &receive; break; }
        if (available) {
            if (!commandSpace(24)) return false;
            uint8_t intent[8]; put32(intent, kPacketBytes); put32(intent + 4, next_local_iid_);
            if (!command(wire::Intent, 1, 1, intent, 8) || !command(IntentRequestAck, 1, 1)) return false;
            available->iid = next_local_iid_++; available->advertised = true;
            event("glink-intent-granted", available->iid, value);
        } else if (!command(IntentRequestAck, 1, 0)) return false;
        break;
    }
    case IntentRequestAck:
        if (channel == remote_channel_ && queue_count_ && queue_[queue_head_].intent_requested && !value)
            return fail(Error::IntentTimeout, "glink-intent-refused");
        break;
    case TxData: case TxDataCont: {
        const uint32_t chunk = le32(header + 8), remaining = le32(header + 12);
        if (channel != remote_channel_) break;
        Receive *target = nullptr;
        for (Receive &receive : receive_) if (receive.advertised && receive.iid == value) target = &receive;
        if (!intents_sent_ || !target) return fail(Error::Protocol, "glink-local-intent");
        Receive &receive = *target;
        if (cmd == TxData && receive.active) return fail(Error::Protocol, "glink-overlapping-data");
        if (cmd == TxDataCont && (!receive.active || receive.remaining != chunk + uint64_t(remaining)))
            return fail(Error::Protocol, "glink-continuation");
        const uint32_t offset = cmd == TxData ? 0 : receive.bytes;
        if (!chunk || offset > kPacketBytes || chunk > kPacketBytes - offset || remaining > kPacketBytes - offset - chunk)
            return fail(Error::Protocol, "glink-reassembly-range");
        if (!remaining && !commandSpace((features_ & 1) ? 8 : 24)) return false;
        if (!remaining && !command((features_ & 1) ? RxDoneReuse : RxDone, 1, value)) return false;
        peek(16, receive.data + offset, chunk); receive.bytes = offset + chunk; receive.remaining = remaining; receive.active = remaining != 0;
        receive.deadline = now_ + 3000;
        if (!remaining) {
            smem_.write(descriptors_.offset + 8, (rx_cursor_ + bytes) % rx_.bytes); Smem::barrier();
            if (!(features_ & 1)) {
                uint8_t intent[8]; put32(intent, kPacketBytes); put32(intent + 4, value);
                if (!command(wire::Intent, 1, 1, intent, 8)) return fail(Error::QueueFull, "readvertise-intent");
            }
            const bool result = packet(receive.data, receive.bytes); receive.bytes = 0;
            return result;
        }
        break;
    }
    case ReadNotify: smem_.kick(12); break;
    case Signals: break;
    default: return fail(Error::Protocol, "glink-unknown-command", cmd);
    }
    smem_.write(descriptors_.offset + 8, (rx_cursor_ + bytes) % rx_.bytes); Smem::barrier(); return true;
}

bool Control::send(uint32_t type, uint32_t source_port, uint32_t node, uint32_t port, const void *data, size_t bytes) {
    if (queue_count_ == kQueue) return fail(Error::QueueFull, "qrtr-queue");
    if (bytes > kPacketBytes - 32 || (bytes && !data)) return fail(Error::Protocol, "qrtr-send-size");
    const size_t padded = (bytes + 3) & ~size_t(3);
    Packet &packet = queue_[(queue_head_ + queue_count_) % kQueue];
    put32(packet.data, 1); put32(packet.data + 4, type); put32(packet.data + 8, kAppsNode);
    put32(packet.data + 12, source_port); put32(packet.data + 16, 0); put32(packet.data + 20, uint32_t(bytes));
    put32(packet.data + 24, node); put32(packet.data + 28, port);
    if (bytes) memcpy(packet.data + 32, data, bytes);
    memset(packet.data + 32 + bytes, 0, padded - bytes);
    packet.bytes = uint32_t(32 + padded); packet.offset = 0; packet.iid = 0;
    packet.generation = status_.generation; packet.deadline = now_ + 3000;
    packet.intent_requested = false; packet.intent_assigned = false;
    ++queue_count_; return true;
}
bool Control::flush(bool transmit) {
    for (Intent &intent : remote_intents_) if (intent.busy && now_ >= intent.deadline) return fail(Error::IntentTimeout, "glink-rx-done-timeout");
    for (unsigned budget = 0; budget < 16 && queue_count_; ++budget) {
        Packet &packet = queue_[queue_head_];
        if (packet.generation != status_.generation) return fail(Error::Restart, "queued-generation");
        if (now_ >= packet.deadline) return fail(Error::IntentTimeout, "glink-send-timeout");
        if (!transmit) return true;
        if (!packet.intent_assigned) {
            Intent *selected = nullptr;
            for (Intent &intent : remote_intents_)
                if (!intent.busy && intent.bytes >= packet.bytes && (!selected || intent.bytes < selected->bytes)) selected = &intent;
            if (!selected) {
                if (!packet.intent_requested && command(IntentRequest, 1, packet.bytes)) packet.intent_requested = true;
                return status_.stage != Stage::Failed;
            }
            selected->busy = true; selected->deadline = now_ + 10000; packet.iid = selected->iid;
            packet.intent_assigned = true;
        }
        const uint32_t remaining = packet.bytes - packet.offset, chunk = remaining > 8192 ? 8192 : remaining;
        put32(scratch_, chunk); put32(scratch_ + 4, remaining - chunk);
        memcpy(scratch_ + 8, packet.data + packet.offset, chunk);
        if (!command(packet.offset ? TxDataCont : TxData, 1, packet.iid, scratch_, chunk + 8)) return status_.stage != Stage::Failed;
        packet.offset += chunk;
        if (packet.offset == packet.bytes) {
            if (le32(packet.data + 4) == NewServer)
                event("qrtr-advertisement-submitted", le32(packet.data + 36), le32(packet.data + 24));
            --queue_count_; queue_head_ = (queue_head_ + 1) % kQueue;
        }
    }
    return true;
}
bool Control::advertise(uint32_t node) {
    static const uint32_t services[3][3] = {{14, 1, kRmtfsPort}, {0x40, 0x101, kPdPort}, {4096, 1, kTftpPort}};
    uint8_t data[20];
    for (const auto &service : services) {
        put32(data, NewServer); put32(data + 4, service[0]); put32(data + 8, service[1]);
        put32(data + 12, kAppsNode); put32(data + 16, service[2]);
        if (!send(NewServer, kControlPort, node, kControlPort, data, sizeof(data))) return false;
    }
    // Remote NEW_SERVER messages supply discovery. NEW_LOOKUP is local to NS.
    services_sent_ = true;
    return true;
}
bool Control::reply(const QrtrPacket &packet, QmiBuilder &message) {
    const size_t bytes = message.finish();
    if (!bytes) return fail(Error::Protocol, "qmi-reply-size");
    if (cache_active_ < 8) {
        Transaction &transaction = transactions_[cache_active_];
        memcpy(transaction.response, message.data, bytes); transaction.response_bytes = bytes;
    }
    return send(Data, packet.destination_port, packet.source_node, packet.source_port, message.data, bytes);
}
bool Control::serviceRequest(const QrtrPacket &packet, const QmiMessage &message) {
    if (packet.bytes > sizeof(transactions_[0].request)) return fail(Error::Protocol, "qmi-service-size");
    for (const Transaction &transaction : transactions_) {
        if (!transaction.used || transaction.expires <= now_ || transaction.generation != status_.generation ||
            transaction.node != packet.source_node || transaction.port != packet.source_port ||
            transaction.local_port != packet.destination_port || transaction.txn != message.transaction) continue;
        if (transaction.id != message.id || transaction.request_bytes != packet.bytes ||
            memcmp(transaction.request, packet.payload, packet.bytes)) return fail(Error::Protocol, "qmi-transaction-reused");
        event("qmi-replayed", message.id, message.transaction);
        if (packet.destination_port == kRmtfsPort && message.id == 3) {
            size_t bytes;
            const uint8_t *direction = message.get(2, bytes);
            /* The shared buffer may have served a newer request since this
             * reply. An idempotent read must refill it before acknowledging
             * the retry. Writes keep their cached acknowledgement. */
            if (direction && bytes == 1 && direction[0] == 0) return rmtfs(packet, message);
        }
        return send(Data, packet.destination_port, packet.source_node, packet.source_port, transaction.response, transaction.response_bytes);
    }
    cache_active_ = cache_next_++ % 8;
    Transaction &transaction = transactions_[cache_active_];
    transaction.node = packet.source_node; transaction.port = packet.source_port; transaction.local_port = packet.destination_port;
    transaction.generation = status_.generation; transaction.id = message.id; transaction.txn = message.transaction;
    transaction.request_bytes = packet.bytes; transaction.response_bytes = 0; transaction.expires = now_ + 30000; transaction.used = true;
    memcpy(transaction.request, packet.payload, packet.bytes);
    const bool result = packet.destination_port == kRmtfsPort ? rmtfs(packet, message) : pdmapper(packet, message);
    cache_active_ = UINT32_MAX;
    return result;
}
bool Control::controlPacket(const QrtrPacket &packet) {
    if (packet.bytes != 20 || le32(packet.payload) != packet.type) return fail(Error::Protocol, "qrtr-control-size");
    const uint8_t *data = packet.payload;
    if (packet.type == Hello) {
        if (status_.stage == Stage::PdFailureAck) return true;
        event("qrtr-hello", packet.source_node, packet.source_port);
        uint8_t hello[20] = {}; put32(hello, Hello);
        if (!send(Hello, kControlPort, packet.source_node, kControlPort, hello, sizeof(hello))) return false;
        return advertise(packet.source_node);
    }
    if (packet.type == Bye || packet.type == Exit) { ++status_.generation; return fail(Error::Restart, "qrtr-bye"); }
    if (packet.type == NewServer || packet.type == DelServer) {
        const uint32_t service = le32(data + 4), instance = le32(data + 8), node = le32(data + 12), port = le32(data + 16);
        event(packet.type == NewServer ? "qrtr-new-server" : "qrtr-del-server", service, instance);
        event("qrtr-server-source", packet.source_node, packet.source_port);
        event("qrtr-server-endpoint", node, port);
        if (service == 0x45 && (instance & 0xff) == 1 && node == packet.source_node && node != kAppsNode && port && port != kControlPort) {
            if (packet.type == DelServer && node == status_.server_node && port == status_.server_port) {
                ++status_.generation; return fail(Error::Restart, "wlfw-deleted");
            }
            if (packet.type == NewServer) {
                if (status_.server_port && (node != status_.server_node || port != status_.server_port)) {
                    ++status_.generation; return fail(Error::Restart, "wlfw-replaced");
                }
                status_.server_node = node; status_.server_port = port; event("wlfw-service", node, port);
            }
        }
    } else if (packet.type == DelClient) {
        const uint32_t node = le32(data + 4), port = le32(data + 8);
        for (unsigned i = 0; i < kTransfers; ++i)
            if (transfers_[i].used && transfers_[i].node == node && transfers_[i].port == port) closeTransfer(i);
    }
    return true;
}
bool Control::packet(const uint8_t *data, size_t bytes) {
    QrtrPacket packet{};
    if (!QrtrPacket::parse(data, bytes, packet)) return fail(Error::Protocol, "qrtr-header");
    ++status_.packets;
    if (packet.source_node == kAppsNode ||
        (packet.destination_node != kAppsNode && packet.destination_node != kBroadcastNode)) return fail(Error::Protocol, "qrtr-node");
    if (packet.type != Data) return controlPacket(packet);
    if (status_.stage == Stage::PdFailureAck) return true;
    if (packet.confirm) {
        uint8_t resume[20] = {}; put32(resume, ResumeTx); put32(resume + 4, packet.destination_node); put32(resume + 8, packet.destination_port);
        if (!send(ResumeTx, packet.destination_port, packet.source_node, packet.source_port, resume, sizeof(resume))) return false;
    }
    if (packet.destination_port == kTftpPort || (packet.destination_port >= 0x100 && packet.destination_port < 0x100 + kTransfers)) return tftp(packet);
    if (packet.destination_port != kRmtfsPort && packet.destination_port != kPdPort && packet.destination_port != kWlfwPort) return true;
    QmiMessage message{};
    if (!QmiMessage::parse(packet.payload, packet.bytes, message)) return fail(Error::Protocol, "qmi-header");
    if (packet.destination_port == kWlfwPort) return wlfw(packet, message);
    if (message.type != kQmiRequest) return true;
    return serviceRequest(packet, message);
}

bool Control::rmtfs(const QrtrPacket &packet, const QmiMessage &message) {
    ++status_.rmtfs_requests; event("rmtfs-request", message.id, message.transaction);
    QmiBuilder response(kQmiResponse, message.transaction, message.id); uint32_t handle = 0; uint16_t error = 0;
    message.u32(1, handle);
    const bool owned = handle >= 1 && handle <= 4 && handle_open_[handle - 1] && handle_node_[handle - 1] == packet.source_node;
    if (message.id == 1) {
        static const char *const names[4] = {"/boot/modem_fs1", "/boot/modem_fs2", "/boot/modem_fsg", "/boot/modem_fsc"};
        size_t bytes; const uint8_t *path = message.get(1, bytes); handle = 0;
        for (unsigned i = 0; i < 4; ++i) if (path && bytes == strlen(names[i]) && !memcmp(path, names[i], bytes)) handle = i + 1;
        if (!handle || (handle_open_[handle - 1] && handle_node_[handle - 1] != packet.source_node)) error = 3;
        else { handle_open_[handle - 1] = true; handle_node_[handle - 1] = packet.source_node; }
        if (error) pdFailureDiagnostic(message, 1, "rmtfs-open-path");
        event("rmtfs-open", handle, bytes, error);
        response.result(error); if (!error) response.u32(0x10, handle);
    } else if (message.id == 2) {
        error = owned ? 0 : 3; if (owned) handle_open_[handle - 1] = false; response.result(error);
    } else if (message.id == 4) {
        uint32_t size = 0;
        const bool sized = message.u32(2, size);
        error = sized && size && size <= resources_.shared_bytes ? 0 : 3;
        response.result(error); if (!error) response.u64(0x10, resources_.shared_phys);
        event("rmtfs-alloc", size, resources_.shared_phys, error);
        event("rmtfs-alloc-caller", handle, owned ? 1 : 0, sized ? 0 : -1);
    } else if (message.id == 3) {
        size_t bytes, dir_bytes, force_bytes;
        const uint8_t *entries = message.get(3, bytes), *direction = message.get(2, dir_bytes), *force = message.get(4, force_bytes);
        /* rmtfs_access_iovec_req_msg_v01 has a u8 element count and triples
         * {sector_addr, physical_offset, num_sector}, each u32. */
        bool valid = owned && entries && bytes >= 1 && entries[0] &&
            bytes == 1 + size_t(entries[0]) * 12 && direction && dir_bytes == 1 && direction[0] <= 1 &&
            force && force_bytes == 1 && force[0] <= 1;
        if (valid) for (unsigned i = 0; i < entries[0]; ++i) {
            const uint8_t *entry = entries + 1 + i * 12;
            const uint32_t sector = le32(entry), offset = le32(entry + 4), count = le32(entry + 8);
            const uint64_t base_low = resources_.shared_phys & 0xffffffffull;
            const uint64_t buffer_offset = offset >= base_low ? uint64_t(offset) - base_low : offset;
            const uint64_t sectors = part_bytes_[handle - 1] / 512;
            if (!count || sector > sectors || count > sectors - sector || buffer_offset > resources_.shared_bytes ||
                count > (resources_.shared_bytes - buffer_offset) / 512) { valid = false; break; }
        }
        if (valid && direction[0]) {
            const int sync = resources_.sync(resources_.ctx, resources_.shared, resources_.shared_bytes, false);
            if (sync) return fail(Error::RmtfsIo, "rmtfs-acquire", sync);
        }
        if (valid) for (unsigned i = 0; i < entries[0]; ++i) {
            const uint8_t *entry = entries + 1 + i * 12;
            const uint32_t sector = le32(entry), offset = le32(entry + 4), count = le32(entry + 8);
            const uint64_t base_low = resources_.shared_phys & 0xffffffffull;
            const size_t buffer_offset = size_t(offset >= base_low ? uint64_t(offset) - base_low : offset);
            uint8_t *buffer = resources_.shared + buffer_offset;
            const bool result = direction[0] ? store_.write(handle, sector, count, buffer, size_t(count) * 512) :
                store_.read(handle, sector, count, buffer, size_t(count) * 512);
            if (!result) return fail(Error::RmtfsIo, "rmtfs-backend");
            event(direction[0] ? "rmtfs-write" : "rmtfs-read", sector, count);
        }
        if (valid && !direction[0]) {
            const int sync = resources_.sync(resources_.ctx, resources_.shared, resources_.shared_bytes, true);
            if (sync) return fail(Error::RmtfsIo, "rmtfs-publish", sync);
        }
        response.result(valid ? 0 : 3);
    } else if (message.id == 5) {
        response.result(owned ? 0 : 3); const uint8_t ok = 0; if (owned) response.tlv(0x10, &ok, 1);
    } else response.result(0x47);
    return reply(packet, response);
}
bool Control::pdmapper(const QrtrPacket &packet, const QmiMessage &message) {
    ++status_.pd_requests; event("pd-request", message.id, message.transaction);
    QmiBuilder response(kQmiResponse, message.transaction, message.id);
    if (message.id == 0x24) {
        status_.error = Error::PdFailure;
        event("pd-failure-report", packet.source_node, packet.source_port, message.transaction);
        pdFailureDiagnostic(message, 1, "pd-failure-service");
        pdFailureDiagnostic(message, 2, "pd-failure-reason");
        stage(Stage::PdFailureAck, 0);
        response.result(0);
        return reply(packet, response);
    }
    if (message.id != 0x21) { response.result(0x47); return reply(packet, response); }
    size_t name_bytes, offset_bytes; const uint8_t *name = message.get(1, name_bytes), *offset_data = message.get(0x10, offset_bytes);
    if (!name || !name_bytes || name_bytes >= 80 || (offset_data && offset_bytes != 4)) {
        response.result(3); return reply(packet, response);
    }
    const uint32_t offset = offset_data ? le32(offset_data) : 0;
    uint8_t list[768] = {}; size_t used = 1; uint16_t total = 0;
    for (unsigned i = 0; i < registry_count_; ++i) {
        const Registry &entry = registry_[i];
        if (strlen(entry.service) != name_bytes || memcmp(entry.service, name, name_bytes)) continue;
        if (total++ < offset) continue;
        const size_t n = strlen(entry.domain);
        if (n + 10 > sizeof(list) - used) continue;
        list[used++] = uint8_t(n); memcpy(list + used, entry.domain, n); used += n;
        put32(list + used, entry.instance); used += 4; list[used++] = entry.valid ? 1 : 0;
        put32(list + used, entry.data); used += 4; ++list[0];
    }
    response.result(0); uint8_t count[2]; put16(count, total); response.tlv(0x10, count, 2);
    put16(count, 1); response.tlv(0x11, count, 2); response.tlv(0x12, list, used);
    event("pd-domains", total, list[0]); return reply(packet, response);
}
void Control::pdFailureDiagnostic(const QmiMessage &message, uint8_t tag, const char *operation) {
    size_t bytes;
    const uint8_t *value = message.get(tag, bytes);
    const size_t captured = bytes > kPdDiagnosticBytes ? size_t(kPdDiagnosticBytes) : bytes;
    char diagnostic[sizeof("pd-failure-service hex=") + 2 * kPdDiagnosticBytes]{};
    size_t cursor = strlen(operation);
    memcpy(diagnostic, operation, cursor);
    memcpy(diagnostic + cursor, " hex=", 5);
    cursor += 5;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < captured; ++i) {
        diagnostic[cursor++] = hex[value[i] >> 4];
        diagnostic[cursor++] = hex[value[i] & 15];
    }
    event(diagnostic, bytes, captured, value ? 0 : -1);
}
bool Control::wlfw(const QrtrPacket &packet, const QmiMessage &message) {
    if (message.type != kQmiResponse || !qmi_pending_ || packet.source_node != qmi_node_ ||
        packet.source_port != qmi_port_ || message.transaction != transaction_ || message.id != 0x24 ||
        qmi_generation_ != status_.generation) { event("wlfw-unmatched", message.id, message.transaction); return true; }
    uint16_t error = 0;
    if (!message.result(error)) return fail(Error::QmiResult, "wlfw-cap-result", error);
    if (!wire::capability(message, status_.capability)) return fail(Error::CapabilityFields, "wlfw-cap-fields");
    qmi_pending_ = false;
    status_.capability_generation = status_.generation;
    event("wlfw-chip-family", status_.capability.chip_id, status_.capability.chip_family);
    event("wlfw-board-soc", status_.capability.board_id, status_.capability.soc_id);
    stage(Stage::Complete, 0); return true;
}

bool Control::poll(uint64_t now_ms) {
    if (status_.stage == Stage::Failed) return false;
    if (status_.stage < Stage::WaitReady) return fail(Error::NotPrepared, "poll-before-pas");
    if (now_ms < now_ || now_ms > UINT64_MAX - 180000) return fail(Error::Clock, "poll-clock");
    now_ = now_ms; Smp2pObservation observation{};
    if (!pollSmp2p(observation)) return false;
    if (status_.stage == Stage::WaitReady) {
        if (observation.negotiated && observation.entryPresent && observation.fresh && (observation.state & 2) && !(observation.state & 1)) {
            if (!attachGlink()) return false;
        }
        if (status_.stage == Stage::WaitReady) {
            if (now_ >= stage_deadline_) return fail(Error::GlinkTimeout, "smp2p-ready-timeout");
            return true;
        }
    } else if (!observation.negotiated || !observation.entryPresent || !(observation.state & 2)) {
        ++status_.generation; return fail(Error::Restart, "modem-ready-lost");
    }
    if (status_.stage != Stage::PdFailureAck && !flush()) return false;
    for (const Receive &receive : receive_)
        if (receive.active && now_ >= receive.deadline) return fail(Error::Protocol, "glink-reassembly-timeout");
    for (unsigned budget = 0; budget < 32 && status_.stage != Stage::Failed &&
         (queue_count_ < kQueue - 4 || status_.stage == Stage::PdFailureAck); ++budget)
        if (!receiveOne()) break;
    if (status_.stage == Stage::Failed) return false;
    if (status_.stage == Stage::PdFailureAck) {
        // Consume RX credits and restart notices before submitting the ACK.
        // A remaining RX backlog defers TX, with the existing queue deadline
        // and generation checks still enforced by flush(false).
        Smem::barrier();
        const bool receive_drained = smem_.read(descriptors_.offset + 8) == smem_.read(descriptors_.offset + 12);
        if (!flush(receive_drained)) return false;
        if (!queue_count_) return fail(Error::PdFailure, "pd-failure-ack-submitted");
        return true;
    }
    if (version_ && !open_sent_) {
        static const char name[] = "IPCRTR";
        if (command(Open, 1, sizeof(name), name, sizeof(name))) open_sent_ = true;
    }
    if (open_ack_ && remote_open_ && !intents_sent_) {
        /* Half the slots are reserved for real RX_INTENT_REQ allocations. */
        uint8_t intents[(kIntents / 2) * 8];
        for (unsigned i = 0; i < kIntents / 2; ++i) { put32(intents + i * 8, kPacketBytes); put32(intents + i * 8 + 4, i + 1); }
        if (command(wire::Intent, 1, kIntents / 2, intents, sizeof(intents))) {
            intents_sent_ = true;
            for (unsigned i = 0; i < kIntents / 2; ++i) { receive_[i].iid = i + 1; receive_[i].advertised = true; }
        }
    }
    if (version_ && open_ack_ && remote_open_ && intents_sent_ && !services_sent_) {
        stage(Stage::Services, 120000); if (!advertise(0)) return false; stage(Stage::WaitWlfw, 120000);
    }
    if (status_.stage == Stage::WaitWlfw && status_.server_port && queue_count_ < kQueue - 1) {
        QmiBuilder request(kQmiRequest, transaction_, 0x24);
        if (!send(Data, kWlfwPort, status_.server_node, status_.server_port, request.data, request.finish())) return false;
        qmi_node_ = status_.server_node; qmi_port_ = status_.server_port; qmi_generation_ = status_.generation;
        qmi_pending_ = true; qmi_deadline_ = now_ + 10000; stage(Stage::Capability, 10000);
        event("wlfw-cap-request", transaction_, 0x24);
    }
    if (!transferPoll() || !flush()) return false;
    if (qmi_pending_ && now_ >= qmi_deadline_) return fail(Error::QmiTimeout, "wlfw-cap-timeout");
    if (status_.stage != Stage::Complete && now_ >= stage_deadline_) return fail(status_.stage == Stage::Glink ? Error::GlinkTimeout : Error::ServiceTimeout, "stage-timeout");
    return true;
}
Control::Status Control::run() {
    if (status_.stage < Stage::WaitReady || status_.stage == Stage::Failed) { fail(Error::NotPrepared, "run-before-pas"); return status_; }
    while (status_.stage != Stage::Complete && poll(resources_.nowMs(resources_.ctx))) resources_.waitMs(resources_.ctx, 1);
    return status_;
}

static size_t decimalText(char *output, uint64_t value) {
    char reverse[24]; size_t bytes = 0;
    do { reverse[bytes++] = char('0' + value % 10); value /= 10; } while (value);
    for (size_t i = 0; i < bytes; ++i) output[i] = reverse[bytes - i - 1];
    output[bytes] = 0; return bytes;
}
static bool firmwarePath(const char *input, char *output, size_t capacity) {
    static const char prefix[] = "/readonly/firmware/image/";
    if (strncmp(input, prefix, sizeof(prefix) - 1)) return false;
    const char *leaf = input + sizeof(prefix) - 1, *component = leaf;
    for (const char *p = leaf; ; ++p) {
        if (!*p || *p == '/') {
            const size_t n = size_t(p - component);
            if (!n || (n == 1 && component[0] == '.') || (n == 2 && component[0] == '.' && component[1] == '.')) return false;
            if (!*p) break;
            leaf = component = p + 1;
        } else if ((*p < 'a' || *p > 'z') && (*p < 'A' || *p > 'Z') &&
                   (*p < '0' || *p > '9') && *p != '.' && *p != '_' && *p != '-') return false;
    }
    if (!join(output, capacity, "firmware", leaf)) return false;
    for (char *p = output; *p; ++p) if (*p >= 'A' && *p <= 'Z') *p = char(*p + ('a' - 'A'));
    return true;
}
static bool ramPath(const char *path) {
    static const char prefix[] = "/readwrite/";
    if (strncmp(path, prefix, sizeof(prefix) - 1)) return false;
    const char *component = path + sizeof(prefix) - 1;
    for (const char *p = component; ; ++p) {
        if (!*p || *p == '/') {
            const size_t n = size_t(p - component);
            if (!n || (n == 1 && component[0] == '.') || (n == 2 && component[0] == '.' && component[1] == '.')) return false;
            if (!*p) return true;
            component = p + 1;
        } else if ((*p < 'a' || *p > 'z') && (*p < 'A' || *p > 'Z') &&
                   (*p < '0' || *p > '9') && *p != '.' && *p != '_' && *p != '-') return false;
    }
}
bool Control::transferError(uint32_t source, uint32_t node, uint32_t port, uint16_t code, const char *text) {
    uint8_t data[128]; const size_t n = strlen(text) + 1;
    if (n > sizeof(data) - 4) return fail(Error::Protocol, "tftp-error-size");
    putBe16(data, 5); putBe16(data + 2, code); memcpy(data + 4, text, n);
    event("tftp-error", code, source);
    return send(Data, source, node, port, data, n + 4);
}
bool Control::transferRequest(const QrtrPacket &packet) {
    const bool write = be16(packet.payload) == 2;
    size_t at = 2; char path[160], mode[16];
    if (packet.bytes > 512 || !wire::string(packet.payload, packet.bytes, at, path, sizeof(path)) ||
        !wire::string(packet.payload, packet.bytes, at, mode, sizeof(mode)) || strcmp(mode, "octet"))
        return transferError(kTftpPort, packet.source_node, packet.source_port, 4, "invalid request");
    for (unsigned i = 0; i < kTransfers; ++i) {
        const Transfer &old = transfers_[i];
        if (!old.used || old.node != packet.source_node || old.port != packet.source_port) continue;
        /* A retransmitted RRQ cannot truncate an in-flight RAM write. */
        if (old.initial_bytes && old.block == 0)
            return send(Data, 0x100 + i, old.node, old.port, old.initial, old.initial_bytes);
        return transferError(kTftpPort, packet.source_node, packet.source_port, 0, "transfer active");
    }
    unsigned index = 0; while (index < kTransfers && transfers_[index].used) ++index;
    if (index == kTransfers) return transferError(kTftpPort, packet.source_node, packet.source_port, 0, "busy");
    Transfer candidate{};
    candidate.node = packet.source_node; candidate.port = packet.source_port; candidate.write = write;
    candidate.generation = status_.generation; candidate.block_bytes = 512; candidate.window = 1;
    candidate.ram_file = -1; candidate.timeout_ms = 200;
    uint32_t option_seen = 0; char option_names[7][16]{}; uint64_t option_values[7]{}; unsigned options = 0;
    uint64_t seek = 0, rsize = 0;
    while (at < packet.bytes) {
        char key[16], value[24]; uint64_t number;
        if (!wire::string(packet.payload, packet.bytes, at, key, sizeof(key)) ||
            !wire::string(packet.payload, packet.bytes, at, value, sizeof(value)) || !wire::decimal(value, number))
            return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "invalid option");
        unsigned bit = 0;
        if (!strcmp(key, "blksize")) {
            bit = 1; if (number < 8) return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "invalid blksize");
            candidate.block_bytes = number > kBlockBytes ? uint32_t(kBlockBytes) : uint32_t(number); number = candidate.block_bytes;
        } else if (!strcmp(key, "wsize")) {
            bit = 2; if (!number) return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "invalid window");
            candidate.window = number > 8 ? 8 : uint32_t(number); number = candidate.window;
        } else if (!strcmp(key, "seek")) { bit = 4; seek = number; }
        else if (!strcmp(key, "rsize")) { bit = 8; rsize = number; }
        else if (!strcmp(key, "tsize")) { bit = 16; }
        else if (!strcmp(key, "timeoutms")) {
            bit = 32; if (number < 50 || number > 5000) return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "invalid timeout");
            candidate.timeout_ms = unsigned(number);
        } else if (!strcmp(key, "timeout")) {
            bit = 64; if (!number || number > 5) return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "invalid timeout");
            candidate.timeout_ms = unsigned(number * 1000);
        } else continue;
        if ((option_seen & bit) || ((bit == 32 || bit == 64) && (option_seen & 96)))
            return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "duplicate option");
        option_seen |= bit;
        memcpy(option_names[options], key, strlen(key) + 1); option_values[options++] = number;
    }
    bool found = false;
    char canonical[160];
    if (firmwarePath(path, canonical, sizeof(canonical))) {
        if (write) return transferError(kTftpPort, packet.source_node, packet.source_port, 2, "read only");
        found = provider_.getFile(provider_.ctx, canonical, &candidate.file, &candidate.file_bytes) &&
            span(candidate.file, candidate.file_bytes);
    } else if (ramPath(path)) {
        for (const RamFile &file : ram_files_)
            if (file.used && !strcmp(file.path, path) && (file.writing || (write && file.readers)))
                return transferError(kTftpPort, packet.source_node, packet.source_port, 0, "file busy");
        if (write) {
            if (seek || rsize) return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "write offset unsupported");
            for (unsigned i = 0; i < kRamFiles; ++i) if (!ram_files_[i].used) { candidate.ram_file = int(i); found = true; break; }
            if (!found) return transferError(kTftpPort, packet.source_node, packet.source_port, 3, "RAM quota");
            for (unsigned i = 0; i < options; ++i)
                if (!strcmp(option_names[i], "tsize") && option_values[i] > kRamFileBytes)
                    return transferError(kTftpPort, packet.source_node, packet.source_port, 3, "RAM quota");
        } else {
            for (unsigned i = 0; i < kRamFiles; ++i) {
                RamFile &file = ram_files_[i];
                if (file.used && !file.writing && !strcmp(file.path, path)) {
                    candidate.file = file.data; candidate.file_bytes = file.bytes; candidate.ram_file = int(i); found = true; break;
                }
            }
        }
    }
    ++status_.tftp_requests; event(write ? "tftp-wrq" : "tftp-rrq", candidate.file_bytes, found); event(path);
    if (!found) return transferError(kTftpPort, packet.source_node, packet.source_port, 1, "file not found");
    if (!write) {
        if (seek > candidate.file_bytes) return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "seek outside file");
        candidate.seek = size_t(seek); candidate.length = candidate.file_bytes - candidate.seek;
        if (rsize && rsize < candidate.length) candidate.length = size_t(rsize);
        /* First candidate avoids ambiguous 16-bit block rollover. */
        if (candidate.length / candidate.block_bytes >= 65535)
            return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "transfer too large");
    }
    putBe16(candidate.initial, 6); size_t used = 2;
    for (unsigned i = 0; i < options; ++i) {
        char value[24];
        uint64_t number = option_values[i];
        if (!write && !strcmp(option_names[i], "tsize")) number = candidate.file_bytes;
        const size_t value_bytes = decimalText(value, number) + 1, key_bytes = strlen(option_names[i]) + 1;
        if (key_bytes + value_bytes > sizeof(candidate.initial) - used)
            return transferError(kTftpPort, packet.source_node, packet.source_port, 8, "options too large");
        memcpy(candidate.initial + used, option_names[i], key_bytes); used += key_bytes;
        memcpy(candidate.initial + used, value, value_bytes); used += value_bytes;
    }
    candidate.used = true; candidate.deadline = now_ + 30000; candidate.retry_at = now_ + candidate.timeout_ms;
    if (options) candidate.initial_bytes = used;
    else if (write) { putBe16(candidate.initial, 4); putBe16(candidate.initial + 2, 0); candidate.initial_bytes = 4; }
    else { candidate.next_block = 1; candidate.window_end = candidate.window; }
    if (write) {
        RamFile &file = ram_files_[candidate.ram_file];
        memcpy(file.path, path, strlen(path) + 1); file.used = true; file.writing = true; file.bytes = 0;
    } else if (candidate.ram_file >= 0) ++ram_files_[candidate.ram_file].readers;
    transfers_[index] = candidate;
    if (candidate.initial_bytes) return send(Data, 0x100 + index, candidate.node, candidate.port, candidate.initial, candidate.initial_bytes);
    return true;
}
bool Control::transferBlock(unsigned index, uint32_t block) {
    Transfer &transfer = transfers_[index];
    const uint64_t offset = uint64_t(block - 1) * transfer.block_bytes;
    if (!block || block > 65535 || offset > transfer.length) return fail(Error::Protocol, "tftp-block-range");
    const size_t bytes = transfer.length - size_t(offset) < transfer.block_bytes ? transfer.length - size_t(offset) : transfer.block_bytes;
    uint8_t data[4 + kBlockBytes]; putBe16(data, 3); putBe16(data + 2, uint16_t(block));
    if (bytes) memcpy(data + 4, transfer.file + transfer.seek + size_t(offset), bytes);
    if (!send(Data, 0x100 + index, transfer.node, transfer.port, data, bytes + 4)) return false;
    transfer.block = block; transfer.final = bytes < transfer.block_bytes; transfer.retry_at = now_ + transfer.timeout_ms;
    return true;
}
void Control::closeTransfer(unsigned index) {
    Transfer &transfer = transfers_[index];
    if (transfer.ram_file >= 0) {
        RamFile &file = ram_files_[transfer.ram_file];
        if (transfer.write && file.writing) file = RamFile{};
        else if (!transfer.write && file.readers) --file.readers;
    }
    transfer.used = false;
}
bool Control::tftp(const QrtrPacket &packet) {
    if (packet.bytes < 4) return transferError(packet.destination_port, packet.source_node, packet.source_port, 4, "short packet");
    const uint16_t op = be16(packet.payload), block = be16(packet.payload + 2);
    if (packet.destination_port == kTftpPort) {
        if (op == 1 || op == 2) return transferRequest(packet);
        return transferError(kTftpPort, packet.source_node, packet.source_port, 4, "request expected");
    }
    const unsigned index = packet.destination_port - 0x100;
    if (index >= kTransfers) return true;
    Transfer &transfer = transfers_[index];
    if (!transfer.used || transfer.node != packet.source_node || transfer.port != packet.source_port || transfer.generation != status_.generation)
        return transferError(packet.destination_port, packet.source_node, packet.source_port, 5, "unknown transfer");
    if (op == 5) {
        event("tftp-client-error", block, index);
        closeTransfer(index); return true;
    }
    if (op == 4 && !transfer.write) {
        if (packet.bytes != 4 || block > transfer.block || block < transfer.acknowledged) return true;
        if (transfer.final && block == transfer.block) {
            event("tftp-read-complete", transfer.length, transfer.block); closeTransfer(index); return true;
        }
        /* Only an ACK for the window end starts the next window. Older ACKs
         * retransmit the outstanding suffix, without advancing file offset. */
        const bool progress = block > transfer.acknowledged || (transfer.initial_bytes && block == 0);
        if (progress) { transfer.retries = 0; transfer.deadline = now_ + 30000; }
        else if (++transfer.retries > 5) return fail(Error::TransferTimeout, "tftp-duplicate-ack-timeout", int(index));
        transfer.acknowledged = block; transfer.next_block = uint32_t(block) + 1;
        transfer.window_end = uint32_t(block) + transfer.window; transfer.final = false;
        transfer.initial_bytes = 0;
        return true;
    }
    if (op == 3 && transfer.write) {
        const size_t bytes = packet.bytes - 4;
        if (bytes > transfer.block_bytes || !block || block > transfer.block + 1) return true;
        uint8_t ack[4]; putBe16(ack, 4); putBe16(ack + 2, uint16_t(transfer.block));
        if (block <= transfer.block) return send(Data, packet.destination_port, transfer.node, transfer.port, ack, sizeof(ack));
        if (transfer.final) return true;
        RamFile &file = ram_files_[transfer.ram_file];
        if (bytes > sizeof(file.data) - file.bytes) {
            file = RamFile{}; transfer.used = false;
            return transferError(packet.destination_port, transfer.node, transfer.port, 3, "RAM quota");
        }
        memcpy(file.data + file.bytes, packet.payload + 4, bytes); file.bytes += bytes; transfer.block = block;
        transfer.retries = 0; transfer.deadline = now_ + 30000; transfer.retry_at = now_ + transfer.timeout_ms;
        transfer.final = bytes < transfer.block_bytes;
        putBe16(ack + 2, block);
        if (!send(Data, packet.destination_port, transfer.node, transfer.port, ack, sizeof(ack))) return false;
        if (transfer.final) {
            for (unsigned i = 0; i < kRamFiles; ++i)
                if (int(i) != transfer.ram_file && ram_files_[i].used && !strcmp(ram_files_[i].path, file.path)) ram_files_[i] = RamFile{};
            file.writing = false; event("tftp-ram-write-complete", file.bytes, index);
            /* Retain the final ACK transaction briefly for duplicate DATA. */
            transfer.deadline = now_ + 5000;
        }
        return true;
    }
    return true;
}
bool Control::transferPoll() {
    for (unsigned i = 0; i < kTransfers; ++i) {
        Transfer &transfer = transfers_[i];
        if (!transfer.used) continue;
        if (transfer.generation != status_.generation) return fail(Error::Restart, "tftp-generation");
        if (transfer.write && transfer.final && now_ >= transfer.deadline) { closeTransfer(i); continue; }
        if (now_ >= transfer.deadline) return fail(Error::TransferTimeout, "tftp-progress-timeout", int(i));
        if (transfer.write) {
            if (transfer.final || now_ < transfer.retry_at || queue_count_ >= kQueue - 4) continue;
            if (++transfer.retries > 5) return fail(Error::TransferTimeout, "tftp-write-timeout", int(i));
            if (!transfer.block && transfer.initial_bytes) {
                if (!send(Data, 0x100 + i, transfer.node, transfer.port, transfer.initial, transfer.initial_bytes)) return false;
                transfer.retry_at = now_ + transfer.timeout_ms; continue;
            }
            uint8_t ack[4]; putBe16(ack, 4); putBe16(ack + 2, uint16_t(transfer.block));
            if (!send(Data, 0x100 + i, transfer.node, transfer.port, ack, sizeof(ack))) return false;
            transfer.retry_at = now_ + transfer.timeout_ms; continue;
        }
        if (!transfer.next_block && now_ >= transfer.retry_at && queue_count_ < kQueue - 4) {
            if (++transfer.retries > 5) return fail(Error::TransferTimeout, "tftp-ack-timeout", int(i));
            if (transfer.initial_bytes) {
                if (!send(Data, 0x100 + i, transfer.node, transfer.port, transfer.initial, transfer.initial_bytes)) return false;
                transfer.retry_at = now_ + transfer.timeout_ms; continue;
            }
            transfer.next_block = transfer.acknowledged + 1; transfer.window_end = transfer.block; transfer.final = false;
        }
        for (unsigned budget = 0; budget < 8 && transfer.next_block && queue_count_ < kQueue - 4; ++budget) {
            const uint32_t block = transfer.next_block;
            if (!transferBlock(i, block)) return false;
            ++transfer.next_block;
            if (transfer.final || block >= transfer.window_end) transfer.next_block = 0;
        }
    }
    return true;
}
} // namespace nabu_wifi

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Derived from buhuo666/XIAOMI-PAD-5_nabu-on-IOS at
 * 56c7364f5c083583b07eea24dded38a9ee932e5f,
 * patches/nabu-wireless/NabuWlanService.cpp (BSD-2-Clause-Patent).
 * Native station/ioctl policy belongs to the separately built network host.
 */
#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K != 0 && NABU_WIFI_ATH10K != 1
#error NABU_WIFI_ATH10K_must_be_zero_or_one
#endif
#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K == 1
#include "NabuWifiService.h"
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSData.h>
#include <libkern/crypto/sha2.h>
#include <kern/sched_prim.h>
#include <string.h>
extern "C" {
#include <sys/hakios.net.h>
#include <sys/errno.h>
int nabu_ath10k_os_radio_powered();
int nabu_ath10k_driver_transmit(const unsigned char *, unsigned long);
int lx_os_thread(const char *, void (*)(void *), void *);
void nabu_wlan_runtime_lost();
}

static_assert(sizeof(hakios_sta_ops) == 64, "station callback ABI");
static_assert(sizeof(struct hakios_sta_state) == 1088, "station state ABI");
static_assert(sizeof(hakios_net_link) == 40, "network link ABI");

namespace NabuWifiService {
static int hexDigit(uint8_t value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool selectMac(const uint8_t *source, size_t bytes, const uint8_t pin[32],
               Digest digest, MacIdentity *output)
{
    if (!output) return false;
    *output = {};
    if (!source || bytes != MacSourceBytes || !pin || !digest ||
        memcmp(source, "wlan0=", 6)) return false;
    MacIdentity selected{};
    digest(source, bytes, selected.sourceSha256);
    if (memcmp(pin, selected.sourceSha256, 32)) return false;
    for (unsigned index = 0; index < 6; ++index) {
        int high = hexDigit(source[6 + index * 2]);
        int low = hexDigit(source[7 + index * 2]);
        if (high < 0 || low < 0) return false;
        selected.address[index] = uint8_t(high * 16 + low);
    }
    static const uint8_t zero[6]{};
    if ((selected.address[0] & 3) || !memcmp(selected.address, zero, 6)) return false;
    *output = selected;
    return true;
}
} // namespace NabuWifiService

namespace {
IOLock *gate;
IOLock *owner;
uint32_t initialized;
uint32_t fatal;
hakios_net_link link{};
hakios_sta_ops nativeOps{};
hakios_sta_ops backendOps{};
const hakios_sta_ops *backendIdentity;
bool published, valid, committed, pendingUp, joining, workerStarted;
bool backendAddressPresent;
uint8_t backendAddress[6]{};
uint64_t generation, connection;
unsigned backendActive, txActive, rxActive;

struct Frame {
    size_t length;
    uint64_t connection;
    uint8_t bytes[HAKIOS_NET_FRAME_MAX];
};
Frame *queue;
unsigned queueHead, queueCount;
uint64_t txAccepted, txDropped, txReturned, txErrors, rxAccepted, rxDropped;

bool ready()
{
    return __atomic_load_n(&initialized, __ATOMIC_ACQUIRE) == 2;
}

bool initialize()
{
    if (ready()) return true;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&initialized, &expected, 1, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return false;
    IOLock *newGate = IOLockAlloc();
    IOLock *newOwner = IOLockAlloc();
    if (!newGate || !newOwner) {
        if (newGate) IOLockFree(newGate);
        if (newOwner) IOLockFree(newOwner);
        __atomic_store_n(&initialized, 0, __ATOMIC_RELEASE);
        return false;
    }
    gate = newGate;
    owner = newOwner;
    __atomic_store_n(&initialized, 2, __ATOMIC_RELEASE);
    return true;
}

void digest(const void *data, size_t bytes, uint8_t output[32])
{
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, data, bytes);
    SHA256_Final(output, &context);
}

bool property(IORegistryEntry *node, const char *name, void *output, size_t bytes)
{
    OSData *data = OSDynamicCast(OSData, node->getProperty(name));
    if (!data || data->getLength() != bytes) return false;
    memcpy(output, data->getBytesNoCopy(), bytes);
    return true;
}

bool readIdentity(NabuWifiService::MacIdentity &identity)
{
    identity = {};
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    IORegistryEntry *wlan = IORegistryEntry::fromPath("/wlan", gIODTPlane);
    uint8_t source[NabuWifiService::MacSourceBytes]{}, pin[32]{}, chosenMac[6]{}, wlanMac[6]{};
    bool found = chosen && wlan &&
        property(chosen, "nabu-wifi-mac-source", source, sizeof(source)) &&
        property(chosen, "nabu-wifi-mac-source-sha256", pin, sizeof(pin)) &&
        property(chosen, "mac-address-wifi0", chosenMac, sizeof(chosenMac)) &&
        property(wlan, "local-mac-address", wlanMac, sizeof(wlanMac));
    if (chosen) chosen->release();
    if (wlan) wlan->release();
    if (!found || !NabuWifiService::selectMac(source, sizeof(source), pin, digest, &identity) ||
        memcmp(identity.address, chosenMac, 6) || memcmp(identity.address, wlanMac, 6)) {
        identity = {};
        return false;
    }
    return true;
}

/* Gate is held for short admission/publication changes. The network host's
 * link-state function posts the kernel link event and makes no backend calls.
 * Publication order is host sta_publish -> gate for join/lost/fatal paths. */
void closeLocked()
{
    ++connection;
    joining = pendingUp = committed = false;
    txDropped += queueCount;
    queueHead = queueCount = 0;
    if (published) hakios_net_link_state(false);
}

void closeAndDrainPackets()
{
    IOLockLock(gate);
    closeLocked();
    while (txActive || rxActive) IOLockSleep(gate, &txActive, THREAD_UNINT);
    IOLockUnlock(gate);
}

/* Every backend call, including state/channels/heard, pins the offered owner.
 * Withdrawal revokes admission, drains the network host, then waits for these
 * pins. No service lock remains held while backend code executes. */
struct BackendCall {
    hakios_sta_ops ops{};
    const hakios_sta_ops *identity = nullptr;
    uint64_t generation = 0;

    BackendCall()
    {
        IOLockLock(gate);
        if (valid && !__atomic_load_n(&fatal, __ATOMIC_ACQUIRE)) {
            ops = backendOps;
            identity = backendIdentity;
            generation = ::generation;
            ++backendActive;
        }
        IOLockUnlock(gate);
    }
    ~BackendCall()
    {
        if (!identity) return;
        IOLockLock(gate);
        --backendActive;
        IOLockWakeup(gate, &backendActive, false);
        IOLockUnlock(gate);
    }
    bool currentLocked() const
    {
        return identity && valid && backendIdentity == identity && ::generation == generation &&
            !__atomic_load_n(&fatal, __ATOMIC_ACQUIRE);
    }
    bool current() const
    {
        IOLockLock(gate);
        bool result = currentLocked();
        IOLockUnlock(gate);
        return result;
    }
    BackendCall(const BackendCall &) = delete;
    BackendCall &operator=(const BackendCall &) = delete;
};

void transmitWorker(void *)
{
    Frame frame;
    for (;;) {
        IOLockLock(gate);
        while (!queueCount) IOLockSleep(gate, &queueCount, THREAD_UNINT);
        frame = queue[queueHead];
        queueHead = (queueHead + 1) % NabuWifiService::QueueCapacity;
        --queueCount;
        if (!valid || !committed || frame.connection != connection ||
            __atomic_load_n(&fatal, __ATOMIC_ACQUIRE)) {
            ++txDropped;
            IOLockUnlock(gate);
            continue;
        }
        ++txActive;
        IOLockUnlock(gate);
        int error = nabu_ath10k_driver_transmit(frame.bytes, frame.length);
        IOLockLock(gate);
        ++txReturned;
        if (error) ++txErrors;
        --txActive;
        IOLockWakeup(gate, &txActive, false);
        IOLockUnlock(gate);
    }
}

bool transmit(mbuf_t packet, size_t length)
{
    IOLockLock(gate);
    if (!packet || !valid || !committed || !workerStarted ||
        __atomic_load_n(&fatal, __ATOMIC_ACQUIRE) || length < 14 ||
        length > HAKIOS_NET_FRAME_MAX || queueCount == NabuWifiService::QueueCapacity) {
        ++txDropped;
        IOLockUnlock(gate);
        return false;
    }
    Frame &frame = queue[(queueHead + queueCount) % NabuWifiService::QueueCapacity];
    if (mbuf_copydata(packet, 0, length, frame.bytes)) {
        ++txDropped;
        IOLockUnlock(gate);
        return false;
    }
    frame.length = length;
    frame.connection = connection;
    ++queueCount;
    ++txAccepted;
    IOLockWakeup(gate, &queueCount, false);
    IOLockUnlock(gate);
    return true;
}

int stationPower(bool on)
{
    BackendCall call;
    if (!call.identity) return ENXIO;
    if (!on) closeAndDrainPackets();
    int error = call.ops.power(on);
    return call.current() ? error : ENXIO;
}

int stationScan(const hakios_sta_scan *request)
{
    if (!request || request->ssid_length > 32 || request->frequency_count > 64) return EINVAL;
    BackendCall call;
    if (!call.identity) return ENXIO;
    int error = call.ops.scan(request);
    return call.current() ? error : ENXIO;
}

void stationHeard(void (*each)(const hakios_sta_bss *, void *), void *context)
{
    BackendCall call;
    if (call.identity && each) call.ops.heard(each, context);
}

struct JoinCommit {
    const BackendCall *call;
    uint64_t connection;
};

bool commitJoin(void *context)
{
    const auto *join = static_cast<const JoinCommit *>(context);
    IOLockLock(gate);
    bool accept = join->call->currentLocked() && joining && pendingUp &&
        connection == join->connection;
    if (accept) {
        committed = true;
        joining = pendingUp = false;
        hakios_net_link_state(true);
    }
    IOLockUnlock(gate);
    return accept;
}

int stationJoin(const hakios_sta_join *request)
{
    if (!request || !request->ssid_length || request->ssid_length > 32 ||
        request->passphrase_length > 64) return EINVAL;
    closeAndDrainPackets();
    if (request->security != HAKIOS_STA_WPA2_PSK) return EOPNOTSUPP;
    BackendCall call;
    if (!call.identity) return ENXIO;
    IOLockLock(gate);
    joining = call.currentLocked();
    JoinCommit join{&call, connection};
    IOLockUnlock(gate);
    int error = call.ops.join(request);
    struct hakios_sta_state state{};
    call.ops.state(&state);
    if (!error && (state.phase != HAKIOS_STA_JOINED ||
                   !hakios_sta_join_commit(commitJoin, &join))) {
        closeAndDrainPackets();
        if (call.current() && nabu_ath10k_os_radio_powered()) call.ops.leave();
        error = ECANCELED;
    }
    if (error) closeAndDrainPackets();
    return call.current() ? error : ENXIO;
}

int stationLeave()
{
    BackendCall call;
    if (!call.identity) return ENXIO;
    closeAndDrainPackets();
    int error = call.ops.leave();
    return call.current() ? error : ENXIO;
}

void stationState(struct hakios_sta_state *state)
{
    if (!state) return;
    *state = {};
    BackendCall call;
    if (!call.identity) { state->last_error = ENXIO; return; }
    IOLockLock(gate);
    uint64_t observedConnection = connection;
    IOLockUnlock(gate);
    call.ops.state(state);
    IOLockLock(gate);
    if (!call.currentLocked()) {
        *state = {};
        state->last_error = ENXIO;
    } else if ((state->phase == HAKIOS_STA_JOINED || state->phase == HAKIOS_STA_JOINING) &&
               (observedConnection != connection || (!committed && !joining))) {
        *state = {};
        state->phase = HAKIOS_STA_IDLE;
    }
    IOLockUnlock(gate);
}

unsigned stationChannels(hakios_sta_channel *channels, unsigned capacity)
{
    if (!channels || !capacity) return 0;
    BackendCall call;
    if (!call.identity) return 0;
    unsigned count = call.ops.channels(channels, capacity);
    if (count > capacity || !call.current()) return 0;
    return count;
}

void withdraw()
{
    IOLockLock(gate);
    valid = false;
    ++generation;
    closeLocked();
    IOLockUnlock(gate);
    hakios_sta_attach(nullptr);
    IOLockLock(gate);
    while (backendActive) IOLockSleep(gate, &backendActive, THREAD_UNINT);
    while (txActive || rxActive) IOLockSleep(gate, &txActive, THREAD_UNINT);
    backendIdentity = nullptr;
    backendOps = {};
    backendAddressPresent = false;
    IOLockUnlock(gate);
}
} // namespace

extern "C" bool nabu_wlan_service_mac_address(uint8_t address[6], uint8_t pin[32])
{
    if (address) memset(address, 0, 6);
    if (pin) memset(pin, 0, 32);
    if (!address || !pin) return false;
    NabuWifiService::MacIdentity identity;
    if (!readIdentity(identity)) return false;
    memcpy(address, identity.address, 6);
    memcpy(pin, identity.sourceSha256, 32);
    return true;
}

extern "C" void nabu_wlan_service_publish()
{
    if (!initialize()) return;
    IOLockLock(owner);
    IOLockLock(gate);
    bool unavailable = published || __atomic_load_n(&fatal, __ATOMIC_ACQUIRE);
    IOLockUnlock(gate);
    if (unavailable) { IOLockUnlock(owner); return; }
    NabuWifiService::MacIdentity identity;
    if (!readIdentity(identity)) {
        IOLog("NABU WLAN SERVICE: permanent MAC source/pin or address binding unavailable\n");
        IOLockUnlock(owner);
        return;
    }
    if (!queue) queue = static_cast<Frame *>(IOMalloc(sizeof(Frame) * NabuWifiService::QueueCapacity));
    if (!queue) { IOLockUnlock(owner); return; }
    if (!workerStarted) {
        bool started = lx_os_thread("nabu-wlan-tx", transmitWorker, nullptr) == 0;
        IOLockLock(gate);
        workerStarted = started;
        IOLockUnlock(gate);
    }
    if (!workerStarted) { IOLockUnlock(owner); return; }
    if (__atomic_load_n(&fatal, __ATOMIC_ACQUIRE)) { IOLockUnlock(owner); return; }
    link.name = "Nabu WCN399x ath10k";
    link.unit = 0;
    memcpy(link.address, identity.address, 6);
    link.wireless = true;
    link.up = false;
    link.transmit = transmit;
    bool attached = hakios_net_attach(&link);
    IOLockLock(gate);
    published = attached;
    IOLockUnlock(gate);
    IOLog("NABU WLAN SERVICE: en0 attached=%u permanent-source-bound=1\n", attached);
    IOLockUnlock(owner);
}

extern "C" void nabu_ath10k_os_net_attach(const unsigned char *address)
{
    if (!initialize()) return;
    IOLockLock(gate);
    backendAddressPresent = address != nullptr;
    if (address) memcpy(backendAddress, address, 6);
    IOLockUnlock(gate);
}

extern "C" void nabu_ath10k_os_station(const hakios_sta_ops *ops)
{
    if (!initialize()) return;
    IOLockLock(owner);
    if (!ops) {
        withdraw();
        IOLockUnlock(owner);
        return;
    }
    if (!ops->power || !ops->scan || !ops->heard || !ops->join || !ops->leave ||
        !ops->state || !ops->channels) { IOLockUnlock(owner); return; }
    IOLockLock(gate);
    bool acceptable = published && !valid && !backendIdentity && backendAddressPresent &&
        !memcmp(link.address, backendAddress, 6) && !memcmp(link.address, ops->address, 6) &&
        !__atomic_load_n(&fatal, __ATOMIC_ACQUIRE);
    IOLockUnlock(gate);
    if (!acceptable || !nabu_ath10k_os_radio_powered()) { IOLockUnlock(owner); return; }
    IOLockLock(gate);
    if (__atomic_load_n(&fatal, __ATOMIC_ACQUIRE)) {
        IOLockUnlock(gate);
        IOLockUnlock(owner);
        return;
    }
    backendOps = *ops;
    backendIdentity = ops;
    ++generation;
    valid = true;
    closeLocked();
    nativeOps = *ops;
    nativeOps.power = stationPower;
    nativeOps.scan = stationScan;
    nativeOps.heard = stationHeard;
    nativeOps.join = stationJoin;
    nativeOps.leave = stationLeave;
    nativeOps.state = stationState;
    nativeOps.channels = stationChannels;
    IOLockUnlock(gate);
    hakios_sta_attach(&nativeOps);
    if (!hakios_sta_present()) withdraw();
    IOLockUnlock(owner);
}

extern "C" void nabu_wlan_service_invalidate(int error)
{
    __atomic_store_n(&fatal, 1, __ATOMIC_RELEASE);
    hakios_sta_invalidate(error);
    if (!ready()) return;
    IOLockLock(gate);
    valid = false;
    ++generation;
    closeLocked();
    IOLockUnlock(gate);
}

extern "C" void nabu_ath10k_os_station_lost(int error)
{
    hakios_sta_lost(error);
    if (!ready()) return;
    IOLockLock(gate);
    closeLocked();
    IOLockUnlock(gate);
}

extern "C" void nabu_ath10k_os_station_fatal(int error)
{
    nabu_wlan_service_invalidate(error);
    nabu_wlan_runtime_lost();
}

extern "C" void nabu_ath10k_os_net_link(int up)
{
    if (!ready()) return;
    IOLockLock(gate);
    if (up) pendingUp = valid && joining && !__atomic_load_n(&fatal, __ATOMIC_ACQUIRE);
    else if (pendingUp || committed || joining) closeLocked();
    IOLockUnlock(gate);
}

extern "C" void nabu_ath10k_os_net_input(const unsigned char *frame, unsigned long length)
{
    if (!ready()) return;
    IOLockLock(gate);
    if (!frame || length < 14 || length > HAKIOS_NET_FRAME_MAX || !valid || !committed ||
        __atomic_load_n(&fatal, __ATOMIC_ACQUIRE)) {
        ++rxDropped;
        IOLockUnlock(gate);
        return;
    }
    ++rxActive;
    IOLockUnlock(gate);
    hakios_net_input(frame, length);
    IOLockLock(gate);
    ++rxAccepted;
    --rxActive;
    IOLockWakeup(gate, &txActive, false);
    IOLockUnlock(gate);
}

extern "C" void nabu_wlan_service_summary()
{
    if (!ready()) return;
    IOLockLock(gate);
    uint64_t accepted = txAccepted, dropped = txDropped, returned = txReturned, errors = txErrors;
    uint64_t received = rxAccepted, rejected = rxDropped, epoch = generation, association = connection;
    unsigned queued = queueCount, active = txActive, readers = backendActive, inputs = rxActive;
    bool up = committed;
    IOLockUnlock(gate);
    IOLog("NABU WLAN DATA: link=%u generation=%llu connection=%llu TX accepted=%llu dropped=%llu "
          "backend-returned=%llu errors=%llu queued=%u active=%u RX handed=%llu dropped=%llu "
          "backend-pins=%u rx-active=%u\n", up, (unsigned long long)epoch,
          (unsigned long long)association, (unsigned long long)accepted, (unsigned long long)dropped,
          (unsigned long long)returned, (unsigned long long)errors, queued, active,
          (unsigned long long)received, (unsigned long long)rejected, readers, inputs);
}
#endif

/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Derived from donor 56c7364 NabuAth10kQrtr.cpp. */
#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <kern/thread.h>
#include <sys/errno.h>
extern "C" {
#include <sys/hakios.qrtr.h>
}
#include "NabuWifiQrtr.h"
#include "NabuWifiQrtrApi.h"

struct hakios_qrtr_port {
    uint32_t id = 0, node = 0;
    uint64_t epoch = 0, generation = 0;
    bool retired = false;
};
namespace {
using Router = NabuAth10kQrtr;
struct Flight {
    enum Kind { Data, Retired, Knel, Dmon } kind = Data;
    uint64_t ticket = 0, router_ticket = 0, generation = 0, epoch = 0;
    uint32_t from = 0, node = 0, destination = 0;
    unsigned slot = 0;
    bool queued = false;
};
struct NabuQrtrNative {
    static void *operator new(size_t, void *address) { return address; }
    Router router;
    IOLock *lock = nullptr;
    thread_t owner = nullptr;
    hakios_qrtr_port ports[Router::port_count]{};
    NabuWifiQrtrOps ops{};
    Router::Endpoint observed{};
    uint64_t control_generation = 0, next_ticket = 0;
    Flight flight{};
    unsigned handoff_mask = 0;
    bool bound = false, stopping = true, peer_seen = false;
    bool polling = false, submitting = false, transport_transition = false;
    bool transport_installed = false, handoff_started = false, legacy_owned = false;
    bool instance_lost = false, shutting_down = false;
    int reason = 0, last_status = 0;
};
NabuQrtrNative *native;

NabuQrtrNative *state() { return __atomic_load_n(&native, __ATOMIC_ACQUIRE); }
uint64_t generation(const NabuQrtrNative &n) { return n.bound ? n.control_generation : n.router.epoch(); }
int error(Router::Result result)
{
    switch (result) {
    case Router::Ok: return 0;
    case Router::Full: return ENOBUFS;
    case Router::TooLarge: return EMSGSIZE;
    case Router::Closed: return ENXIO;
    case Router::NotConnected: return ENOTCONN;
    case Router::Busy: return EBUSY;
    case Router::Empty: return EWOULDBLOCK;
    case Router::InstanceLost: return ENETDOWN;
    default: return EINVAL;
    }
}
hakios_qrtr_port *find(NabuQrtrNative &n, const hakios_qrtr_port *port)
{
    for (auto &candidate : n.ports) {
        if (&candidate == port && candidate.id && !candidate.retired) return &candidate;
    }
    return nullptr;
}
bool owns(const NabuQrtrNative &n, uint32_t local)
{
    return n.router.owns_port(local) || (n.legacy_owned && (local == 0x12 || local == 0x14));
}
bool free_ports(const NabuQrtrNative &n)
{
    for (const auto &port : n.ports) if (port.id) return false;
    return true;
}
void clear_unposted_retired(NabuQrtrNative &n)
{
    for (unsigned i = 0; i < Router::port_count; ++i) {
        auto &port = n.ports[i];
        bool leased = n.flight.ticket && n.flight.kind == Flight::Retired &&
            n.flight.slot == i && n.flight.from == port.id;
        if (port.retired && !leased) port = {};
    }
}
void lose(NabuQrtrNative &n, int reason)
{
    n.router.invalidate();
    n.peer_seen = false;
    n.reason = reason;
    n.instance_lost = true;
    n.handoff_started = false;
    n.handoff_mask = 0;
    clear_unposted_retired(n);
    IOLockWakeup(n.lock, &n.router, false);
}
void wait_transition(NabuQrtrNative &n)
{
    while (n.transport_transition) IOLockSleep(n.lock, &n.router, THREAD_UNINT);
}

hakios_qrtr_port *open_port(hakios_qrtr_receive_t receive, hakios_qrtr_server_t server, void *context)
{
    auto *n = state();
    if (!n) return nullptr;
    IOLockLock(n->lock);
    hakios_qrtr_port *out = nullptr;
    if (!n->stopping && !n->transport_transition) {
        for (auto &port : n->ports) if (!port.id) {
            if (n->router.open(receive, server, context, port.id) == Router::Ok) {
                port.epoch = n->router.epoch();
                port.generation = generation(*n);
                out = &port;
            }
            break;
        }
    }
    IOLockUnlock(n->lock);
    return out;
}
int send_port(hakios_qrtr_port *handle, uint32_t node, uint32_t to, const void *data, size_t bytes)
{
    auto *n = state();
    if (!n) return ENXIO;
    IOLockLock(n->lock);
    auto *port = find(*n, handle);
    int status = ENXIO;
    if (port && !n->stopping && port->generation == generation(*n)) {
        status = error(n->router.send_at(port->epoch, port->id, node, to, data, bytes));
    }
    IOLockUnlock(n->lock);
    return status;
}
int lookup_port(hakios_qrtr_port *handle, uint32_t service, uint32_t version, uint32_t instance)
{
    auto *n = state();
    if (!n) return ENXIO;
    IOLockLock(n->lock);
    auto *port = find(*n, handle);
    int status = ENXIO;
    if (port && !n->stopping && port->generation == generation(*n) && port->epoch == n->router.epoch()) {
        status = error(n->router.lookup(port->id, service, version, instance));
    }
    IOLockUnlock(n->lock);
    return status;
}
void close_port(hakios_qrtr_port *handle)
{
    auto *n = state();
    if (!n) return;
    IOLockLock(n->lock);
    hakios_qrtr_port *port = nullptr;
    for (auto &candidate : n->ports) if (&candidate == handle && candidate.id) port = &candidate;
    if (!port) { IOLockUnlock(n->lock); return; }
    const uint32_t id = port->id;
    const uint64_t epoch = port->epoch;
    n->router.begin_close(id);
    while (n->router.finish_close(id) == Router::Busy) {
        if (current_thread() == n->owner) panic("Nabu QRTR: close inside owner lease");
        IOLockSleep(n->lock, &n->router, THREAD_UNINT);
    }
    /* Another close waiter may have finished and its DEL_CLIENT may already
     * have submitted. Never retire a different handle reusing this slot. */
    if (port->id == id && port->epoch == epoch && !port->retired) {
        if (n->peer_seen && !n->stopping && n->router.instance_live()) {
            port->node = n->observed.node;
            port->retired = true;
        } else *port = {};
    }
    IOLockWakeup(n->lock, &n->router, false);
    while (port->id == id && port->epoch == epoch && port->retired) {
        if (current_thread() == n->owner) panic("Nabu QRTR: close needs owner submission progress");
        IOLockSleep(n->lock, &n->router, THREAD_UNINT);
    }
    IOLockUnlock(n->lock);
}
const hakios_qrtr_ops transport{open_port, send_port, lookup_port, close_port};

int complete(NabuQrtrNative &n, uint64_t ticket, int status)
{
    if (status < 0) return EINVAL;
    if (!ticket || n.flight.ticket != ticket) return ENOENT;
    Flight flight = n.flight;
    n.flight = {};
    n.last_status = status;
    if (flight.kind == Flight::Data) {
        int finished = error(n.router.finish_send(flight.router_ticket, status == 0));
        if (finished) return finished;
    } else if (flight.kind == Flight::Retired) {
        auto &port = n.ports[flight.slot];
        if (port.id == flight.from && port.epoch == flight.epoch && port.retired &&
            (status == 0 || !n.router.instance_live())) port = {};
    } else if (!status && !n.stopping && n.peer_seen &&
               flight.generation == generation(n) && n.handoff_started) {
        n.handoff_mask |= flight.kind == Flight::Knel ? 1u : 2u;
        if (n.handoff_mask == 3) n.legacy_owned = true;
    }
    IOLockWakeup(n.lock, &n.router, false);
    return 0;
}
void little32(uint8_t *data, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) data[i] = uint8_t(value >> (i * 8));
}
int next_output(NabuQrtrNative &n, const uint8_t *&data, size_t &bytes, uint8_t *control)
{
    if (n.flight.ticket) return EWOULDBLOCK;
    if (n.next_ticket == UINT64_MAX) return ENOBUFS;
    Flight flight;
    flight.generation = generation(n);
    flight.epoch = n.router.epoch();
    flight.node = n.observed.node;
    bool selected = false;
    if (n.bound && n.handoff_started && n.handoff_mask != 3 && n.peer_seen) {
        flight.kind = (n.handoff_mask & 1) ? Flight::Dmon : Flight::Knel;
        flight.from = flight.kind == Flight::Knel ? 0x12 : 0x14;
        selected = true;
    } else if (n.router.instance_live()) {
        for (unsigned i = 0; i < Router::port_count; ++i) if (n.ports[i].retired) {
            flight.kind = Flight::Retired;
            flight.slot = i;
            flight.from = n.ports[i].id;
            flight.node = n.ports[i].node;
            flight.epoch = n.ports[i].epoch;
            selected = true;
            break;
        }
    }
    if (selected) {
        little32(control, 6); little32(control + 4, 1);
        little32(control + 8, flight.from); little32(control + 12, 0); little32(control + 16, 0);
        data = control; bytes = 20;
        flight.destination = 0xfffffffe;
    } else {
        Router::Send packet;
        auto result = n.router.begin_send(packet);
        if (result != Router::Ok) return error(result);
        flight.kind = Flight::Data;
        flight.router_ticket = packet.ticket;
        flight.from = packet.local;
        flight.node = packet.node;
        flight.destination = packet.port;
        flight.epoch = packet.epoch;
        data = packet.data; bytes = packet.bytes;
    }
    flight.ticket = ++n.next_ticket;
    n.flight = flight;
    return 0;
}
int poll(NabuQrtrNative &n, bool checked, uint64_t expected, NabuAth10kQrtrSend send, void *cookie)
{
    (void)send;
    (void)cookie;
    IOLockLock(n.lock);
    if (n.stopping || current_thread() != n.owner || n.polling ||
        (checked && (!expected || expected != generation(n)))) {
        int result = ENETDOWN;
        if (current_thread() != n.owner) result = EPERM;
        if (n.polling) result = EBUSY;
        if (n.stopping) result = ENETDOWN;
        IOLockUnlock(n.lock);
        return result;
    }
    if (!n.bound) { IOLockUnlock(n.lock); return ENOTCONN; }
    n.polling = true;
    int status = 0;
    for (unsigned i = 0; i < Router::port_count + Router::queue_count && !n.stopping; ++i) {
        if (n.flight.ticket) break;
        const uint8_t *data = nullptr;
        size_t bytes = 0;
        uint8_t control[20];
        int selected = next_output(n, data, bytes, control);
        if (selected == EWOULDBLOCK || selected == EBUSY) break;
        if (selected) { status = selected; break; }
        Flight flight = n.flight;
        uint32_t type = flight.kind == Flight::Data ? 1 : 6;
        uint32_t to = flight.destination;
        n.submitting = true;
        IOLockUnlock(n.lock);
        int admitted = n.ops.submit(n.ops.cookie, type, flight.from, flight.node, to,
            data, bytes, flight.generation, flight.ticket);
        IOLockLock(n.lock);
        n.submitting = false;
        if (admitted < 0) admitted = EINVAL;
        if (n.flight.ticket == flight.ticket) {
            if (!admitted) n.flight.queued = true;
            else complete(n, flight.ticket, admitted);
        }
        IOLockWakeup(n.lock, &n.router, false);
        if (admitted) { status = admitted; break; }
        if (n.flight.ticket) break;
    }
    for (unsigned i = 0; i < Router::port_count + Router::queue_count && !n.stopping; ++i) {
        Router::Callback callback;
        if (n.router.begin_callback(callback) != Router::Ok) break;
        IOLockUnlock(n.lock); callback.invoke(); IOLockLock(n.lock);
        n.router.finish_callback(callback.ticket);
        IOLockWakeup(n.lock, &n.router, false);
    }
    n.polling = false;
    IOLockWakeup(n.lock, &n.router, false);
    IOLockUnlock(n.lock);
    return status;
}
int observe_peer(NabuQrtrNative &n, bool checked, uint64_t expected, const Router::Endpoint &peer, bool available)
{
    if (current_thread() != n.owner) return EPERM;
    if (n.stopping || (checked && (!expected || expected != generation(n)))) return ENETDOWN;
    if (peer.service != Router::wlfw_service || peer.version != Router::wlfw_version || peer.node == 1) return EINVAL;
    if (available) {
        if (n.instance_lost) return ENETDOWN;
        if (n.peer_seen && !n.observed.same(peer)) { lose(n, ENETDOWN); return ENETDOWN; }
        if (n.peer_seen && n.observed.same(peer) && !n.router.instance_live()) return 0;
        if (n.router.instance_live()) {
            int status = error(n.router.announce_at(n.router.epoch(), peer));
            if (status) return status;
        } else if (!n.bound || n.handoff_started) return ENOTCONN;
        n.observed = peer;
        n.peer_seen = true;
        return 0;
    }
    if (!n.peer_seen || !n.observed.same(peer)) return ENOTCONN;
    lose(n, ENETDOWN);
    return 0;
}
} // namespace

extern "C" bool nabu_ath10k_qrtr_prepare(void)
{
    if (state()) return true;
    IOLock *lock = IOLockAlloc();
    if (!lock) return false;
    void *memory = IOMalloc(sizeof(NabuQrtrNative));
    if (!memory) { IOLockFree(lock); return false; }
    auto *created = new (memory) NabuQrtrNative;
    created->lock = lock;
    NabuQrtrNative *expected = nullptr;
    if (!__atomic_compare_exchange_n(&native, &expected, created, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        created->~NabuQrtrNative(); IOFree(memory, sizeof(NabuQrtrNative)); IOLockFree(lock);
    }
    return true;
}
extern "C" const hakios_qrtr_ops *nabu_ath10k_qrtr_transport(void) { return &transport; }
extern "C" uint64_t nabu_ath10k_qrtr_generation(void)
{
    auto *n = state(); if (!n) return 0;
    IOLockLock(n->lock); uint64_t value = generation(*n); IOLockUnlock(n->lock); return value;
}
extern "C" int nabu_ath10k_qrtr_bind(const NabuWifiQrtrOps *ops, uint64_t expected)
{
    auto *n = state(); if (!n) return ENXIO;
    if (!ops || !ops->submit || !expected) return EINVAL;
    IOLockLock(n->lock);
    int status = 0;
    if (!free_ports(*n) || n->router.instance_live() || n->router.has_leases() || n->flight.ticket ||
        n->polling || n->submitting || n->transport_transition || n->shutting_down) status = EBUSY;
    else if (n->bound && expected <= n->control_generation) status = EINVAL;
    else {
        n->ops = *ops; n->bound = true; n->control_generation = expected;
        n->owner = current_thread(); n->stopping = false; n->peer_seen = false;
        n->handoff_started = false; n->handoff_mask = 0;
        n->instance_lost = false;
    }
    IOLockUnlock(n->lock); return status;
}
extern "C" int nabu_ath10k_qrtr_begin_handoff(void)
{
    auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock); int status = 0;
    if (current_thread() != n->owner) status = EPERM;
    else if (!n->bound || n->stopping || !n->peer_seen) status = ENOTCONN;
    else if (n->router.instance_live() || !free_ports(*n) || n->flight.ticket || n->polling) status = EBUSY;
    else n->handoff_started = true;
    IOLockUnlock(n->lock); return status;
}
extern "C" bool nabu_ath10k_qrtr_handoff_complete(void)
{
    auto *n = state(); if (!n) return false;
    IOLockLock(n->lock);
    bool done = n->bound && n->handoff_started && n->handoff_mask == 3 && !n->stopping && n->peer_seen;
    IOLockUnlock(n->lock); return done;
}
extern "C" bool nabu_ath10k_qrtr_start_instance(void)
{
    auto *n = state(); if (!n) return false;
    IOLockLock(n->lock);
    bool free = free_ports(*n) && !n->router.has_leases() && !n->flight.ticket &&
        !n->polling && !n->submitting && !n->transport_transition && !n->shutting_down;
    bool allowed = n->bound && (current_thread() == n->owner && n->handoff_started &&
        n->handoff_mask == 3 && n->peer_seen && !n->instance_lost);
    bool started = free && allowed && n->router.start_instance() == Router::Ok;
    if (started) {
        n->owner = current_thread(); n->stopping = true; n->transport_transition = true;
        n->instance_lost = false;
        n->router.announce(n->observed);
    }
    IOLockUnlock(n->lock);
    if (started) {
        hakios_qmi_set_transport(&transport);
        IOLockLock(n->lock); n->transport_installed = true; n->transport_transition = false;
        n->stopping = false; IOLockWakeup(n->lock, &n->router, false); IOLockUnlock(n->lock);
    }
    return started;
}
extern "C" int nabu_ath10k_qrtr_announce_instance(uint64_t expected, uint32_t service, uint32_t version,
    uint32_t instance, uint32_t node, uint32_t port)
{
    auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock); int status = observe_peer(*n, true, expected, {service, version, instance, node, port}, true);
    IOLockUnlock(n->lock); return status;
}
extern "C" int nabu_ath10k_qrtr_withdraw_instance(uint64_t expected, uint32_t service, uint32_t version,
    uint32_t instance, uint32_t node, uint32_t port)
{
    auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock); int status = observe_peer(*n, true, expected, {service, version, instance, node, port}, false);
    IOLockUnlock(n->lock); return status;
}
extern "C" int nabu_ath10k_qrtr_announce(uint32_t service, uint32_t version, uint32_t instance, uint32_t node, uint32_t port)
{
    auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock); int status = observe_peer(*n, false, 0, {service, version, instance, node, port}, true);
    IOLockUnlock(n->lock); return status;
}
extern "C" int nabu_ath10k_qrtr_withdraw(uint32_t service, uint32_t version, uint32_t instance, uint32_t node, uint32_t port)
{
    auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock); int status = observe_peer(*n, false, 0, {service, version, instance, node, port}, false);
    IOLockUnlock(n->lock); return status;
}
extern "C" int nabu_ath10k_qrtr_receive_instance(uint64_t expected, uint32_t local, uint32_t node,
    uint32_t port, const void *data, size_t bytes, bool *owned)
{
    if (!owned) return EINVAL;
    *owned = false; auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock); *owned = owns(*n, local);
    int status = ENXIO;
    if (*owned) {
        if (!expected || expected != generation(*n) || n->stopping) status = ENETDOWN;
        else if (current_thread() != n->owner) status = EPERM;
        else status = error(n->router.receive_at(n->router.epoch(), local, node, port, data, bytes));
    }
    IOLockUnlock(n->lock); return status;
}
extern "C" bool nabu_ath10k_qrtr_receive(uint32_t local, uint32_t node, uint32_t port, const void *data, size_t bytes)
{
    bool owned = false;
    nabu_ath10k_qrtr_receive_instance(nabu_ath10k_qrtr_generation(), local, node, port, data, bytes, &owned);
    return owned;
}
extern "C" int nabu_ath10k_qrtr_poll(NabuAth10kQrtrSend send, void *cookie)
{
    auto *n = state(); return n ? poll(*n, false, 0, send, cookie) : ENXIO;
}
extern "C" int nabu_ath10k_qrtr_poll_instance(uint64_t expected, NabuAth10kQrtrSend send, void *cookie)
{
    auto *n = state(); return n ? poll(*n, true, expected, send, cookie) : ENXIO;
}
extern "C" int nabu_ath10k_qrtr_poll_bound(void)
{
    auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock); bool bound = n->bound; IOLockUnlock(n->lock);
    return bound ? poll(*n, false, 0, nullptr, nullptr) : ENOTCONN;
}
extern "C" int nabu_qrtr_submitted(uint64_t ticket, int status)
{
    auto *n = state(); if (!n) return ENXIO;
    IOLockLock(n->lock);
    int result = current_thread() == n->owner ? complete(*n, ticket, status) : EPERM;
    IOLockUnlock(n->lock); return result;
}
extern "C" void nabu_qrtr_invalidate(uint64_t expected, int reason)
{
    auto *n = state(); if (!n) return;
    IOLockLock(n->lock); if (expected && expected == generation(*n)) lose(*n, reason); IOLockUnlock(n->lock);
}
extern "C" void nabu_ath10k_qrtr_invalidate_instance(uint64_t expected) { nabu_qrtr_invalidate(expected, ENETDOWN); }
extern "C" void nabu_ath10k_qrtr_invalidate(void) { nabu_qrtr_invalidate(nabu_ath10k_qrtr_generation(), ENETDOWN); }
extern "C" void nabu_ath10k_qrtr_shutdown(void)
{
    auto *n = state(); if (!n) return;
    IOLockLock(n->lock);
    if (n->shutting_down) {
        while (n->shutting_down) {
            if (current_thread() == n->owner && (n->polling || n->flight.ticket)) panic("Nabu QRTR: nested owner shutdown");
            IOLockSleep(n->lock, &n->router, THREAD_UNINT);
        }
        IOLockUnlock(n->lock);
        return;
    }
    n->shutting_down = true;
    wait_transition(*n); n->stopping = true; lose(*n, ENETDOWN);
    for (auto &port : n->ports) if (port.id && !port.retired) n->router.begin_close(port.id);
    bool installed = n->transport_installed;
    n->transport_transition = installed;
    IOLockUnlock(n->lock);
    if (installed) hakios_qmi_set_transport(nullptr);
    IOLockLock(n->lock); n->transport_installed = false; n->transport_transition = false;
    IOLockWakeup(n->lock, &n->router, false);
    while (n->router.has_leases() || n->flight.ticket || n->submitting || n->polling) {
        if (current_thread() == n->owner) panic("Nabu QRTR: shutdown inside owner lease");
        IOLockSleep(n->lock, &n->router, THREAD_UNINT);
    }
    clear_unposted_retired(*n);
    n->shutting_down = false;
    IOLockWakeup(n->lock, &n->router, false);
    IOLockUnlock(n->lock);
}
#endif

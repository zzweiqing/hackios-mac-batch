/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Runtime hooks derived from donor 56c7364f5c083583b07eea24dded38a9ee932e5f,
 * patches/nabu-wireless/NabuAth10kRuntime.cpp. nabu keeps its existing
 * Control/PAS/power/DMA owners and uses the actual ArmCpu interrupt adapter.
 */
#include "NabuWifiRuntime.h"
#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K
#if !defined(NABU_WIFI_RADIO) || !NABU_WIFI_RADIO
#error NABU_WIFI_ATH10K_requires_NABU_WIFI_RADIO
#endif
#include "NabuWifiDma.h"
#include "NabuWifiIrq.h"
#include "NabuWifiQrtrApi.h"
#include "NabuWifiService.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSData.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <mach/kmod.h>
#include <string.h>
extern "C" {
#include <sys/errno.h>
#include <sys/nabu_wifi_network.h>
extern kmod_info_t g_kernel_kmod_info;
void nabu_wifi_network_static_init();
int lx_os_thread(const char *, void (*)(void *), void *);
int nabu_ath10k_driver_prepare();
int nabu_ath10k_driver_start();
void nabu_ath10k_driver_stop();
void hakios_sta_sample_signal();
}

namespace {
using Control = nabu_wifi::Control;
Control *control;
IOLock *state_lock;
NabuWifiIrq *irqs;
NabuWifiDma::View arena;
IOMemoryMap *wlan_map, *msa_map;
uint8_t mac_address[6];
uint32_t firmware_live, failed;
uint32_t attached_vectors;
bool bound, prepared, worker_started, worker_stopped, stop_requested;
int start_result;
unsigned observation_ticks;

bool property(IORegistryEntry *chosen, const char *name, void *output, size_t bytes) {
    const OSData *data = OSDynamicCast(OSData, chosen->getProperty(name));
    if (!data || data->getLength() != bytes || !data->getBytesNoCopy()) return false;
    memcpy(output, data->getBytesNoCopy(), bytes);
    return true;
}
bool irqResources(NabuWifiIrqResources &resources) {
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (!chosen) return false;
    uint32_t routes[24];
    resources = {};
    bool valid = property(chosen, "nabu-wifi-source-fdt-sha256", resources.source_fdt_sha256, 32) &&
        property(chosen, "nabu-wifi-ce-irq-qualification-sha256", resources.qualification_sha256, 32) &&
        property(chosen, "nabu-wifi-ce-irq-routes", routes, sizeof(routes));
    chosen->release();
    if (!valid) return false;
    for (unsigned index = 0; index < 12; ++index) {
        if (routes[index * 2 + 1] != 1 && routes[index * 2 + 1] != 4) return false;
        resources.source_spec[index] = 414 + index;
        resources.intid[index] = routes[index * 2];
        resources.edge[index] = routes[index * 2 + 1] == 1;
    }
    resources.route_qualified = resources.trigger_qualified = true;
    return true;
}
IOMemoryMap *mapWindow(uint64_t physical, size_t bytes) {
    IODeviceMemory *memory = IODeviceMemory::withRange(physical, bytes);
    if (!memory) return nullptr;
    IOMemoryMap *mapping = memory->map(kIOMapAnywhere | kIOMapInhibitCache);
    memory->release();
    if (!mapping || !mapping->getVirtualAddress() || mapping->getLength() != bytes) {
        if (mapping) mapping->release();
        return nullptr;
    }
    return mapping;
}
int submit(void *, uint32_t type, uint32_t from, uint32_t node, uint32_t port,
           const void *data, size_t bytes, uint64_t generation, uint64_t ticket) {
    if (!control || generation > UINT32_MAX) return ENETDOWN;
    switch (control->queueExternal(type, from, node, port, data, bytes, uint32_t(generation), ticket)) {
    case Control::QueueResult::Queued: return 0;
    case Control::QueueResult::Busy: return EAGAIN;
    case Control::QueueResult::Invalid: return EINVAL;
    case Control::QueueResult::Unavailable: return ENETDOWN;
    }
    return EINVAL;
}
void announce(void *, uint32_t generation, uint32_t service, uint32_t instance,
              uint32_t node, uint32_t port, bool available) {
    int result = available ?
        nabu_ath10k_qrtr_announce_instance(generation, service, instance & 255, instance >> 8, node, port) :
        nabu_ath10k_qrtr_withdraw_instance(generation, service, instance & 255, instance >> 8, node, port);
    if (result && result != ENOENT)
        IOLog("NABU ATH10K QRTR announcement status=%d service=%u instance=%u\n", result, service, instance);
}
bool receive(void *, uint32_t generation, uint32_t node, uint32_t port,
             uint32_t local, const uint8_t *data, size_t bytes) {
    bool owned = false;
    const int result = nabu_ath10k_qrtr_receive_instance(generation, local, node, port, data, bytes, &owned);
    if (owned && result == ENOBUFS) return false;
    if (owned && result)
        IOLog("NABU ATH10K QRTR rejected ingress status=%d local=%u node=%u port=%u\n", result, local, node, port);
    return true;
}
void pump(void *, uint32_t) {
    const int result = nabu_ath10k_qrtr_poll_bound();
    if (result && result != EAGAIN && result != EWOULDBLOCK) {
        IOLog("NABU ATH10K QRTR owner pump status=%d\n", result);
        nabu_wlan_runtime_lost();
    }
}
void invalidated(void *, uint32_t generation, int reason) {
    nabu_qrtr_invalidate(generation, reason);
    nabu_wlan_runtime_lost();
}
void submitted(void *, uint64_t ticket, int status) {
    const int result = nabu_qrtr_submitted(ticket, status);
    if (result) {
        IOLog("NABU ATH10K QRTR submission receipt status=%d ticket=%llu\n", result,
              static_cast<unsigned long long>(ticket));
        nabu_wlan_runtime_lost();
    }
}
void driverWorker(void *) {
    int result = nabu_ath10k_driver_prepare();
    if (!result) result = nabu_ath10k_driver_start();
    IOLockLock(state_lock); start_result = result; IOLockUnlock(state_lock);
    IOLog("NABU ATH10K driver start status=%d station-offer-is-separate\n", result);
    if (result) nabu_wlan_runtime_lost();
    IOLockLock(state_lock);
    while (!stop_requested) IOLockSleep(state_lock, &stop_requested, THREAD_UNINT);
    IOLockUnlock(state_lock);
    nabu_ath10k_driver_stop();
    IOLockLock(state_lock); worker_stopped = true; IOLockUnlock(state_lock);
    IOLog("NABU ATH10K driver and IRQ teardown returned; owned DMA remains retained\n");
}
} // namespace

namespace NabuWifiRuntime {
bool configure(Control &owner) {
    if (control || !nabu_ath10k_qrtr_prepare()) return false;
    state_lock = IOLockAlloc();
    if (!state_lock) return false;
    control = &owner;
    return control->configureExternal({nullptr, announce, receive, pump, invalidated, submitted});
}
bool bind() {
    if (!control || bound || control->status().error != Control::Error::None) return false;
    NabuWifiQrtrOps ops{nullptr, submit};
    const int result = nabu_ath10k_qrtr_bind(&ops, control->status().generation);
    bound = result == 0;
    return bound;
}
bool beginHandoff() {
    if (!bound || prepared || __atomic_load_n(&failed, __ATOMIC_ACQUIRE)) return false;
    uint8_t pin[32];
    NabuWifiIrqResources resources;
    if (!nabu_wlan_service_mac_address(mac_address, pin) || !irqResources(resources) ||
        !NabuWifiDma::radioMemory(arena) || arena.bytes != NabuWifiDma::ArenaBytes ||
        arena.iova != NabuWifiDma::IovaBase || !arena.cpu) {
        IOLog("NABU ATH10K gate=unqualified-permanent-mac-ce-route-or-dma-view\n");
        return false;
    }
    if (nabu_wifi_network_register_classes(g_kernel_kmod_info.name, nabu_wifi_network_static_init) != kOSReturnSuccess ||
        !nabu_wifi_network_stack_start()) return false;
    const int irq_status = nabu_wifi_irq_create(&resources, &irqs);
    if (irq_status) {
        IOLog("NABU ATH10K CE adapter prepare status=%d\n", irq_status);
        return false;
    }
    wlan_map = mapWindow(0x18800000, 0x800000);
    msa_map = mapWindow(0x8bc00000, 0x180000);
    if (!wlan_map || !msa_map) return false;
    prepared = true;
    if (!control->beginNativeHandoff() || nabu_ath10k_qrtr_begin_handoff()) return false;
    IOLog("NABU ATH10K pending actual KNEL and DMON DEL_CLIENT submissions generation=%u\n", control->status().generation);
    return true;
}
bool poll() {
    if (__atomic_load_n(&failed, __ATOMIC_ACQUIRE)) return false;
    if (!prepared) return true;
    if (!worker_started && control->status().stage == Control::Stage::NativeReady) {
        if (!nabu_ath10k_qrtr_handoff_complete() || !nabu_ath10k_qrtr_start_instance()) return false;
        nabu_wlan_service_publish();
        __atomic_store_n(&firmware_live, 1, __ATOMIC_RELEASE);
        IOLockLock(state_lock); worker_started = true; IOLockUnlock(state_lock);
        const int result = lx_os_thread("nabu-ath10k", driverWorker, nullptr);
        if (result) {
            IOLockLock(state_lock); worker_stopped = true; start_result = result; IOLockUnlock(state_lock);
            nabu_wlan_runtime_lost();
            return false;
        }
        IOLog("NABU ATH10K FW_READY handed off generation=%u withdrawn-clients=%u\n",
              control->status().generation, control->status().withdrawn_clients);
    }
    if (worker_started && ++observation_ticks % 1000 == 0) hakios_sta_sample_signal();
    return !__atomic_load_n(&failed, __ATOMIC_ACQUIRE);
}
bool healthy() { return !__atomic_load_n(&failed, __ATOMIC_ACQUIRE); }
void summary() {
    nabu_wlan_service_summary();
    if (!state_lock) return;
    IOLockLock(state_lock);
    IOLog("NABU ATH10K summary prepared=%u started=%u stopped=%u live=%u failed=%u start-status=%d\n",
          prepared, worker_started, worker_stopped, __atomic_load_n(&firmware_live, __ATOMIC_ACQUIRE),
          __atomic_load_n(&failed, __ATOMIC_ACQUIRE), start_result);
    IOLockUnlock(state_lock);
}
} // namespace NabuWifiRuntime

extern "C" void nabu_wlan_runtime_lost() {
    __atomic_store_n(&firmware_live, 0, __ATOMIC_RELEASE);
    if (__atomic_exchange_n(&failed, 1, __ATOMIC_ACQ_REL)) return;
    nabu_ath10k_qrtr_invalidate();
    nabu_wlan_service_invalidate(ENXIO);
    if (!state_lock) return;
    IOLockLock(state_lock);
    stop_requested = true;
    IOLockWakeup(state_lock, &stop_requested, false);
    IOLockUnlock(state_lock);
}
extern "C" void *nabu_ath10k_os_radio_memory(unsigned long bytes, unsigned long long *address) {
    if (!prepared || !address || bytes != arena.bytes || !arena.cpu ||
        __atomic_load_n(&failed, __ATOMIC_ACQUIRE)) return nullptr;
    *address = arena.iova;
    return arena.cpu;
}
extern "C" void *nabu_ath10k_os_map_registers(unsigned long long physical, unsigned long bytes) {
    if (!prepared || __atomic_load_n(&failed, __ATOMIC_ACQUIRE)) return nullptr;
    if (physical == 0x18800000 && bytes == 0x800000 && wlan_map)
        return reinterpret_cast<void *>(wlan_map->getVirtualAddress());
    if (physical == 0x8bc00000 && bytes == 0x180000 && msa_map)
        return reinterpret_cast<void *>(msa_map->getVirtualAddress());
    IOLog("NABU ATH10K rejected MMIO physical=%llx bytes=%lu\n", physical, bytes);
    return nullptr;
}
extern "C" void nabu_ath10k_os_print(const char *text) { if (text) IOLog("NABU ATH10K %s", text); }
extern "C" void nabu_ath10k_os_tell(const char *text) { if (text) IOLog("NABU ATH10K %s", text); }
extern "C" unsigned nabu_ath10k_os_option(const char *name) {
    return name && (!strcmp(name, "wifi_keep") || !strcmp(name, "wifi_irq"));
}
extern "C" int nabu_ath10k_os_radio_powered() {
    return __atomic_load_n(&firmware_live, __ATOMIC_ACQUIRE) && !__atomic_load_n(&failed, __ATOMIC_ACQUIRE);
}
extern "C" int nabu_ath10k_os_rproc_boot() { return nabu_ath10k_os_radio_powered() ? 0 : ENXIO; }
extern "C" int nabu_ath10k_os_radio_address(unsigned char *address) {
    if (!prepared || !address) return 0;
    memcpy(address, mac_address, 6);
    return 1;
}
extern "C" int nabu_ath10k_os_firmware(const char *name, const void **data, unsigned long *bytes) {
    /* Public WCN399x interface descriptor. Executable firmware and BDF are
     * supplied by this tablet's verified immutable bundle through Control. */
    static const uint8_t metadata[] = {
        'Q','C','A','-','A','T','H','1','0','K',0,0,
        1,0,0,0,4,0,0,0,0xa4,0xe4,0xbe,0x5b,
        2,0,0,0,3,0,0,0,0x40,0,0x0c,0,
        5,0,0,0,4,0,0,0,4,0,0,0,
        6,0,0,0,4,0,0,0,3,0,0,0
    };
    if (!data || !bytes) return EINVAL;
    *data = nullptr; *bytes = 0;
    if (!name || strcmp(name, "ath10k/WCN3990/hw1.0/firmware-5.bin")) return ENOENT;
    *data = metadata; *bytes = sizeof(metadata);
    return 0;
}
extern "C" int nabu_ath10k_os_irq_attach(unsigned vector, void (*function)(void *), void *argument) {
    if (vector >= 12 || !function) return EINVAL;
    if (!prepared || !irqs || __atomic_load_n(&failed, __ATOMIC_ACQUIRE)) return ENXIO;
    const int result = nabu_wifi_irq_attach(irqs, vector, function, argument);
    if (result) {
        IOLog("NABU ATH10K IRQ attach vector=%u status=%d\n", vector, result);
        return EIO;
    }
    __atomic_fetch_or(&attached_vectors, 1u << vector, __ATOMIC_RELEASE);
    return 0;
}
extern "C" void nabu_ath10k_os_irq_enable(unsigned vector) {
    if (!irqs) return;
    if (__atomic_load_n(&failed, __ATOMIC_ACQUIRE)) {
        const int status = nabu_wifi_irq_mask(irqs, vector, 10000);
        if (status) panic("NABU ATH10K IRQ retirement mask failed: %d", status);
        return;
    }
    const int result = nabu_wifi_irq_unmask(irqs, vector, 10000);
    if (result) nabu_wlan_runtime_lost();
}
extern "C" void nabu_ath10k_os_irq_disable(unsigned vector) {
    if (!irqs) return;
    const int result = nabu_wifi_irq_mask(irqs, vector, 10000);
    if (result) panic("NABU ATH10K IRQ mask failed before backend release: %d", result);
}
extern "C" void nabu_ath10k_os_irq_detach_all() {
    if (!irqs) return;
    const uint32_t attached = __atomic_load_n(&attached_vectors, __ATOMIC_ACQUIRE);
    for (unsigned vector = 0; vector < 12; ++vector) {
        if (!(attached & (1u << vector))) continue;
        const int status = nabu_wifi_irq_detach(irqs, vector, 10000);
        if (status) panic("NABU ATH10K IRQ detach failed before backend release: %d", status);
        __atomic_fetch_and(&attached_vectors, ~(1u << vector), __ATOMIC_RELEASE);
    }
    const int result = nabu_wifi_irq_destroy(irqs, 10000);
    if (result) panic("NABU ATH10K IRQ drain failed before backend release: %d", result);
    irqs = nullptr;
}
#endif

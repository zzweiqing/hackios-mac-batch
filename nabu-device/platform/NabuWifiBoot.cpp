/* SPDX-License-Identifier: MIT */
#include "NabuWifiFirmware.h"
#include "NabuWifiControl.h"
#include "NabuWifiMpss.h"
#include "NabuWifiPower.h"
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <mach/mach_time.h>
#include <pexpert/pexpert.h>
#include <string.h>

namespace {
uint32_t started;
nabu_wifi::Control *control;
NabuWifiMpss::Mpss modem;
IOMemoryMap *maps[3];
uint8_t *seed_arena;
size_t seed_bytes;

uint64_t nowMs(void *) {
    uint64_t nanoseconds = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nanoseconds);
    return nanoseconds / 1000000;
}
void waitMs(void *, unsigned milliseconds) {
    uint64_t deadline;
    clock_interval_to_deadline(milliseconds, kMillisecondScale, &deadline);
    do { thread_yield_internal(1); } while (mach_absolute_time() < deadline);
}
bool getFile(void *, const char *path, const uint8_t **data, size_t *bytes) {
    return nabu_wifi_firmware_file(path, data, bytes);
}
int modemFile(void *ctx, const char *path, const uint8_t **data, size_t *bytes) {
    return getFile(ctx, path, data, bytes) ? 0 : int(kIOReturnNotFound);
}
void logControl(void *, const nabu_wifi::Control::Event *event) {
    IOLog("NABU WIFI control stage=%s error=%s generation=%u operation=%s a=%llu b=%llu status=%d\n",
          nabu_wifi::Control::stageName(event->stage), nabu_wifi::Control::errorName(event->error),
          event->generation, event->operation, (unsigned long long)event->a,
          (unsigned long long)event->b, event->status);
}
int assignMsa(void *, uint64_t address, uint32_t bytes, bool secure) {
    const NabuWifiMpss::Result result = NabuWifiMpss::nativeAssignMsaRegion(address, bytes, secure);
    if (result.msaAssigned) return 0;
    return result.error == NabuWifiMpss::Error::None ? -1 : int(result.error) << 16 | (result.status & 0xffff);
}
int prepareSmp2p(void *, const NabuWifiMpss::Region *region, NabuWifiMpss::Smp2pObservation *out) {
    if (!control || region->physical != NabuWifiMpss::SmemBase || region->bytes != NabuWifiMpss::SmemBytes)
        return int(kIOReturnBadArgument);
    nabu_wifi::Control::Smp2pObservation observation{};
    if (!control->pollSmp2p(observation)) return int(kIOReturnNotReady);
    *out = {observation.negotiated, observation.entryPresent, observation.fresh, observation.state};
    return 0;
}
int pollSmp2p(void *ctx, NabuWifiMpss::Smp2pObservation *out) {
    const NabuWifiMpss::Region region{nullptr, nullptr, NabuWifiMpss::SmemBase, NabuWifiMpss::SmemBytes};
    return prepareSmp2p(ctx, &region, out);
}
bool mapControl(nabu_wifi::Smem::Mapping *out) {
    static const uint64_t physical[] = {0x86000000, 0x17c00000, 0x1f43000};
    static const size_t extent[] = {0x200000, 4096, 4096};
    for (unsigned i = 0; i < 3; ++i) {
        IODeviceMemory *memory = IODeviceMemory::withRange(physical[i], extent[i]);
        if (!memory) return false;
        maps[i] = memory->map(kIOMapAnywhere | kIOMapInhibitCache);
        memory->release();
        if (!maps[i] || !maps[i]->getVirtualAddress() || maps[i]->getLength() != extent[i]) return false;
    }
    *out = {reinterpret_cast<volatile uint8_t *>(maps[0]->getVirtualAddress()),
            reinterpret_cast<volatile uint8_t *>(maps[1]->getVirtualAddress() + 12),
            reinterpret_cast<volatile uint8_t *>(maps[2]->getVirtualAddress()),
            0x86000000, 0x17c0000c, 0x1f43000, 0x200000};
    return true;
}
bool allocateSeeds() {
    static const char *names[] = {"modemst1", "modemst2", "fsg", "fsc"};
    for (const char *name : names) {
        char path[48];
        snprintf(path, sizeof(path), "rmtfs-seed/%s.img", name);
        const uint8_t *data;
        size_t bytes;
        if (!nabu_wifi_firmware_file(path, &data, &bytes) || !bytes || bytes % 512 ||
            bytes > 128 * 1024 * 1024 - seed_bytes) return false;
        seed_bytes += bytes;
    }
    seed_arena = static_cast<uint8_t *>(IOMalloc(seed_bytes));
    return seed_arena != nullptr;
}
void coldStart() {
    unsigned gpu = 0;
    PE_parse_boot_argn("nabu-gpu", &gpu, sizeof(gpu));
    if (gpu) { IOLog("NABU WIFI boot error gate=concurrent-gpu-power-owner\n"); return; }
    control = new nabu_wifi::Control();
    nabu_wifi::Control::Resources resources{};
    if (!control || !allocateSeeds() || !mapControl(&resources.smem)) {
        IOLog("NABU WIFI boot error gate=control-resource-allocation\n"); return;
    }
    NabuWifiMpss::Region shared{};
    const NabuWifiMpss::Result assignment = NabuWifiMpss::nativeRmtfsSharedRegion(&shared);
    if (!assignment.sharedAssigned) {
        IOLog("NABU WIFI boot error gate=rmtfs-sharing stage=%s error=%s status=%d\n",
              NabuWifiMpss::stageName(assignment.stage), NabuWifiMpss::errorName(assignment.error), assignment.status);
        return;
    }
    resources.log = logControl;
    resources.nowMs = nowMs;
    resources.waitMs = waitMs;
    resources.rmtfs_arena = seed_arena;
    resources.rmtfs_arena_bytes = seed_bytes;
    resources.shared = shared.data;
    resources.shared_phys = shared.physical;
    resources.shared_bytes = shared.bytes;
    resources.sync = NabuWifiMpss::nativeRmtfsSharedSync;
    resources.msa_phys = NabuWifiMpss::MsaBase;
    resources.msa_bytes = 0x100000;
    resources.assignMsa = assignMsa;
    const nabu_wifi::FileProvider provider{nullptr, getFile};
    if (!control->initialize(resources, provider)) return;
    const int power = NabuWifiPower::beginBeforeGpu();
    if (power) { IOLog("NABU WIFI boot error gate=power-owner status=%d\n", power); return; }
    NabuWifiMpss::Ops ops{};
    ops.getFile = modemFile;
    ops.vote = NabuWifiPower::vote;
    ops.enableXo = NabuWifiPower::enableXo;
    ops.setModemLoadState = NabuWifiPower::setModemLoadState;
    ops.prepareSmp2p = prepareSmp2p;
    ops.pollSmp2p = pollSmp2p;
    const NabuWifiMpss::Result result = modem.start(ops);
    if (!result.authenticated || !result.readyObserved || result.error != NabuWifiMpss::Error::None) return;
    if (!control->startAfterPas(nowMs(nullptr))) return;
    const nabu_wifi::Control::Status status = control->run();
    if (status.stage != nabu_wifi::Control::Stage::Complete ||
        status.error != nabu_wifi::Control::Error::None || !status.capability.valid ||
        status.capability_generation != status.generation) return;
    IOLog("NABU WIFI WLFW capability generation=%u node=%u port=%u chip_valid=%u chip_id=%u chip_family=%u board_valid=%u board_id=%u "
          "soc_valid=%u soc_id=%u firmware_valid=%u firmware_version=%u rmtfs=%llu pd=%llu tftp=%llu\n",
          status.generation, status.server_node, status.server_port, status.capability.chip_valid, status.capability.chip_id,
          status.capability.chip_family, status.capability.board_valid, status.capability.board_id, status.capability.soc_valid,
          status.capability.soc_id, status.capability.firmware_valid, status.capability.firmware_version,
          (unsigned long long)status.rmtfs_requests, (unsigned long long)status.pd_requests,
          (unsigned long long)status.tftp_requests);
    while (control->poll(nowMs(nullptr))) waitMs(nullptr, 1);
    const nabu_wifi::Control::Status stopped = control->status();
    IOLog("NABU WIFI services stopped stage=%s error=%s status=%d\n",
          nabu_wifi::Control::stageName(stopped.stage), nabu_wifi::Control::errorName(stopped.error), stopped.detail);
}
void worker(void *argument, wait_result_t) {
    const uintptr_t mode = reinterpret_cast<uintptr_t>(argument);
    thread_set_thread_name(current_thread(), "nabu-wifi-control");
    IOLog("NABU WIFI boot begin mode=%lu\n", static_cast<unsigned long>(mode));
    if (nabu_wifi_firmware_load() == 0) {
        if (mode == 2) coldStart();
        else IOLog("NABU WIFI boot input-only-complete\n");
    }
    thread_terminate(current_thread());
}
} // namespace

extern "C" void nabu_wifi_start() {
    unsigned mode = 0;
    if (!PE_parse_boot_argn("nabu-wifi", &mode, sizeof(mode)) || !mode) return;
    if (mode > 2) { IOLog("NABU WIFI boot error gate=mode\n"); return; }
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&started, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return;
    thread_t thread = THREAD_NULL;
    const kern_return_t result = kernel_thread_start(worker, reinterpret_cast<void *>(uintptr_t(mode)), &thread);
    if (result != KERN_SUCCESS) IOLog("NABU WIFI boot error gate=worker-create status=%d\n", result);
    else thread_deallocate(thread);
}

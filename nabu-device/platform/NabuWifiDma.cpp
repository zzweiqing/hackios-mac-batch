/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "NabuWifiDma.h"

#if defined(NABU_WIFI_RADIO) && NABU_WIFI_RADIO
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSData.h>
#include <mach/vm_param.h>
extern "C" uint64_t gPhysBase, gPhysSize;
extern "C" vm_offset_t ml_vtophys(vm_offset_t);
/* CI 43253223009 / build/armcpu/ArmCpu.cpp:902. Registration enables the
 * level source immediately and exposes group/enable/edge/priority/router. */
extern "C" IOReturn armcpu_spi_attach(uint32_t, bool, void (*)(void *), void *, uint32_t *, uint64_t *);
namespace NabuWifiDma {
namespace {
IOLock *sharedLock;
unsigned sharedLockHeld;
unsigned radioCallEntered;
Owner nativeOwner;
RadioGate radioGate;
NativeLease nativeLease;
FaultIrqs faultIrqs;
IOMemoryMap *smmuMapping;
volatile uint8_t *smmuRegisters;
struct RadioCall {
    bool entered;
    RadioCall() {
        unsigned expected = 0;
        entered = __atomic_compare_exchange_n(&radioCallEntered, &expected, 1, false,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    }
    ~RadioCall() {
        if (entered) __atomic_store_n(&radioCallEntered, 0, __ATOMIC_RELEASE);
    }
};

bool sourceBound()
{
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (!chosen) return false;
    const OSData *source = OSDynamicCast(OSData, chosen->getProperty("nabu-wifi-source-fdt-sha256"));
    bool valid = source && sourceDigestMatches(source->getBytesNoCopy(), source->getLength());
    chosen->release();
    return valid;
}

int read32(void *, size_t offset, uint32_t *out)
{
    if (!out || !smmuRegisters || (offset & 3) || offset > SmmuBytes - 4) return int(kIOReturnBadArgument);
    *out = *reinterpret_cast<volatile uint32_t *>(smmuRegisters + offset);
    return 0;
}
int read64(void *, size_t offset, uint64_t *out)
{
    if (!out || !smmuRegisters || (offset & 7) || offset > SmmuBytes - 8) return int(kIOReturnBadArgument);
    *out = *reinterpret_cast<volatile uint64_t *>(smmuRegisters + offset);
    return 0;
}
int write32(void *, size_t offset, uint32_t value)
{
    if (!smmuRegisters || (offset & 3) || offset > SmmuBytes - 4) return int(kIOReturnBadArgument);
    *reinterpret_cast<volatile uint32_t *>(smmuRegisters + offset) = value;
    return 0;
}
int write64(void *, size_t offset, uint64_t value)
{
    if (!smmuRegisters || (offset & 7) || offset > SmmuBytes - 8) return int(kIOReturnBadArgument);
    *reinterpret_cast<volatile uint64_t *>(smmuRegisters + offset) = value;
    return 0;
}
int barrier(void *)
{
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}
ArmSmmu4KIo registerIo()
{
    return {nullptr, SmmuBytes, read32, read64, write32, write64, barrier};
}

int mapSmmu()
{
    if (smmuMapping) return smmuRegisters ? 0 : int(kIOReturnNotReady);
    IODeviceMemory *memory = IODeviceMemory::withRange(SmmuBase, SmmuBytes);
    if (!memory) return int(kIOReturnNoMemory);
    smmuMapping = memory->map(kIOMapAnywhere | kIOMapInhibitCache);
    memory->release();
    if (!smmuMapping) return int(kIOReturnNoMemory);
    if (!smmuMapping->getVirtualAddress() || smmuMapping->getLength() != SmmuBytes) return int(kIOReturnNoSpace);
    smmuRegisters = reinterpret_cast<volatile uint8_t *>(smmuMapping->getVirtualAddress());
    return 0;
}

int mastersStopped(void *)
{
    if (!radioGate.stopped() || !smmuMapping || !smmuRegisters) return int(kIOReturnNotReady);
    uint32_t id0 = 0;
    int status = read32(nullptr, 0x20, &id0);
    if (status) return status;
    return (id0 & (1u << 30)) ? 0 : int(kIOReturnUnsupported);
}
int claimLease(void *, const Lease *lease)
{
    if (!lease || !__atomic_load_n(&sharedLockHeld, __ATOMIC_ACQUIRE) || !radioGate.stopped()) return int(kIOReturnNotReady);
    return nativeLease.claim(registerIo(), *lease);
}
int attachIrq(void *, uint32_t id, bool edge, void (*handler)(void *), void *cookie,
    uint32_t *readback, uint64_t *router)
{
    return int(armcpu_spi_attach(id, edge, handler, cookie, readback, router));
}
int installFaults(void *, const Lease *lease, const ArmSmmu4KIo *)
{
    if (!lease || !nativeLease.held || !radioGate.stopped()) return int(kIOReturnNotReady);
    int status = faultIrqs.install({nullptr, attachIrq}, registerIo(), *lease);
    IOLog("NABU WIFI DMA fault IRQ bank=%u global=%u context=%u status=%d readback=%08x/%08x router=%llx/%llx\n",
        lease->bank, GlobalFaultIrq.spi + 32, ContextFaultIrqs[lease->bank].spi + 32, status,
        faultIrqs.globalReadback, faultIrqs.contextReadback,
        static_cast<unsigned long long>(faultIrqs.globalRouter), static_cast<unsigned long long>(faultIrqs.contextRouter));
    if (!status && __atomic_load_n(&faultIrqs.contextHandler.faulted, __ATOMIC_ACQUIRE)) return ArmSmmu4KFault;
    return status;
}
int nativeWindow(void *, uint64_t *base, uint64_t *bytes)
{
    *base = gPhysBase;
    *bytes = gPhysSize;
    return 0;
}
int nativeAllocate(void *, size_t bytes, Memory *out)
{
    if (!out || (bytes != ArenaBytes && bytes != TableBytes)) return int(kIOReturnBadArgument);
    *out = {};
    /* nullptr avoids IOMallocContiguous's legacy 32-bit PA-output constraint.
     * ml_vtophys checks every real 4 KiB span of the owned WB allocation. */
    void *cpu = IOMallocContiguous(bytes, AllocationAlignment, nullptr);
    if (!cpu) return int(kIOReturnNoMemory);
    uint64_t physical = ml_vtophys(reinterpret_cast<vm_offset_t>(cpu));
    Memory memory{cpu, physical, bytes};
    bool valid = detail::contiguousMemory(memory, gPhysBase, gPhysSize,
        [](uintptr_t address) { return ml_vtophys(vm_offset_t(address)); });
    if (!valid) {
        IOFreeContiguous(cpu, bytes);
        return int(kIOReturnUnsupported);
    }
    *out = memory;
    return 0;
}
void nativeRelease(void *, Memory *memory)
{
    IOFreeContiguous(memory->cpu, memory->bytes);
    *memory = {};
}
int nativePublish(void *, const Memory *memory, size_t offset, size_t bytes)
{
    if (!memory || !memory->cpu || !bytes || offset > memory->bytes || bytes > memory->bytes - offset) {
        return int(kIOReturnBadArgument);
    }
    uintptr_t start = reinterpret_cast<uintptr_t>(memory->cpu) + offset;
    uintptr_t end = start + bytes;
    for (uintptr_t at = start & ~uintptr_t(63); at < end; at += 64) {
        __asm__ volatile("dc civac, %0" :: "r"(at) : "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}
} // namespace
const Platform &nativePlatform()
{
    static const Platform platform{nullptr, nativeWindow, nativeAllocate, nativeRelease, nativePublish};
    return platform;
}
Owner *radioOwner() { return &nativeOwner; }
int prepareRadio()
{
    RadioCall call;
    if (!call.entered) return int(kIOReturnBusy);
    if (!sourceBound()) return int(kIOReturnNotFound);
    int mapped = mapSmmu();
    if (mapped) return mapped;
    if (nativeOwner.prepare(nativePlatform())) return 0;
    int status = nativeOwner.result().status;
    return status ? status : RadioUnavailable;
}

int activateRadioAfterPasStop()
{
    RadioCall call;
    if (!call.entered) return int(kIOReturnBusy);
    if (!sourceBound()) return int(kIOReturnNotFound);
    int mapped = mapSmmu();
    if (mapped) return mapped;
    Activation activation{nullptr, SmmuBase, registerIo(),
        [](void *) { return nabu_wifi_smmu_lock(); },
        [](void *) { nabu_wifi_smmu_unlock(); }, claimLease, mastersStopped, installFaults};
    int status = activateAfterPasStop(nativeOwner, nativePlatform(), activation, radioGate);
    if (!status) {
        if (__atomic_load_n(&faultIrqs.contextHandler.faulted, __ATOMIC_ACQUIRE)) {
            nativeOwner.retainFault();
            return ArmSmmu4KFault;
        }
        return 0;
    }
    return status;
}

void radioAuthAttempted()
{
    radioGate.authAttempted();
}

bool observeRadio()
{
    RadioCall call;
    if (!call.entered) return false;
    if (__atomic_load_n(&faultIrqs.contextHandler.faulted, __ATOMIC_ACQUIRE)) {
        FaultRecord fault;
        if (faultIrqs.context.read(fault)) {
            IOLog("NABU WIFI DMA context fault sequence=%llu bank=%u status=%08x address=%llx "
                  "sid-field=%x syndrome=%08x/%08x/%08x ack=%08x io=%d dropped=%llu\n",
                  static_cast<unsigned long long>(fault.sequence), fault.bank, fault.status,
                  static_cast<unsigned long long>(fault.address), fault.sidField,
                  fault.syndrome0, fault.syndrome1, fault.syndrome2, fault.ackReadback,
                  fault.ioStatus, static_cast<unsigned long long>(fault.dropped));
        }
    }
    return observeAfterFault(nativeOwner, faultIrqs.contextHandler.faulted);
}

int lockShared()
{
    IOLock *lock = __atomic_load_n(&sharedLock, __ATOMIC_ACQUIRE);
    if (!lock) {
        IOLock *allocated = IOLockAlloc();
        if (!allocated) return int(kIOReturnNoMemory);
        IOLock *expected = nullptr;
        if (__atomic_compare_exchange_n(&sharedLock, &expected, allocated, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) lock = allocated;
        else { IOLockFree(allocated); lock = expected; }
    }
    IOLockLock(lock);
    __atomic_store_n(&sharedLockHeld, 1, __ATOMIC_RELEASE);
    return 0;
}
void unlockShared()
{
    __atomic_store_n(&sharedLockHeld, 0, __ATOMIC_RELEASE);
    IOLockUnlock(__atomic_load_n(&sharedLock, __ATOMIC_ACQUIRE));
}
bool readGlobal(uint64_t *after, FaultRecord *out)
{
    if (!after || !out) return false;
    FaultRecord record;
    if (!faultIrqs.global.read(record) || record.sequence <= *after) return false;
    *out = record;
    *after = record.sequence;
    return true;
}
} // namespace NabuWifiDma

extern "C" int nabu_wifi_smmu_lock(void) { return NabuWifiDma::lockShared(); }
extern "C" void nabu_wifi_smmu_unlock(void) { NabuWifiDma::unlockShared(); }
extern "C" bool nabu_wifi_smmu_global_fault_read(uint64_t *after, NabuWifiDma::FaultRecord *out)
{
    return NabuWifiDma::readGlobal(after, out);
}

#else
namespace NabuWifiDma {
int prepareRadio() { return RadioUnavailable; }
int activateRadioAfterPasStop() { return RadioUnavailable; }
void radioAuthAttempted() {}
bool observeRadio() { return false; }
}
#endif

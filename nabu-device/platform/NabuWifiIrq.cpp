// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "NabuWifiIrq.h"
#ifndef NABU_WIFI_ATH10K
#define NABU_WIFI_ATH10K 0
#endif
#if NABU_WIFI_ATH10K != 0 && NABU_WIFI_ATH10K != 1
#error NABU_WIFI_ATH10K_must_be_zero_or_one
#endif

#if NABU_WIFI_ATH10K
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <mach/mach_time.h>
#include <machine/machine_routines.h>
#include <string.h>

struct NabuWifiIrq {
    struct Vector {
        NabuWifiIrq *owner;
        unsigned index;
        void (*function)(void *);
        void *context;
        uint32_t accepting, running;
        uint64_t generation, pending_generation, worker_generation, rearm_generation;
        bool attached, gic_attached;
    } vectors[12];
    NabuWifiIrqResources resources;
    IOLock *lock;
    thread_t worker_thread;
    uint32_t pending, stopping, stopped, retiring, active_vector;
};

namespace {
constexpr uint8_t SourceFdt[32] = {
    0x21,0xd4,0x35,0x5e,0xba,0x46,0xbc,0xd6,0x04,0x3d,0x3f,0x4b,0x92,0x05,0x0a,0x7b,
    0xba,0xc4,0xf9,0x47,0x62,0x07,0xc7,0xc5,0xaf,0xea,0x61,0x4e,0xc5,0x75,0x13,0xc9,
};
uint64_t nowMs()
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000000;
}
bool threadContext() { return !ml_at_interrupt_context() && ml_get_interrupts_enabled(); }
unsigned remainingMs(uint64_t deadline)
{
    const uint64_t now = nowMs();
    return now >= deadline ? 0 : static_cast<unsigned>(deadline - now);
}
bool validResources(const NabuWifiIrqResources *resources)
{
    if (!resources || !resources->route_qualified || !resources->trigger_qualified ||
        memcmp(resources->source_fdt_sha256, SourceFdt, 32) != 0) { return false; }
    uint8_t evidence = 0;
    for (unsigned i = 0; i < 32; i++) { evidence |= resources->qualification_sha256[i]; }
    if (!evidence) { return false; }
    for (unsigned i = 0; i < 12; i++) {
        if (resources->source_spec[i] != 414 + i || resources->intid[i] < 32 ||
            resources->intid[i] >= 1008) { return false; }
        for (unsigned j = 0; j < i; j++) {
            if (resources->intid[i] == resources->intid[j]) { return false; }
        }
    }
    return true;
}
bool lockUntil(NabuWifiIrq *irq, uint64_t deadline, unsigned budget)
{
    for (unsigned polls = 0; ; polls++) {
        if (IOLockTryLock(irq->lock)) { return true; }
        if (polls >= budget || nowMs() >= deadline) { return false; }
        IOSleep(1);
    }
}
bool drain(const uint32_t *running, uint64_t deadline, unsigned budget)
{
    for (unsigned polls = 0; ; polls++) {
        if (__atomic_load_n(running, __ATOMIC_ACQUIRE) == 0) { return true; }
        if (polls >= budget || nowMs() >= deadline) { return false; }
        IOSleep(1);
    }
}
void irqArrived(void *context)
{
    auto *vector = static_cast<NabuWifiIrq::Vector *>(context);
    const uint64_t generation = __atomic_load_n(&vector->generation, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&vector->accepting, __ATOMIC_ACQUIRE) == 0) { return; }
    __atomic_store_n(&vector->pending_generation, generation, __ATOMIC_RELEASE);
    __atomic_fetch_or(&vector->owner->pending, 1u << vector->index, __ATOMIC_RELEASE);
    thread_wakeup(reinterpret_cast<event_t>(&vector->owner->pending));
}
void worker(void *context, wait_result_t)
{
    auto *irq = static_cast<NabuWifiIrq *>(context);
    __atomic_store_n(&irq->worker_thread, current_thread(), __ATOMIC_RELEASE);
    for (;;) {
        // Register the wait before exchanging pending, then cancel it when
        // work/stop was already published. Both arrival races retain a wake.
        assert_wait(reinterpret_cast<event_t>(&irq->pending), THREAD_UNINT);
        const uint32_t pending = __atomic_exchange_n(&irq->pending, 0U, __ATOMIC_ACQUIRE);
        if (!pending && !__atomic_load_n(&irq->stopping, __ATOMIC_ACQUIRE)) {
            thread_block(THREAD_CONTINUE_NULL);
            continue;
        }
        clear_wait(current_thread(), THREAD_AWAKENED);
        if (__atomic_load_n(&irq->stopping, __ATOMIC_ACQUIRE)) { break; }
        for (unsigned i = 0; i < 12; i++) {
            if (!(pending & (1u << i))) { continue; }
            IOLockLock(irq->lock);
            auto &vector = irq->vectors[i];
            const uint64_t generation = __atomic_exchange_n(&vector.pending_generation, 0ULL, __ATOMIC_ACQUIRE);
            if (!generation || generation != __atomic_load_n(&vector.generation, __ATOMIC_ACQUIRE) ||
                !vector.attached || __atomic_load_n(&irq->retiring, __ATOMIC_ACQUIRE) ||
                !__atomic_load_n(&vector.accepting, __ATOMIC_ACQUIRE)) {
                IOLockUnlock(irq->lock);
                continue;
            }
            __atomic_store_n(&vector.running, 1U, __ATOMIC_RELEASE);
            vector.worker_generation = generation;
            __atomic_store_n(&vector.rearm_generation, generation, __ATOMIC_RELEASE);
            __atomic_store_n(&irq->active_vector, i + 1, __ATOMIC_RELEASE);
            auto function = vector.function;
            void *argument = vector.context;
            IOLockUnlock(irq->lock);
            function(argument);
            // Publish completion without the administrative lock so a caller
            // holding that lock can drain the worker with a bounded sleep.
            __atomic_store_n(&irq->active_vector, 0U, __ATOMIC_RELEASE);
            __atomic_store_n(&vector.running, 0U, __ATOMIC_RELEASE);
            IOLockLock(irq->lock);
            const uint64_t rearm = __atomic_load_n(&vector.rearm_generation, __ATOMIC_ACQUIRE);
            if (vector.attached && vector.gic_attached && rearm &&
                rearm == __atomic_load_n(&vector.generation, __ATOMIC_ACQUIRE) &&
                !__atomic_load_n(&irq->retiring, __ATOMIC_ACQUIRE) &&
                !__atomic_load_n(&irq->stopping, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&vector.accepting, 1U, __ATOMIC_RELEASE);
                const int32_t result = armcpu_spi_unmask(irq->resources.intid[i], irqArrived, &vector, 1000);
                if (result != kIOReturnSuccess) {
                    __atomic_store_n(&vector.accepting, 0U, __ATOMIC_RELEASE);
                    IOLog("NABU WIFI IRQ rearm vector=%u status=%#x\n", i, result);
                }
            }
            IOLockUnlock(irq->lock);
        }
    }
    __atomic_store_n(&irq->stopped, 1U, __ATOMIC_RELEASE);
    thread_terminate(current_thread());
}
int32_t change(NabuWifiIrq *irq, unsigned index, unsigned timeoutMs, unsigned operation)
{
    if (!irq || index >= 12 || timeoutMs > 10000) { return kIOReturnBadArgument; }
    if (!threadContext()) { return kIOReturnNotPermitted; }
    if (current_thread() == __atomic_load_n(&irq->worker_thread, __ATOMIC_ACQUIRE)) {
        if (operation == 2 || __atomic_load_n(&irq->active_vector, __ATOMIC_ACQUIRE) != index + 1) {
            return kIOReturnNotPermitted;
        }
        auto &vector = irq->vectors[index];
        if (__atomic_load_n(&irq->retiring, __ATOMIC_ACQUIRE)) { return kIOReturnNotReady; }
        if (operation == 0) {
            __atomic_store_n(&vector.accepting, 0U, __ATOMIC_RELEASE);
            __atomic_store_n(&vector.rearm_generation, 0ULL, __ATOMIC_RELEASE);
            uint64_t expected = vector.worker_generation;
            if (__atomic_compare_exchange_n(&vector.generation, &expected, expected + 1, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                vector.worker_generation++;
            }
            __atomic_store_n(&vector.pending_generation, 0ULL, __ATOMIC_RELEASE);
            __atomic_fetch_and(&irq->pending, ~(1u << index), __ATOMIC_ACQ_REL);
            return kIOReturnSuccess;
        }
        if (vector.worker_generation != __atomic_load_n(&vector.generation, __ATOMIC_ACQUIRE)) {
            return kIOReturnNotReady;
        }
        __atomic_store_n(&vector.rearm_generation, vector.worker_generation, __ATOMIC_RELEASE);
        return kIOReturnSuccess;
    }
    const uint64_t deadline = nowMs() + timeoutMs;
    if (!lockUntil(irq, deadline, timeoutMs)) { return kIOReturnTimeout; }
    auto &vector = irq->vectors[index];
    if (!vector.attached || __atomic_load_n(&irq->stopping, __ATOMIC_ACQUIRE)) {
        IOLockUnlock(irq->lock); return kIOReturnNotReady;
    }
    if (operation == 1 && __atomic_load_n(&irq->retiring, __ATOMIC_ACQUIRE)) {
        IOLockUnlock(irq->lock); return kIOReturnNotReady;
    }
    __atomic_store_n(&vector.accepting, 0U, __ATOMIC_RELEASE);
    __atomic_store_n(&vector.rearm_generation, 0ULL, __ATOMIC_RELEASE);
    __atomic_fetch_add(&vector.generation, 1ULL, __ATOMIC_ACQ_REL);
    int32_t result = kIOReturnSuccess;
    if (vector.gic_attached) {
        const unsigned remaining = remainingMs(deadline);
        result = operation == 2 ? armcpu_spi_detach(irq->resources.intid[index], irqArrived, &vector, remaining) :
                                 armcpu_spi_mask(irq->resources.intid[index], irqArrived, &vector, remaining);
        if (result == kIOReturnSuccess && operation == 2) { vector.gic_attached = false; }
    }
    if (result == kIOReturnSuccess) {
        // GIC callback drain precedes queue invalidation. A worker may already
        // hold this vector's bit in its local batch, so it also checks the
        // consumed generation ticket before admitting backend work.
        __atomic_store_n(&vector.pending_generation, 0ULL, __ATOMIC_RELEASE);
        __atomic_fetch_and(&irq->pending, ~(1u << index), __ATOMIC_ACQ_REL);
    }
    if (result == kIOReturnSuccess && !drain(&vector.running, deadline, timeoutMs)) { result = kIOReturnTimeout; }
    if (result == kIOReturnSuccess && operation == 1) {
        if (!vector.gic_attached) { result = kIOReturnNotReady; }
        else {
            __atomic_store_n(&vector.accepting, 1U, __ATOMIC_RELEASE);
            const unsigned remaining = remainingMs(deadline);
            result = armcpu_spi_unmask(irq->resources.intid[index], irqArrived, &vector, remaining);
            if (result != kIOReturnSuccess) { __atomic_store_n(&vector.accepting, 0U, __ATOMIC_RELEASE); }
        }
    } else if (result == kIOReturnSuccess && operation == 2) {
        vector.attached = false;
        vector.function = nullptr;
        vector.context = nullptr;
    }
    IOLockUnlock(irq->lock);
    return result;
}
} // namespace

int32_t nabu_wifi_irq_create(const NabuWifiIrqResources *resources, NabuWifiIrq **out)
{
    if (!out) { return kIOReturnBadArgument; }
    *out = nullptr;
    if (!threadContext()) { return kIOReturnNotPermitted; }
    if (!validResources(resources)) { return kIOReturnNotPermitted; }
    auto *irq = static_cast<NabuWifiIrq *>(IOMalloc(sizeof(NabuWifiIrq)));
    if (!irq) { return kIOReturnNoMemory; }
    memset(irq, 0, sizeof(*irq));
    irq->resources = *resources;
    irq->lock = IOLockAlloc();
    if (!irq->lock) { IOFree(irq, sizeof(*irq)); return kIOReturnNoMemory; }
    for (unsigned i = 0; i < 12; i++) { irq->vectors[i].owner = irq; irq->vectors[i].index = i; }
    thread_t thread;
    const kern_return_t result = kernel_thread_start(worker, irq, &thread);
    if (result != KERN_SUCCESS) {
        IOLockFree(irq->lock); IOFree(irq, sizeof(*irq)); return result;
    }
    thread_deallocate(thread);
    *out = irq;
    return kIOReturnSuccess;
}
int32_t nabu_wifi_irq_attach(NabuWifiIrq *irq, unsigned index, void (*function)(void *), void *context)
{
    if (!irq || index >= 12 || !function) { return kIOReturnBadArgument; }
    if (!threadContext()) { return kIOReturnNotPermitted; }
    if (current_thread() == __atomic_load_n(&irq->worker_thread, __ATOMIC_ACQUIRE)) { return kIOReturnNotPermitted; }
    if (!lockUntil(irq, nowMs() + 1000, 1000)) { return kIOReturnTimeout; }
    auto &vector = irq->vectors[index];
    if (vector.attached || __atomic_load_n(&irq->stopping, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&irq->retiring, __ATOMIC_ACQUIRE)) {
        IOLockUnlock(irq->lock); return kIOReturnExclusiveAccess;
    }
    uint32_t readback = 0;
    uint64_t route = 0;
    int32_t result = armcpu_spi_attach_deferred(irq->resources.intid[index], irq->resources.edge[index],
                                              irqArrived, &vector, &readback, &route);
    if (result == kIOReturnSuccess) {
        __atomic_fetch_add(&vector.generation, 1ULL, __ATOMIC_RELEASE);
        __atomic_store_n(&vector.pending_generation, 0ULL, __ATOMIC_RELEASE);
        vector.function = function;
        vector.context = context;
        vector.attached = vector.gic_attached = true;
        __atomic_store_n(&vector.accepting, 1U, __ATOMIC_RELEASE);
        result = armcpu_spi_unmask(irq->resources.intid[index], irqArrived, &vector, 1000);
        if (result != kIOReturnSuccess) { __atomic_store_n(&vector.accepting, 0U, __ATOMIC_RELEASE); }
    }
    IOLockUnlock(irq->lock);
    return result;
}
int32_t nabu_wifi_irq_mask(NabuWifiIrq *irq, unsigned vector, unsigned timeoutMs)
{ return change(irq, vector, timeoutMs, 0); }
int32_t nabu_wifi_irq_unmask(NabuWifiIrq *irq, unsigned vector, unsigned timeoutMs)
{ return change(irq, vector, timeoutMs, 1); }
int32_t nabu_wifi_irq_detach(NabuWifiIrq *irq, unsigned vector, unsigned timeoutMs)
{ return change(irq, vector, timeoutMs, 2); }
bool nabu_wifi_irq_quiesced(NabuWifiIrq *irq)
{
    if (!irq || !threadContext() || !IOLockTryLock(irq->lock)) { return false; }
    bool quiesced = __atomic_load_n(&irq->retiring, __ATOMIC_ACQUIRE) != 0;
    for (unsigned i = 0; i < 12; i++) {
        const auto &vector = irq->vectors[i];
        quiesced = quiesced && !vector.attached && !vector.gic_attached &&
            !__atomic_load_n(&vector.running, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&vector.accepting, __ATOMIC_ACQUIRE);
    }
    IOLockUnlock(irq->lock);
    return quiesced;
}
int32_t nabu_wifi_irq_quiesce_all(NabuWifiIrq *irq, unsigned timeoutMs)
{
    if (!irq || timeoutMs > 10000) { return kIOReturnBadArgument; }
    if (!threadContext() || current_thread() == __atomic_load_n(&irq->worker_thread, __ATOMIC_ACQUIRE)) {
        return kIOReturnNotPermitted;
    }
    const uint64_t deadline = nowMs() + timeoutMs;
    if (!lockUntil(irq, deadline, timeoutMs)) { return kIOReturnTimeout; }
    __atomic_store_n(&irq->retiring, 1U, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < 12; i++) {
        __atomic_store_n(&irq->vectors[i].accepting, 0U, __ATOMIC_RELEASE);
        __atomic_store_n(&irq->vectors[i].rearm_generation, 0ULL, __ATOMIC_RELEASE);
        __atomic_fetch_add(&irq->vectors[i].generation, 1ULL, __ATOMIC_ACQ_REL);
    }
    IOLockUnlock(irq->lock);
    for (unsigned i = 0; i < 12; i++) {
        const int32_t result = change(irq, i, remainingMs(deadline), 2);
        if (result != kIOReturnSuccess && result != kIOReturnNotReady) { return result; }
    }
    return nabu_wifi_irq_quiesced(irq) ? kIOReturnSuccess : kIOReturnTimeout;
}
int32_t nabu_wifi_irq_destroy(NabuWifiIrq *irq, unsigned timeoutMs)
{
    if (!irq || timeoutMs > 10000) { return kIOReturnBadArgument; }
    if (!threadContext()) { return kIOReturnNotPermitted; }
    if (current_thread() == __atomic_load_n(&irq->worker_thread, __ATOMIC_ACQUIRE)) { return kIOReturnNotPermitted; }
    const uint64_t deadline = nowMs() + timeoutMs;
    if (!lockUntil(irq, deadline, timeoutMs)) { return kIOReturnTimeout; }
    for (unsigned i = 0; i < 12; i++) {
        if (irq->vectors[i].attached) { IOLockUnlock(irq->lock); return kIOReturnBusy; }
    }
    __atomic_store_n(&irq->stopping, 1U, __ATOMIC_RELEASE);
    thread_wakeup(reinterpret_cast<event_t>(&irq->pending));
    IOLockUnlock(irq->lock);
    // stopped is the worker's final access to this handle.
    for (unsigned polls = 0; !__atomic_load_n(&irq->stopped, __ATOMIC_ACQUIRE); polls++) {
        if (polls >= timeoutMs || nowMs() >= deadline) { return kIOReturnTimeout; }
        IOSleep(1);
    }
    IOLockFree(irq->lock);
    IOFree(irq, sizeof(*irq));
    return kIOReturnSuccess;
}
#else
// kIOReturnUnsupported, available without introducing IOKit imports.
constexpr int32_t Unsupported = static_cast<int32_t>(0xe00002c7u);
int32_t nabu_wifi_irq_create(const NabuWifiIrqResources *, NabuWifiIrq **out)
{ if (out) { *out = nullptr; } return Unsupported; }
int32_t nabu_wifi_irq_attach(NabuWifiIrq *, unsigned, void (*)(void *), void *) { return Unsupported; }
int32_t nabu_wifi_irq_mask(NabuWifiIrq *, unsigned, unsigned) { return Unsupported; }
int32_t nabu_wifi_irq_unmask(NabuWifiIrq *, unsigned, unsigned) { return Unsupported; }
int32_t nabu_wifi_irq_detach(NabuWifiIrq *, unsigned, unsigned) { return Unsupported; }
int32_t nabu_wifi_irq_quiesce_all(NabuWifiIrq *, unsigned) { return Unsupported; }
bool nabu_wifi_irq_quiesced(NabuWifiIrq *) { return false; }
int32_t nabu_wifi_irq_destroy(NabuWifiIrq *, unsigned) { return Unsupported; }
#endif

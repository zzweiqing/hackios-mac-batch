// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>

struct NabuWifiIrq;

// The caller supplies the independently qualified PDC -> GIC route and
// trigger evidence. No INTID or trigger is inferred from FDT flags zero.
struct NabuWifiIrqResources {
    uint32_t source_spec[12];
    uint32_t intid[12];
    bool edge[12];
    bool route_qualified;
    bool trigger_qualified;
    uint8_t source_fdt_sha256[32];
    uint8_t qualification_sha256[32];
};

// All administrative APIs are thread-only. Timeout is 0..10000 ms.
// On failure, the handle and backend contexts remain owned until a successful
// detach/destroy. Administrative mask drains the backend worker. The active
// vector's own worker may mask without self-drain, or request rearm after its
// callback returns. Other worker administrative calls are rejected.
// destroy requires exclusive caller ownership against other API callers.
int32_t nabu_wifi_irq_create(const NabuWifiIrqResources *, NabuWifiIrq **);
int32_t nabu_wifi_irq_attach(NabuWifiIrq *, unsigned vector, void (*)(void *), void *);
int32_t nabu_wifi_irq_mask(NabuWifiIrq *, unsigned vector, unsigned timeout_ms);
int32_t nabu_wifi_irq_unmask(NabuWifiIrq *, unsigned vector, unsigned timeout_ms);
int32_t nabu_wifi_irq_detach(NabuWifiIrq *, unsigned vector, unsigned timeout_ms);
// Begin permanent retirement, cancel rearm, and detach all vectors. A failure
// retains the handle/contexts. managed_free and DMA release must require both
// checked success and quiesced()==true, queried while the handle is still held.
int32_t nabu_wifi_irq_quiesce_all(NabuWifiIrq *, unsigned timeout_ms);
bool nabu_wifi_irq_quiesced(NabuWifiIrq *);
int32_t nabu_wifi_irq_destroy(NabuWifiIrq *, unsigned timeout_ms);

// The legacy six-argument attach retains immediate enable and real readback.
// Deferred attach starts masked and masks each delivery in the GIC ISR before
// invoking its callback. A thread explicitly rearms it after backend work.
extern "C" {
int32_t armcpu_spi_attach_deferred(uint32_t, bool, void (*)(void *), void *, uint32_t *, uint64_t *);
int32_t armcpu_spi_mask(uint32_t, void (*)(void *), void *, unsigned);
int32_t armcpu_spi_unmask(uint32_t, void (*)(void *), void *, unsigned);
int32_t armcpu_spi_detach(uint32_t, void (*)(void *), void *, unsigned);
}

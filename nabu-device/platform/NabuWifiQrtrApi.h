/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Adapted from donor 56c7364 NabuAth10kQrtr.api.h. */
#ifndef NABU_WIFI_QRTR_API_H
#define NABU_WIFI_QRTR_API_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct hakios_qrtr_ops;
/* Retained callback ABI. Native poll requires bound Ops and uses submit with
 * explicit tickets. The legacy callback cannot complete a queued lease. */
typedef bool (*NabuAth10kQrtrSend)(void *, uint32_t type, uint32_t from,
    uint32_t node, uint32_t to, const void *, size_t);
struct NabuWifiQrtrOps {
    void *cookie;
    /* Sole owner, outside adapter lock. 0 means copied into Control's queue,
     * EAGAIN means no admission. A queued ticket MUST receive submitted(ticket,
     * status) after the actual last chunk, or terminal cancellation/removal.
     * Payload is borrowed only until this callback returns. */
    int (*submit)(void *, uint32_t type, uint32_t src, uint32_t node, uint32_t port,
        const void *, size_t bytes, uint64_t generation, uint64_t ticket);
};
bool nabu_ath10k_qrtr_prepare(void);
/* Bind on the Control owner after CLS_Router closure. Generation is the
 * actual Control generation. Runtime keeps this owner's cookie alive. */
int nabu_ath10k_qrtr_bind(const struct NabuWifiQrtrOps *, uint64_t generation);
int nabu_ath10k_qrtr_begin_handoff(void);
bool nabu_ath10k_qrtr_handoff_complete(void);
/* Requires bound Ops and actual submission of legacy DEL_CLIENT 0x12/0x14.
 * Real endpoint announcement may be cached before this starts the instance. */
bool nabu_ath10k_qrtr_start_instance(void);
const struct hakios_qrtr_ops *nabu_ath10k_qrtr_transport(void);
uint64_t nabu_ath10k_qrtr_generation(void);
/* Instance APIs use Control's bound generation. Remote node 0 is valid,
 * Apps node 1 is rejected. 0 means no first bound instance exists. */
int nabu_ath10k_qrtr_announce(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
int nabu_ath10k_qrtr_withdraw(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
int nabu_ath10k_qrtr_announce_instance(uint64_t generation,
    uint32_t service, uint32_t version, uint32_t instance, uint32_t node, uint32_t port);
int nabu_ath10k_qrtr_withdraw_instance(uint64_t generation,
    uint32_t service, uint32_t version, uint32_t instance, uint32_t node, uint32_t port);
/* Ownership query plus legacy receive attempt. true includes full queues,
 * closed/retired IDs and rejected source/generation. Coordinator ingress uses
 * receive_instance to observe backpressure and retain the original message. */
bool nabu_ath10k_qrtr_receive(uint32_t local, uint32_t node, uint32_t port, const void *, size_t);
/* Always sets owned. ENOBUFS means retain/retry in the coordinator ingress
 * queue. A rejected old/wrong-source packet stays owned and cannot fall through
 * to a previous service. 0 means the exact datagram has been copied here. */
int nabu_ath10k_qrtr_receive_instance(uint64_t generation,
    uint32_t local, uint32_t node, uint32_t port, const void *, size_t, bool *owned);
int nabu_ath10k_qrtr_poll(NabuAth10kQrtrSend, void *);
int nabu_ath10k_qrtr_poll_instance(uint64_t generation, NabuAth10kQrtrSend, void *);
/* Bound Ops always use the asynchronous ticket path, including legacy poll.
 * Pump after Control's existing RX/TX budgets. EAGAIN retains the message. */
int nabu_ath10k_qrtr_poll_bound(void);
/* Sole owner. status=0 confirms actual last-chunk submission. Positive status
 * is terminal removal from Control's queue, allowing retry/cancellation here.
 * Unknown/stale tickets return ENOENT and cannot finish another lease. */
int nabu_qrtr_submitted(uint64_t ticket, int status);
void nabu_ath10k_qrtr_invalidate(void);
void nabu_ath10k_qrtr_invalidate_instance(uint64_t generation);
void nabu_qrtr_invalidate(uint64_t generation, int reason);
/* Stop delivery and drain leases. QMI clients release their handles afterwards.
 * Live close waits for actual DEL_CLIENT submission too, so it runs on a
 * worker while the sole owner keeps polling/flushing. Shutdown with a queued
 * ticket requires completion/cancellation before a synchronous owner call. */
void nabu_ath10k_qrtr_shutdown(void);
/* All int results are 0 or positive errno. poll=0 means one bounded pump
 * completed, including any retained transport retry. Callbacks expose only
 * actual server observations and original payload bytes. */
#ifdef __cplusplus
}
#endif
#endif

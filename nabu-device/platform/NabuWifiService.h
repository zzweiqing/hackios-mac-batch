/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef NABU_WIFI_SERVICE_H
#define NABU_WIFI_SERVICE_H

#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K != 0 && NABU_WIFI_ATH10K != 1
#error NABU_WIFI_ATH10K_must_be_zero_or_one
#endif
#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K == 1
#if !defined(KERNEL)
#error NABU_WIFI_ATH10K_requires_kernel_native_headers
#endif
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <sys/hakios.sta.h>
#ifdef __cplusplus
}

namespace NabuWifiService {
constexpr size_t MacSourceBytes = 18;
constexpr unsigned QueueCapacity = 256;
struct MacIdentity {
    uint8_t address[6];
    uint8_t sourceSha256[32];
};
typedef void (*Digest)(const void *, size_t, uint8_t[32]);
/* Exact captured persist format: wlan0=<12 hex digits>. The caller pins the
 * original source SHA from its device-bound selection receipt. Output is
 * cleared on failure. Locally administered/multicast/zero addresses fail. */
bool selectMac(const uint8_t *, size_t, const uint8_t[32], Digest, MacIdentity *);
}

extern "C" {
#endif
void nabu_wlan_service_publish();
void nabu_wlan_service_summary();
void nabu_wlan_service_invalidate(int error);
/* Supplies the validated permanent address to the backend before radio init.
 * Requires the same source/pin and chosen/wlan properties as publication. */
bool nabu_wlan_service_mac_address(uint8_t[6], uint8_t[32]);
void nabu_ath10k_os_net_attach(const unsigned char *address);
void nabu_ath10k_os_net_input(const unsigned char *, unsigned long);
void nabu_ath10k_os_net_link(int up);
/* Offers/withdrawals are serialized driver-owner operations. Withdrawal
 * drains native calls, state readers, accepted TX and admitted RX. The owner
 * quiesces its own packet/link callbacks before replacing/freeing a backend. */
void nabu_ath10k_os_station(const struct hakios_sta_ops *);
void nabu_ath10k_os_station_lost(int error);
void nabu_ath10k_os_station_fatal(int error);
#ifdef __cplusplus
}
#endif
#endif
#endif

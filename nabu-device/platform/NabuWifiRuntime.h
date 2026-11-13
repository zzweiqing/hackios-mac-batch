/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef NABU_WIFI_RUNTIME_H
#define NABU_WIFI_RUNTIME_H
#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K != 0 && NABU_WIFI_ATH10K != 1
#error NABU_WIFI_ATH10K_must_be_zero_or_one
#endif
#if defined(NABU_WIFI_ATH10K) && NABU_WIFI_ATH10K
#include "NabuWifiControl.h"
namespace NabuWifiRuntime {
/* Configure before Control.initialize, then bind its actual generation.
 * Control remains the only GLINK executor throughout driver teardown. */
bool configure(nabu_wifi::Control &);
bool bind();
bool beginHandoff();
bool healthy();
bool poll();
void summary();
}
extern "C" void nabu_wlan_runtime_lost();
#endif
#endif

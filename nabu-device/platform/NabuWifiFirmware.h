/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_FIRMWARE_H
#define NABU_WIFI_FIRMWARE_H
#include <stddef.h>
#include <stdint.h>

extern "C" {
/* These functions run only on the Wi-Fi executor. The loaded allocation is
 * retained for the boot. Files are immutable to callers after verification. */
int nabu_wifi_firmware_load();
bool nabu_wifi_firmware_file(const char *, const uint8_t **, size_t *);
void nabu_wifi_start();
}
#endif

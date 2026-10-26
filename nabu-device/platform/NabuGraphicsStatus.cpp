// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded, opt-in snapshots of existing software state; no registry or MMIO reads.
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>

extern "C" {
extern volatile unsigned nabu_graphics_worker_stage;
extern volatile int native_mobile_graphics_load_status;
extern volatile uint32_t native_legacy_stage, native_legacy_surface_found;
extern volatile int native_legacy_meta_status, native_legacy_surface_status;
extern volatile uint32_t native_legacy_init_result, native_legacy_probe_match, native_legacy_start_result;
extern volatile int native_legacy_console_status;
extern volatile uint32_t native_legacy_console_width, native_legacy_console_height;
extern volatile uint32_t native_legacy_console_stride, native_legacy_console_rotation;
extern volatile uint32_t native_legacy_transfer_calls, native_legacy_frame_count;
extern volatile int native_legacy_transfer_status;

static void
nabu_graphics_status_worker(void *parameter, wait_result_t waitResult)
{
    (void)parameter;
    (void)waitResult;
    const unsigned delays[] = {2000, 3000, 5000, 10000, 10000, 30000};
    unsigned elapsed = 0;
    for (unsigned delay : delays) {
        IOSleep(delay);
        elapsed += delay;
        if (native_legacy_transfer_calls) break;
        IOLog("NABU DISPLAY t=%us worker=%u family=%d legacy=%u meta=%d\n",
            elapsed / 1000, nabu_graphics_worker_stage, native_mobile_graphics_load_status,
            native_legacy_stage, native_legacy_meta_status);
        IOLog("NABU DISPLAY console=%d %ux%u stride=%u rotate=%u init=%u\n",
            native_legacy_console_status, native_legacy_console_width, native_legacy_console_height,
            native_legacy_console_stride, native_legacy_console_rotation, native_legacy_init_result);
        IOLog("NABU DISPLAY surface=%d found=%u probe=%u start=%u frames=%u copy=%d\n",
            native_legacy_surface_status, native_legacy_surface_found, native_legacy_probe_match,
            native_legacy_start_result, native_legacy_frame_count, native_legacy_transfer_status);
    }
    thread_terminate(current_thread());
}

void
native_legacy_status_start(void)
{
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("nabu-display-status", &enabled, sizeof(enabled)) || enabled != 1) return;
    thread_t worker = THREAD_NULL;
    kern_return_t result = kernel_thread_start(nabu_graphics_status_worker, nullptr, &worker);
    if (result == KERN_SUCCESS) thread_deallocate(worker);
    else IOLog("NABU DISPLAY status worker creation failed=%d\n", result);
}
}

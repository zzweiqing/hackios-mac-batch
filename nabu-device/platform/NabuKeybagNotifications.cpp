// SPDX-License-Identifier: BSD-2-Clause-Patent
// Ephemeral notification transport only. No keys, lock state or user-client operations.
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <libkern/c++/OSSymbol.h>
#include <pexpert/pexpert.h>
#include <mach/kmod.h>

#if !defined(NABU_LEGACY_CPU_PRESENT)
#error Keybag notifications are limited to the explicit QEMU RAM-Data CPU profile
#endif

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern volatile uint32_t native_owner_data_stage;
extern volatile int native_owner_data_status;
extern volatile uint64_t native_ram_block_bytes;
volatile uint32_t nabu_keybag_notification_stage;
volatile int nabu_keybag_notification_status = kIOReturnNotReady;
volatile uint32_t nabu_keybag_notification_subscriptions, nabu_keybag_notification_failures;
volatile uint32_t nabu_keybag_notification_refused_opens;
volatile uint64_t nabu_keybag_notification_service;
void nabu_keybag_notifications_static_init(void) __asm__("__GLOBAL__sub_I_NabuKeybagNotifications.cpp");
}

// The matching class is the consumer's event ABI. The distinct service name and
// properties identify an owned RAM-only transport, not Apple security hardware.
class AppleKeyStore final : public IOService {
    OSDeclareDefaultStructors(AppleKeyStore)
public:
    bool start(IOService *provider) override {
        if (!IOService::start(provider)) return false;
        setName("Nabu ephemeral keybag notifications");
        if (!setProperty("NabuEphemeralNotificationTransport", true) ||
            !setProperty("HardwareKeyStore", false) || !setProperty("KeyOperationsAvailable", false) ||
            !setProperty("StateQueriesAvailable", false)) {
            IOService::stop(provider);
            return false;
        }
        registerService();
        return true;
    }
    OSPtr<IONotifier> registerInterest(const OSSymbol *kind, IOServiceInterestHandler handler,
                                     void *target, void *ref = nullptr) override {
        auto notifier = IOService::registerInterest(kind, handler, target, ref);
        if (notifier) ++nabu_keybag_notification_subscriptions;
        else ++nabu_keybag_notification_failures;
        return notifier;
    }
    IOReturn newUserClient(task_t, void *, UInt32, OSDictionary *, IOUserClient **client) override {
        if (client) *client = nullptr;
        ++nabu_keybag_notification_refused_opens;
        return kIOReturnNotReady;
    }
    IOReturn newUserClient(task_t task, void *security, UInt32 type, IOUserClient **client) override {
        return newUserClient(task, security, type, nullptr, client);
    }
};
OSDefineMetaClassAndStructors(AppleKeyStore, IOService)

extern "C" void nabu_keybag_notifications_start(void) {
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("nabu-keybag-notifications", &enabled, sizeof(enabled)) ||
        enabled != 1 || nabu_keybag_notification_stage) return;
    nabu_keybag_notification_stage = 1;
    if (native_owner_data_stage != 4 || native_owner_data_status || !native_ram_block_bytes) return;
    const OSSymbol *name = OSSymbol::withCString("AppleKeyStore");
    bool absent = name && !OSMetaClass::getMetaClassWithName(name);
    OSSafeReleaseNULL(name);
    if (!absent) {
        nabu_keybag_notification_status = kIOReturnExclusiveAccess;
        return;
    }
    IOService *provider = IOService::getResourceService();
    if (!provider) return;
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return;
    nabu_keybag_notifications_static_init();
    nabu_keybag_notification_status = OSMetaClass::postModLoad(handle);
    if (nabu_keybag_notification_status) return;
    nabu_keybag_notification_stage = 2;
    IOService *service = new AppleKeyStore;
    bool attached = service && service->init() && service->attach(provider);
    if (!attached || !service->start(provider)) {
        if (attached) service->detach(provider);
        OSSafeReleaseNULL(service);
        nabu_keybag_notification_status = kIOReturnError;
        return;
    }
    nabu_keybag_notification_service = (uintptr_t)service;
    nabu_keybag_notification_status = kIOReturnSuccess;
    nabu_keybag_notification_stage = 3;
}

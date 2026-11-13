"""Bind the board timer and preserve multi-instruction assembly on Darwin ARM64.

Pinned against upstream UniXNU/ArmCpu commit 93a5030c5d983d0ef90f0fca93879d6e36ad1ba8.
The 14 unique multi-instruction asm templates (17 source sites) below match that
commit exactly. On Darwin AArch64 ';' is a comment, so the naive upstream source
only emits the instruction before the first ';'. patch_assembly rewrites each
template to explicit newlines and check_armcpu_object proves the emitted Mach-O
object really contains every instruction inside the caller function bodies.
patch_boot_order restores the Darwin 23 boot-CPU registration order and
patch_smp_hold adds a default-off pre-CPU_ON hold (see their comments).
The boot-order transform is a consistency fix, not a demonstrated stall fix."""
import hashlib
import re
import struct

# Upstream source identity. build-nabu-platform.py refuses to transform an
# ArmCpu.cpp that does not match, so template drift is caught before compile.
# The hash is over the normalized LF bytes of the pinned Git blob, so it is
# stable whether a working tree checks the file out as LF or CRLF.
PINNED_ARMCPU_COMMIT = '93a5030c5d983d0ef90f0fca93879d6e36ad1ba8'
PINNED_ARMCPU_SOURCE_SHA256 = '202bc278dfe52c2d0a988ec3672a95fbbd169be7f3b323d088b93c8e814f6f8f'


def normalized_source_sha256(source_bytes):
    """SHA-256 of the ArmCpu.cpp with CRLF normalized to LF."""
    return hashlib.sha256(source_bytes.replace(b'\r\n', b'\n')).hexdigest()

TIMER_HELPER = r'''static uint32_t gTimerIntid = 27;
static uint32_t kSgiPpiEnable = 0xffffU | (1U << 27);

static bool nabuTimerIntid(bool present, const void *data, unsigned size, uint32_t *out)
{
  if (!present) { *out = 27; return true; }
  if (!data || size != 4) { return false; }
  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  uint32_t value = uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
                   (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
  if (value < 16 || value >= 32) { return false; }
  *out = value;
  return true;
}
'''

TIMER_PROPERTY = r'''  OSObject *timerObject = gic->getProperty ("virtual-timer-intid");
  OSData *timerData = OSDynamicCast (OSData, timerObject);
  uint32_t timerIntid = 27;
  valid = valid && nabuTimerIntid(timerObject != nullptr,
      timerData ? timerData->getBytesNoCopy() : nullptr,
      timerData ? timerData->getLength() : 0, &timerIntid);
  if (valid) {
    gTimerIntid = timerIntid;
    kSgiPpiEnable = 0xffffU | (1U << timerIntid);
    IOLog("ArmCpu: virtual timer INTID=%u\n", timerIntid);
  }
'''


def patch_timer_source(text):
    for old, new in (
            ('static const uint32_t kSgiPpiEnable = 0xffffU | (1U << 27);\n', TIMER_HELPER),
            ('  armcpu_gic_stride = static_cast<uint32_t> (gRedistStride);\n',
             TIMER_PROPERTY + '  armcpu_gic_stride = static_cast<uint32_t> (gRedistStride);\n'),
            ('    if ((id & 0xffffff) == 27) {\n', '    if ((id & 0xffffff) == gTimerIntid) {\n')):
        if text.count(old) != 1:
            raise ValueError('ArmCpu timer source drift: ' + old[:90])
        text = text.replace(old, new, 1)
    return text


# Darwin AArch64 treats ';' as a comment, so only the first instruction was
# emitted. Keep the pinned templates explicit to reject upstream source drift.
ASM_TEMPLATES = (
    (r'isb; mrs %0, cntvct_el0', 1),
    (r'msr icc_sre_el1, %0; isb', 1),
    (r'msr icc_igrpen1_el1, %0; dsb sy; isb', 2),
    (r'msr icc_eoir1_el1, %0; isb', 2),
    (r'dsb ishst; msr icc_sgi1r_el1, %0; isb', 2),
    (r'mrs %0, daif; msr daifset, #2; isb', 1),
    (r'dsb ishst; isb; mrs %0, cntvct_el0; isb', 1),
    (r'msr icc_sgi1r_el1, %0; isb; mrs %1, cntvct_el0', 1),
    (r'dsb ishst; msr icc_sgi0r_el1, %0; isb', 1),
    (r'msr icc_eoir0_el1, %0; isb', 1),
    (r'isb; mrs %0, cntvct_el0; isb; mrs %2, icc_pmr_el1; isb; mrs %1, cntvct_el0', 1),
    (r'msr daif, %0; isb', 1),
    (r'msr cntv_ctl_el0, %0; isb', 1),
    (r'dsb sy; isb', 1),
)


def patch_assembly(text):
    for template, count in ASM_TEMPLATES:
        old = '"' + template + '"'
        if text.count(old) != count:
            raise ValueError('ArmCpu assembly source drift: ' + template)
        fixed = template.replace('; ', r'\n\t')
        if template.startswith('msr icc_sgi1r_el1, %0;'):
            # tb is output %0; sgi is input %1. Match the upstream T733 fix.
            fixed = r'msr icc_sgi1r_el1, %1\n\tisb\n\tmrs %0, cntvct_el0'
        text = text.replace(old, '"' + fixed + '"')
    if re.search(r'__asm__\s+volatile\s*\(\s*"[^"\n]*;', text):
        raise ValueError('ArmCpu retains a Darwin assembly comment separator')
    return text


BOOT_INIT_OLD = '''  enableGic ();
  if (gSpiIpi) { spiIpiConfigure (gDist, logicalId, affinity); }
  enableCPUTimeBase (true);
  setCPUState (kIOCPUStateRunning);
  bootInitialized = true;
  if (gSelfIpi) { signalCPU (this); }
}'''

BOOT_INIT_NEW = '''  // The boot driver runs on a schedulable IOKit thread. Enabling Group 1
  // can deliver a pending timer before the GIC readback and timer/state setup
  // finish. Keep the local hardware handoff non-preemptible and IRQ-masked.
  // Queue the self-IPI before restoring IRQs so its handler can clear
  // SIGPdisabled before normal AST processing at _enable_preemption().
  // Restore the caller's IRQ and preemption state. No allocation, service
  // publication, registration, or pending-CPU drain belongs in this interval.
  _disable_preemption ();
  const boolean_t nabuSavedIrq = ml_set_interrupts_enabled (FALSE);
  armcpu_nabu_boot_phase = 20;
  enableGic ();
  armcpu_nabu_boot_phase = 21;
  if (gSpiIpi) { spiIpiConfigure (gDist, logicalId, affinity); }
  enableCPUTimeBase (true);
  armcpu_nabu_boot_phase = 22;
  setCPUState (kIOCPUStateRunning);
  bootInitialized = true;
  if (gSelfIpi) { signalCPU (this); }
  armcpu_nabu_boot_phase = 23;
  ml_set_interrupts_enabled (nabuSavedIrq);
  armcpu_nabu_boot_phase = 24;
  _enable_preemption ();
  armcpu_nabu_boot_phase = 26;
}'''


def patch_boot_handoff(text):
    """Guard only boot initCPU's hardware handoff, with passive progress fields.

    These fields are last-reached milestones, not an atomic stack sample. The
    existing early ESP sampler emits them only under nabu-smp-watch=1. Secondary
    initCPU/PSCI/GIC register values and the scheduler algorithm are unchanged.
    Phase 23 follows self-IPI queueing, 24 follows IRQ restoration, and 26
    follows normal preemption restoration, including any pending urgent AST.
    """
    pairs = (
        ('extern "C" kern_return_t processor_start (processor_t);\n',
         '// Exact Darwin 23 preemption entry points; balance only the hardware handoff.\n'
         'extern "C" void _disable_preemption (void);\n'
         'extern "C" void _enable_preemption (void);\n'
         'extern "C" kern_return_t processor_start (processor_t);\n'),
        ('volatile uint32_t armcpu_registered = 0;\n',
         'volatile uint32_t armcpu_registered = 0;\n'
         'volatile uint32_t armcpu_nabu_boot_phase = 0;\n'
         'volatile uint32_t armcpu_nabu_register_phase[8];\n'
         'volatile int32_t armcpu_nabu_register_rc[8];\n'),
        (BOOT_INIT_OLD, BOOT_INIT_NEW),
        ('  armcpu_registered = 1;\n',
         '  armcpu_registered = 1;\n  armcpu_nabu_boot_phase = 10;\n'),
        ('  if (!bootInitialized) { initCPU (true); }\n  registerService ();\n',
         '  if (!bootInitialized) { initCPU (true); }\n'
         '  armcpu_nabu_boot_phase = 30;\n  registerService ();\n'
         '  armcpu_nabu_boot_phase = 31;\n'),
        ('  __atomic_store_n (&gBootRegistered, 1U, __ATOMIC_RELEASE);\n  drainPending ();\n',
         '  __atomic_store_n (&gBootRegistered, 1U, __ATOMIC_RELEASE);\n'
         '  armcpu_nabu_boot_phase = 32;\n  drainPending ();\n'
         '  armcpu_nabu_boot_phase = 33;\n'),
        ('    __atomic_store_n (&gPending[logicalId], this, __ATOMIC_RELEASE);\n',
         '    armcpu_nabu_register_phase[logicalId] = 1;\n'
         '    __atomic_store_n (&gPending[logicalId], this, __ATOMIC_RELEASE);\n'),
        ('bool ArmCpu::finishSecondary (void)\n{\n',
         'bool ArmCpu::finishSecondary (void)\n{\n'
         '  armcpu_nabu_register_phase[logicalId] = 2;\n'),
        ('  if (status != KERN_SUCCESS) { armcpu_smp_fail[logicalId] = 4; return false; }\n',
         '  armcpu_nabu_register_rc[logicalId] = status;\n'
         '  armcpu_nabu_register_phase[logicalId] = 4;\n'
         '  if (status != KERN_SUCCESS) { armcpu_smp_fail[logicalId] = 4; return false; }\n'),
        ('  registerService ();\n  startSecondary ();\n',
         '  registerService ();\n  armcpu_nabu_register_phase[logicalId] = 5;\n'
         '  startSecondary ();\n  armcpu_nabu_register_phase[logicalId] = 6;\n'),
    )
    for old, new in pairs:
        if text.count(old) != 1:
            raise ValueError('ArmCpu boot handoff source drift: ' + old[:90])
        text = text.replace(old, new, 1)
    # Scope the enter marker to finishSecondary, never to boot registration.
    start = text.index('bool ArmCpu::finishSecondary (void)')
    tail = text[start:]
    call = '  kern_return_t status = ml_processor_register (&info, &machProcessor, &ipi_handler, &pmi);\n'
    if tail.count(call) != 1:
        raise ValueError('ArmCpu secondary registration source drift')
    return text[:start] + tail.replace(
        call, '  armcpu_nabu_register_phase[logicalId] = 3;\n' + call, 1)


# Boot CPU registration order. Upstream 93a5030c registers the boot CPU with
# ml_processor_register only after its IOCPUInterruptController is installed,
# because Darwin 25 (xnu-12377) boots the processor from ml_processor_register
# and calls initCPU there. Darwin 23 (xnu-10063, this build) does not: its
# arm64 ml_processor_register only fills BootCpuData/pset fields and returns.
# Droid-VM/ArmCpu fe98808b (merged over 93a5030c at c85e0841) selects the order
# with `registerLate = version_major >= 25` for xnu-10063; the frame-rate
# figures it cites (412-1046 against 3262 frames/100 s) come from a DroidVM
# guest, not from nabu. This build is fixed to Darwin 23, so the transform
# emits that fork's !registerLate path statically:
#   ml_processor_register -> panic on failure -> setCPUNumber -> armcpu_registered
#   ... IOCPUInterruptController setup ... -> if (!bootInitialized) initCPU (true)
# which is also the statement order of the ArmCpu 1951cc84 build that this
# board ran with ncpus=8 avail=8. This is a consistency fix that restores that
# order; it is NOT a demonstrated fix for the dd02/eb46 stall at boot_phase=23
# (that failure is not shown to depend on this order, and the SMP hold below is
# unreachable there because helper threads start only after phase 33).
# A Darwin 25 build must not use this transform.
# Marker note: armcpu_registered=1 (NabuSMP reg=1) and armcpu_nabu_boot_phase=10
# (set right after it) now precede the controller setup, so neither implies the
# IOCPUInterruptController is installed. A last phase of 10 means the boot path
# stopped between registration and initCPU, i.e. during controller setup.
BOOT_ORDER_OLD = '''  info.cluster_type = clusterType (physical);
  setCPUNumber (info.log_id);
'''
BOOT_ORDER_NEW = '''  info.cluster_type = clusterType (physical);
  // Darwin 23 (xnu-10063) leaves initCPU to the driver, so the boot CPU
  // registers before its interrupt controller (order of ArmCpu 1951cc84 and
  // of Droid-VM ArmCpu fe98808b's version_major < 25 path).
  perfmon_interrupt_handler_func pmi = nullptr;
  kern_return_t status = ml_processor_register (&info, &machProcessor, &ipi_handler, &pmi);
  if (status != KERN_SUCCESS) { panic ("ArmCpu: CPU %u registration failed: %d", logicalId, status); }
  setCPUNumber (info.log_id);
  armcpu_registered = 1;
'''
BOOT_REGISTER_LATE = '''  gController = controller;
  // Newer kernels boot the processor from ml_processor_register, which calls initCPU and enables the GIC and
  // timer; the handler above must already be installed. Older kernels leave initCPU to the driver.
  perfmon_interrupt_handler_func pmi = nullptr;
  kern_return_t status = ml_processor_register (&info, &machProcessor, &ipi_handler, &pmi);
  if (status != KERN_SUCCESS) { panic ("ArmCpu: CPU %u registration failed: %d", logicalId, status); }
  armcpu_registered = 1;
  if (!bootInitialized) { initCPU (true); }
'''
BOOT_REGISTER_EARLY = '''  gController = controller;
  // The boot CPU registered above, before this controller (Darwin 23 order).
  if (!bootInitialized) { initCPU (true); }
'''


def patch_boot_order(text):
    """Register the boot CPU before its interrupt controller (Darwin 23 order).

    Only the boot branch of ArmCpu::start changes; finishSecondary, initCPU,
    interrupt, startThread and startCPU are untouched by this transform.
    """
    for old, new in ((BOOT_ORDER_OLD, BOOT_ORDER_NEW),
                     (BOOT_REGISTER_LATE, BOOT_REGISTER_EARLY)):
        if text.count(old) != 1:
            raise ValueError('ArmCpu boot order source drift: ' + old[:90])
        text = text.replace(old, new, 1)
    return text


# Opt-in observation gate, default off: armcpu-smp-hold-ms=N with 1 <= N <= 10000
# sleeps N ms in each secondary's helper thread just before processor_start
# (PSCI CPU_ON). An absent argument, or a numeric value of 0 or > 10000, does
# nothing. PE_parse_boot_argn byte-copies a non-numeric value into holdMs, so
# such a value may produce a short hold, and a bare flag reads as 1 (1 ms).
# The boot IOKit thread, initCPU and the scheduler are unchanged. The helper
# runs only after the boot CPU's initCPU, which enables the timer unless
# armcpu-skip-gic=1 left it off; IOSleep would then never return, so the hold
# is skipped whenever skipGic is set. With the ESP writer's ~1 s cadence a
# hold of >= 3000 ms commits the pre-CPU_ON state before any secondary core
# executes.
SMP_HOLD_BOOTARG = 'armcpu-smp-hold-ms'
SMP_HOLD_MAX_MS = 10000
SMP_HOLD_OLD = '''  armcpu_smp_step[self->logicalId] = 3;
  // Blocks until the new core reaches the scheduler; a core that never arrives only stalls this helper thread.
  processor_start (self->machProcessor);
'''
SMP_HOLD_NEW = '''  armcpu_smp_step[self->logicalId] = 3;
  unsigned holdMs = 0;
  if (!self->skipGic && PE_parse_boot_argn ("armcpu-smp-hold-ms", &holdMs, sizeof (holdMs)) &&
      holdMs != 0 && holdMs <= 10000) {
    IOSleep (holdMs);
  }
  // Blocks until the new core reaches the scheduler; a core that never arrives only stalls this helper thread.
  processor_start (self->machProcessor);
'''


def patch_smp_hold(text):
    """Add the default-off, bounded pre-CPU_ON hold to ArmCpu::startThread."""
    if text.count(SMP_HOLD_OLD) != 1:
        raise ValueError('ArmCpu SMP hold source drift: ' + SMP_HOLD_OLD[:90])
    return text.replace(SMP_HOLD_OLD, SMP_HOLD_NEW, 1)


def patch_source(text, spi_lifecycle=False):
    # The pinned file may be checked out with CRLF; normalize so the pinned
    # source templates match and the transform is deterministic.
    text = patch_assembly(patch_timer_source(text.replace('\r\n', '\n')))
    text = patch_boot_handoff(patch_smp_hold(patch_boot_order(text)))
    return patch_spi_lifecycle(text) if spi_lifecycle else text


# The default transform remains byte-identical. A coordinator opts in only
# for a candidate that links the IRQ lifecycle consumers and qualifies them.
SPI_STATE_OLD = '''struct ArmCpuSpi {uint32_t id; void (*handler) (void *); void *context; volatile uint64_t count;};
static ArmCpuSpi gSpi[ARMCPU_SPI_SLOTS];
static volatile uint32_t gSpiUsed = 0;
'''
SPI_STATE_NEW = r'''#define ARMCPU_SPI_LIFECYCLE_VERSION 1
struct ArmCpuSpi {
  uint32_t id;
  void (*handler) (void *);
  void *context;
  uint64_t count;
  uint32_t readers, accepting;
  bool registered, deferred, edge;
};
static ArmCpuSpi gSpi[ARMCPU_SPI_SLOTS];
static uint32_t gSpiUsed = 0;
'''
SPI_DISPATCH_OLD = '''      ArmCpuSpi *spi = nullptr;
      const uint32_t used = __atomic_load_n (&gSpiUsed, __ATOMIC_ACQUIRE);
      for (uint32_t slot = 0; intid >= 32 && slot < used && spi == nullptr; slot++) {
        if (gSpi[slot].id == intid) { spi = &gSpi[slot]; }
      }
      if (spi != nullptr) {
        armcpu_irq_phase = 7;
        spi->count = spi->count + 1;
        spi->handler (spi->context);
'''
SPI_DISPATCH_NEW = '''      if (armcpuSpiDispatch (intid)) {
'''
SPI_NATIVE = r'''static IOLock *gSpiConfigLock = nullptr;
static uint64_t armcpuSpiNowMs (void)
{
  uint64_t ns = 0;
  absolutetime_to_nanoseconds (mach_absolute_time (), &ns);
  return ns / 1000000;
}
static bool armcpuSpiThreadContext (void)
{
  return !ml_at_interrupt_context () && ml_get_interrupts_enabled ();
}
static bool armcpuSpiTryLock (void)
{
  IOLock *lock = __atomic_load_n (&gSpiConfigLock, __ATOMIC_ACQUIRE);
  if (lock == nullptr) {
    IOLock *allocated = IOLockAlloc ();
    if (allocated == nullptr) { return false; }
    IOLock *expected = nullptr;
    if (!__atomic_compare_exchange_n (&gSpiConfigLock, &expected, allocated, false,
                                      __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
      IOLockFree (allocated);
      lock = expected;
    } else { lock = allocated; }
  }
  return IOLockTryLock (lock);
}
static void armcpuSpiUnlock (void) { IOLockUnlock (gSpiConfigLock); }
static void armcpuSpiSleep (void) { IOSleep (1); }
static void armcpuSpiBarrier (void) { __asm__ volatile ("dsb sy" ::: "memory"); }
'''
SPI_HELPER = r'''// Administrative operations are thread-only and serialized. The ISR never
// takes that lock. IDs are immutable after publication, including tombstones.
// SC reader admission and closure make a successful drain safe for context
// release. Reader counters are never reset when the same INTID is reattached.
static ArmCpuSpi *armcpuSpiFind (uint32_t intid)
{
  const uint32_t used = __atomic_load_n (&gSpiUsed, __ATOMIC_ACQUIRE);
  for (uint32_t slot = 0; slot < used; slot++) {
    if (gSpi[slot].id == intid) { return &gSpi[slot]; }
  }
  return nullptr;
}
static void armcpuSpiDisable (uint32_t intid)
{
  write32 (gDist, 0x180 + (intid / 32) * 4, 1U << (intid % 32));
  armcpuSpiBarrier ();
}
static bool armcpuSpiDispatch (uint32_t intid)
{
  ArmCpuSpi *spi = armcpuSpiFind (intid);
  if (spi == nullptr) { return false; }
  __atomic_fetch_add (&spi->readers, 1U, __ATOMIC_SEQ_CST);
  bool deliver = __atomic_load_n (&spi->accepting, __ATOMIC_SEQ_CST) != 0;
  if (deliver && spi->deferred) {
    deliver = __atomic_exchange_n (&spi->accepting, 0U, __ATOMIC_SEQ_CST) != 0;
    armcpuSpiDisable (intid);
  } else if (!deliver) { armcpuSpiDisable (intid); }
  if (deliver) {
    armcpu_irq_phase = 7;
    __atomic_fetch_add (&spi->count, 1ULL, __ATOMIC_RELAXED);
    spi->handler (spi->context);
  }
  __atomic_fetch_sub (&spi->readers, 1U, __ATOMIC_SEQ_CST);
  return true;
}
static bool armcpuSpiLock (uint64_t deadline, unsigned budget)
{
  for (unsigned polls = 0; ; polls++) {
    if (armcpuSpiTryLock ()) { return true; }
    if (polls >= budget || armcpuSpiNowMs () >= deadline) { return false; }
    armcpuSpiSleep ();
  }
}
static bool armcpuSpiDrain (ArmCpuSpi *spi, uint64_t deadline, unsigned budget)
{
  for (unsigned polls = 0; ; polls++) {
    if (__atomic_load_n (&spi->readers, __ATOMIC_SEQ_CST) == 0) { return true; }
    if (polls >= budget || armcpuSpiNowMs () >= deadline) { return false; }
    armcpuSpiSleep ();
  }
}
static uint32_t armcpuSpiReadback (uint32_t intid)
{
  const uint32_t word = (intid / 32) * 4, bit = 1U << (intid % 32);
  const unsigned cfg = 0xc00 + (intid / 16) * 4, shift = (intid % 16) * 2 + 1;
  return ((read32 (gDist, 0x80 + word) & bit) ? 1U : 0U) |
         ((read32 (gDist, 0x100 + word) & bit) ? 2U : 0U) |
         (((read32 (gDist, cfg) >> shift) & 1U) << 2) |
         (static_cast<uint32_t> (*reinterpret_cast<volatile uint8_t *> (gDist + 0x400 + intid)) << 8);
}
static __attribute__((always_inline)) inline IOReturn armcpuSpiAttach (
    uint32_t intid, bool edge, void (*handler) (void *), void *context,
    uint32_t *readback, uint64_t *router, bool deferred)
{
  if (gDist == 0 || armcpu_gic_ready == 0 || handler == nullptr) { return kIOReturnNotReady; }
  const unsigned interrupts = ((read32 (gDist, 4) & 31) + 1) * 32;
  if (intid < 32 || intid >= 1020 || intid >= interrupts) { return kIOReturnBadArgument; }
  if (!armcpuSpiThreadContext ()) { return kIOReturnNotPermitted; }
  if (!armcpuSpiLock (armcpuSpiNowMs () + 1000, 1000)) { return kIOReturnTimeout; }
  ArmCpuSpi *spi = armcpuSpiFind (intid);
  IOReturn result = kIOReturnSuccess;
  if (spi != nullptr && spi->registered) { result = kIOReturnExclusiveAccess; }
  const uint32_t used = __atomic_load_n (&gSpiUsed, __ATOMIC_ACQUIRE);
  if (spi == nullptr && used >= ARMCPU_SPI_SLOTS) { result = kIOReturnNoResources; }
  if (result != kIOReturnSuccess) { armcpuSpiUnlock (); return result; }
  const uint32_t word = (intid / 32) * 4, bit = 1U << (intid % 32);
  write32 (gDist, 0x180 + word, bit);
  if (!waitClear (gDist, 0, 1U << 31)) { armcpuSpiUnlock (); return kIOReturnTimeout; }
  write32 (gDist, 0x80 + word, read32 (gDist, 0x80 + word) | bit);
  *reinterpret_cast<volatile uint8_t *> (gDist + 0x400 + intid) = 0xa0;
  const unsigned cfg = 0xc00 + (intid / 16) * 4, shift = (intid % 16) * 2 + 1;
  write32 (gDist, cfg, (read32 (gDist, cfg) & ~(1U << shift)) | ((edge ? 1U : 0U) << shift));
  *reinterpret_cast<volatile uint64_t *> (gDist + 0x6000 + 8 * intid) = gBootAffinity;
  const uint64_t route = *reinterpret_cast<volatile uint64_t *> (gDist + 0x6000 + 8 * intid);
  // Legacy attach still returns its actual readback and enables immediately.
  // Deferred attach requires ownership/configuration readback before publishing.
  if (deferred && (armcpuSpiReadback (intid) != (1U | (edge ? 4U : 0U) | 0xa000U) ||
                   route != gBootAffinity)) { armcpuSpiUnlock (); return kIOReturnNotPermitted; }
  if (spi == nullptr) { spi = &gSpi[used]; spi->id = intid; }
  spi->handler = handler;
  spi->context = context;
  spi->deferred = deferred;
  spi->edge = edge;
  spi->registered = true;
  __atomic_store_n (&spi->count, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n (&spi->accepting, deferred ? 0U : 1U, __ATOMIC_SEQ_CST);
  if (used < ARMCPU_SPI_SLOTS && spi == &gSpi[used]) {
    __atomic_store_n (&gSpiUsed, used + 1, __ATOMIC_RELEASE);
  }
  armcpuSpiBarrier ();
  if (!deferred) { write32 (gDist, 0x100 + word, bit); }
  if (readback != nullptr) { *readback = armcpuSpiReadback (intid); }
  if (router != nullptr) { *router = *reinterpret_cast<volatile uint64_t *> (gDist + 0x6000 + 8 * intid); }
  armcpuSpiUnlock ();
  return kIOReturnSuccess;
}
extern "C" IOReturn armcpu_spi_attach (uint32_t intid, bool edge, void (*handler) (void *), void *context,
                                       uint32_t *readback, uint64_t *router)
{
  return armcpuSpiAttach (intid, edge, handler, context, readback, router, false);
}
extern "C" IOReturn armcpu_spi_attach_deferred (uint32_t intid, bool edge, void (*handler) (void *), void *context,
                                                uint32_t *readback, uint64_t *router)
{
  return armcpuSpiAttach (intid, edge, handler, context, readback, router, true);
}
static IOReturn armcpuSpiChange (uint32_t intid, void (*handler) (void *), void *context,
                                 unsigned timeoutMs, unsigned operation)
{
  if (!armcpuSpiThreadContext ()) { return kIOReturnNotPermitted; }
  if (timeoutMs > 10000 || handler == nullptr) { return kIOReturnBadArgument; }
  const uint64_t deadline = armcpuSpiNowMs () + timeoutMs;
  if (!armcpuSpiLock (deadline, timeoutMs)) { return kIOReturnTimeout; }
  ArmCpuSpi *spi = armcpuSpiFind (intid);
  if (spi == nullptr || !spi->registered || spi->handler != handler || spi->context != context) {
    armcpuSpiUnlock (); return kIOReturnExclusiveAccess;
  }
  __atomic_store_n (&spi->accepting, 0U, __ATOMIC_SEQ_CST);
  armcpuSpiDisable (intid);
  for (unsigned polls = 0; (read32 (gDist, 0) & (1U << 31)) != 0 ||
                           (armcpuSpiReadback (intid) & 2U) != 0; polls++) {
    if (polls >= timeoutMs || armcpuSpiNowMs () >= deadline) {
      armcpuSpiUnlock (); return kIOReturnTimeout;
    }
    armcpuSpiSleep ();
  }
  if (!armcpuSpiDrain (spi, deadline, timeoutMs)) { armcpuSpiUnlock (); return kIOReturnTimeout; }
  if (operation == 1) {
    if (armcpuSpiReadback (intid) != (1U | (spi->edge ? 4U : 0U) | 0xa000U) ||
        *reinterpret_cast<volatile uint64_t *> (gDist + 0x6000 + 8 * intid) != gBootAffinity) {
      armcpuSpiUnlock (); return kIOReturnNotPermitted;
    }
    __atomic_store_n (&spi->accepting, 1U, __ATOMIC_SEQ_CST);
    write32 (gDist, 0x100 + (intid / 32) * 4, 1U << (intid % 32));
    armcpuSpiBarrier ();
    if ((armcpuSpiReadback (intid) & 2U) == 0 &&
        __atomic_load_n (&spi->accepting, __ATOMIC_SEQ_CST) != 0) {
      __atomic_store_n (&spi->accepting, 0U, __ATOMIC_SEQ_CST);
      armcpuSpiDisable (intid);
      armcpuSpiUnlock (); return kIOReturnNotPermitted;
    }
  } else if (operation == 2) {
    spi->registered = false;
    spi->handler = nullptr;
    spi->context = nullptr;
  }
  armcpuSpiUnlock ();
  return kIOReturnSuccess;
}
extern "C" IOReturn armcpu_spi_mask (uint32_t intid, void (*handler) (void *), void *context, unsigned timeoutMs)
{ return armcpuSpiChange (intid, handler, context, timeoutMs, 0); }
extern "C" IOReturn armcpu_spi_unmask (uint32_t intid, void (*handler) (void *), void *context, unsigned timeoutMs)
{ return armcpuSpiChange (intid, handler, context, timeoutMs, 1); }
extern "C" IOReturn armcpu_spi_detach (uint32_t intid, void (*handler) (void *), void *context, unsigned timeoutMs)
{ return armcpuSpiChange (intid, handler, context, timeoutMs, 2); }
extern "C" uint64_t armcpu_spi_count (uint32_t intid)
{
  ArmCpuSpi *spi = armcpuSpiFind (intid);
  return spi == nullptr ? 0 : __atomic_load_n (&spi->count, __ATOMIC_RELAXED);
}
'''


def patch_spi_lifecycle(text):
    """Replace only the SPI table, dispatch subsection and exported SPI API."""
    newline = '\r\n' if '\r\n' in text else '\n'
    text = text.replace('\r\n', '\n')
    if 'ARMCPU_SPI_LIFECYCLE_VERSION' in text:
        raise ValueError('ArmCpu SPI lifecycle already present; use the preserved baseline')
    start = 'extern "C" IOReturn armcpu_spi_attach ('
    end = 'extern "C" uint64_t armcpu_spi_count (uint32_t intid)\n'
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('ArmCpu SPI API source drift')
    first = text.index(start)
    last = text.index('\n}', text.index(end, first)) + 2
    old_api = text[first:last]
    # Bind the exact actual implementation; changes to its register recipe or
    # output layout need an explicit review instead of a permissive rewrite.
    if hashlib.sha256(old_api.encode()).hexdigest() != SPI_API_SHA256:
        raise ValueError('ArmCpu SPI API register/readback source drift')
    for old in (SPI_STATE_OLD, SPI_DISPATCH_OLD):
        if text.count(old) != 1:
            raise ValueError('ArmCpu SPI state/dispatch source drift')
    text = text.replace(old_api, SPI_HELPER[SPI_HELPER.index('static __attribute__((always_inline))'):], 1)
    text = text.replace(SPI_STATE_OLD, SPI_STATE_NEW, 1)
    text = text.replace(SPI_DISPATCH_OLD, SPI_DISPATCH_NEW, 1)
    marker = 'extern "C" {\nvolatile uint64_t armcpu_spi_unhandled = 0;'
    if text.count(marker) != 1:
        raise ValueError('ArmCpu SPI helper insertion source drift')
    prefix = SPI_NATIVE + SPI_HELPER[:SPI_HELPER.index('static __attribute__((always_inline))')]
    text = text.replace(marker, prefix + '\n' + marker, 1)
    includes = '#include <machine/machine_routines.h>\n'
    if text.count(includes) != 1:
        raise ValueError('ArmCpu SPI include source drift')
    text = text.replace(includes, includes + '#include <IOKit/IOLib.h>\n#include <IOKit/IOLocks.h>\n#include <kern/clock.h>\n#include <mach/mach_time.h>\n', 1)
    return text.replace('\n', newline)


SPI_API_SHA256 = 'cebb9197e690622d36fc9ededcb7ebb7ca68f7e1b842f3ff7ef8f5e088e36095'


# A64 encodings verified against clang for arm64-apple-ios17.0. System-register
# msr/mrs keep the target/source register in the low 5 bits, so mask with
# 0xffffffe0. Barriers and the DAIFSet immediate have a fixed full encoding.
ENC = {
    'isb': (0xd5033fdf, 0xffffffff),
    'dsb_sy': (0xd5033f9f, 0xffffffff),
    'dsb_ishst': (0xd5033a9f, 0xffffffff),
    'daifset2': (0xd50342df, 0xffffffff),
    'cntvct': (0xd53be040, 0xffffffe0),
    'cntfrq': (0xd53be000, 0xffffffe0),
    'sre': (0xd518cca0, 0xffffffe0),
    'igrpen1': (0xd518cce0, 0xffffffe0),
    'eoir1': (0xd518cc20, 0xffffffe0),
    'eoir0': (0xd518c820, 0xffffffe0),
    'sgi1r': (0xd518cba0, 0xffffffe0),
    'sgi0r': (0xd518cbe0, 0xffffffe0),
    'daif_mrs': (0xd53b4220, 0xffffffe0),
    'daif_msr': (0xd51b4220, 0xffffffe0),
    'cntvctl': (0xd51be320, 0xffffffe0),
    'pmr': (0xd5384600, 0xffffffe0),
    'ctr': (0xd53b0020, 0xffffffe0),
    'dc_civac': (0xd50b7e20, 0xffffffe0),
}

_LTMP = re.compile(r'^_ltmp\d+$')


def _function_bounds(image, name):
    """Return (start, end, section) for a defined text symbol in `image`."""
    start = image.names.get(name)
    if start is None:
        return None
    section = next((s for s in image.sections if s[0] <= start < s[0] + s[1]), None)
    if section is None:
        return None
    limit = section[0] + section[1]
    end = min([v for k, v in image.names.items()
               if not _LTMP.match(k) and start < v < limit] + [limit])
    return start, end, section


def _words(image, name):
    bounds = _function_bounds(image, name)
    if bounds is None:
        return None, None
    start, end, section = bounds
    code = image.data[section[2] + start - section[0]:section[2] + end - section[0]]
    return struct.unpack('<%dI' % (len(code) // 4), code), start


def _matches(word, token):
    enc, mask = ENC[token]
    return word & mask == enc


def _find_sequence(words, seq):
    """Indexes where the ordered instruction-name sequence appears contiguously."""
    hits = []
    for i in range(0, len(words) - len(seq) + 1):
        if all(_matches(words[i + j], token) for j, token in enumerate(seq)):
            hits.append(i)
    return hits


def _find_subsequence(words, seq):
    """Indexes where `seq` appears in order but not necessarily contiguously."""
    hits = []
    j = 0
    for i, word in enumerate(words):
        if _matches(word, seq[j]):
            if j == len(seq) - 1:
                hits.append(i)
                j = 0
            else:
                j += 1
    return hits


def _require_all(image, label, token_seq, callers):
    """Every listed caller must contain `token_seq` at least once.

    Each caller is an explicit production function boundary; a template that
    appears in a different function does not satisfy the requirement. This
    prevents an unrelated copy of the same instruction from passing the gate.
    """
    seq = tuple(token_seq)
    failed = []
    detail = []
    for caller in callers:
        words, base = _words(image, caller)
        if words is None:
            failed.append((caller, 'missing symbol'))
            continue
        hits = _find_sequence(words, seq)
        if not hits:
            failed.append((caller, 'missing ' + '+'.join(seq)))
            continue
        detail.append({'function': caller,
                       'at': [hex((base or 0) + 4 * i) for i in hits]})
    if failed:
        raise ValueError('ArmCpu template "%s" failed: %s' %
                         (label, '; '.join('%s: %s' % f for f in failed)))
    return {'sequence': list(seq), 'in': detail}


# Production caller lists. Every entry is an actual function in the pinned
# ArmCpu.cpp; counter/waitClear/cleanToMemory are static and inline under -O2, so
# their instructions are validated inside these caller bodies. Each listed
# caller must independently contain the sequence - not merely any one caller.
SGI_SENDERS = ('__ZN6ArmCpu9signalCPUEP5IOCPU', '_armcpu_ipi_selftest')
EOIR1_CALLERS = ('__ZN6ArmCpu9interruptEv', '_armcpu_sgi_selfprobe')
IGRPEN1_CALLERS = ('__ZN6ArmCpu9enableGicEv', '__ZN6ArmCpu10quiesceCPUEv')
# waitClear inlines counter() (isb + cntvct_el0) before the GIC poll loop and
# again on the timeout path. Its three logical call sites are initDistributor
# (2 calls), wakeRedistributor (2) and armcpu_spi_attach (1).
INIT_DISTRIBUTOR = '__ZN6ArmCpu15initDistributorEv'
PREPARE_GIC = '__ZN6ArmCpu10prepareGicEv'
WAKE_REDISTRIBUTOR = '__ZN6ArmCpu17wakeRedistributorEb'
SPI_ATTACH = '_armcpu_spi_attach'
# startCPU calls cleanToMemory three times; the static body is inlined there.
CLEAN_CALLERS = ('__ZN6ArmCpu8startCPUEmm',)


def check_armcpu_object(path):
    """Verify every pinned multi-instruction template in the real Mach-O object."""
    from native_ufs_bindings import MachO
    image = MachO(path)
    if image.kind != 1:
        raise ValueError('ArmCpu object check requires a relocatable Mach-O object')
    verified = {}

    verified['sre+isb'] = _require_all(
        image, 'gic sre enable', ('sre', 'isb'), ('__ZN6ArmCpu9enableGicEv',))
    verified['igrpen1+dsb+isb'] = _require_all(
        image, 'gic group1 enable', ('igrpen1', 'dsb_sy', 'isb'), IGRPEN1_CALLERS)
    verified['eoir1+isb'] = _require_all(
        image, 'eoir1', ('eoir1', 'isb'), EOIR1_CALLERS)
    verified['eoir0+isb'] = _require_all(
        image, 'eoir0', ('eoir0', 'isb'), ('_armcpu_sgi_selfprobe',))
    verified['sgi1r-send'] = _require_all(
        image, 'sgi1r send', ('dsb_ishst', 'sgi1r', 'isb'), SGI_SENDERS)
    verified['sgi0r-send'] = _require_all(
        image, 'sgi0r send', ('dsb_ishst', 'sgi0r', 'isb'), ('_armcpu_sgi_selfprobe',))
    verified['daif-save-mask'] = _require_all(
        image, 'daif save+mask', ('daif_mrs', 'daifset2', 'isb'),
        ('_armcpu_sgi_selfprobe',))
    verified['daif-restore'] = _require_all(
        image, 'daif restore', ('daif_msr', 'isb'), ('_armcpu_sgi_selfprobe',))
    verified['probe-timestamp'] = _require_all(
        image, 'probe timestamp', ('dsb_ishst', 'isb', 'cntvct', 'isb'),
        ('_armcpu_sgi_selfprobe',))
    verified['sgi1r-selfprobe-timestamp'] = _require_all(
        image, 'sgi1r selfprobe', ('sgi1r', 'isb', 'cntvct'),
        ('_armcpu_sgi_selfprobe',))
    verified['pmr-timed-read'] = _require_all(
        image, 'pmr timed read', ('isb', 'cntvct', 'isb', 'pmr', 'isb', 'cntvct'),
        ('_armcpu_sgi_selfprobe',))
    # enableCPUTimeBase is the sole source of the timer-reload template (line
    # 778). If the symbol survives, check it directly; otherwise it was inlined
    # into its only caller, quiesceCPU, so that caller must carry it.
    time_base = '__ZN6ArmCpu17enableCPUTimeBaseEb'
    if image.names.get(time_base) is not None:
        verified['timer-reload'] = _require_all(
            image, 'timer reload', ('cntvctl', 'isb'), (time_base,))
    else:
        verified['timer-reload'] = _require_all(
            image, 'timer reload', ('cntvctl', 'isb'),
            ('__ZN6ArmCpu10quiesceCPUEv',))

    # counter/waitClear: each logical waitClear site must show two contiguous
    # ISB->CNTVCT reads (start plus loop/timeout) and the CNTFRQ read. A bare
    # CNTVCT mrs elsewhere does not pass. initDistributor may be inlined into
    # prepareGic under -O2, so accept whichever of the two carries the body.
    waitclear_detail = []
    for logical, candidates in (
            ('initDistributor', (INIT_DISTRIBUTOR, PREPARE_GIC)),
            ('wakeRedistributor', (WAKE_REDISTRIBUTOR,)),
            ('armcpu_spi_attach', (SPI_ATTACH,))):
        chosen = None
        for caller in candidates:
            words, base = _words(image, caller)
            if words is None:
                continue
            seq_hits = _find_sequence(words, ('isb', 'cntvct'))
            freq = _find_sequence(words, ('cntfrq',))
            if len(seq_hits) >= 2 and freq:
                chosen = {'function': caller,
                          'isb_cntvct_at': [hex((base or 0) + 4 * i) for i in seq_hits],
                          'cntfrq_at': [hex((base or 0) + 4 * i) for i in freq]}
                break
        if chosen is None:
            raise ValueError(
                'ArmCpu waitClear logical site %s lacks two ISB->CNTVCT reads '
                'and CNTFRQ in %s' % (logical, candidates))
        chosen['logical_site'] = logical
        waitclear_detail.append(chosen)
    verified['waitClear-counter-cntvct-cntfrq'] = {'in': waitclear_detail}

    # cleanToMemory: startCPU must retain the DC CIVAC loop and its trailing
    # DSB SY + ISB. Check for a DC CIVAC (masked) followed by the dsb+isb tail.
    words, base = _words(image, CLEAN_CALLERS[0])
    if words is None:
        raise ValueError('ArmCpu startCPU is missing for cleanToMemory check')
    dc_hits = _find_subsequence(words, ('dc_civac',))
    tail = _find_sequence(words, ('dsb_sy', 'isb'))
    if not dc_hits or not any(i > dc_hits[0] for i in tail):
        raise ValueError('ArmCpu startCPU lacks cleanToMemory DC CIVAC + DSB+ISB tail')
    verified['cleanToMemory-dc-civac-dsb-isb'] = {
        'function': CLEAN_CALLERS[0],
        'dc_civac_at': [hex((base or 0) + 4 * i) for i in dc_hits],
        'dsb_isb_at': [hex((base or 0) + 4 * i) for i in tail],
    }

    # The 14th unique template (dsb sy + isb) belongs only to cleanToMemory,
    # which is inlined into startCPU; record it as the same verified entry so
    # the template is named without demanding it in unrelated callers.
    verified['dsb-sy-isb'] = {
        'sequence': ['dsb_sy', 'isb'],
        'in': [{'function': CLEAN_CALLERS[0],
                'at': verified['cleanToMemory-dc-civac-dsb-isb']['dsb_isb_at']}],
    }

    # The gate names 14 unique templates (17 source sites). It adds derived
    # checks that are not separate templates: waitClear start/loop CNTVCT plus
    # CNTFRQ, and cleanToMemory's DC CIVAC loop. Reported separately so a
    # template count is never conflated with the number of verified sequences.
    return {'templates_verified': sorted(verified), 'template_count': 14,
            'source_sites': 17, 'sequence_count': len(verified),
            'runtime_qualified': False, 'detail': verified}


def check_ipi_object(path):
    """Legacy interface: require the real SGI write in both emitters only."""
    from native_ufs_bindings import MachO
    image = MachO(path)
    if image.kind != 1:
        raise ValueError('IPI instruction check requires a relocatable ArmCpu object')
    checked = {}
    for name in SGI_SENDERS:
        words, base = _words(image, name)
        if words is None:
            raise ValueError('ArmCpu IPI sender is missing: ' + name)
        hits = _find_sequence(words, ('dsb_ishst', 'sgi1r', 'isb'))
        if not hits:
            raise ValueError('ArmCpu sender lacks DSB / ICC_SGI1R_EL1 / ISB: ' + name)
        checked[name] = [hex((base or 0) + 4 * i) for i in hits]
    return {'senders': checked, 'sgi1r_barriers_verified': True, 'runtime_qualified': False}

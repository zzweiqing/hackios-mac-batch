/* Early secondary-bring-up evidence rows for the ESP writer. Header-only,
 * runtime opt-in via nabu-smp-watch=1: when the argument is absent or not 1
 * the poll returns after the one-time gate and never touches a counter, the
 * clock or the capture ring. The writer calls this at the top of its loop,
 * before the first nabu_capture_snapshot, so the earliest ArmCpu bring-up
 * state is recorded even while the GPU probe callback is still unset.
 *
 * Counter reads are raw software counters, non-atomic across fields, with no
 * rendering proof (snapshot=non-atomic render_proof=0). Raw values only:
 * psci_rc=0 with step<4 does not prove CPU_ON succeeded, and all eight slot
 * rows are emitted (including unstarted zero slots) so no slot state is
 * inferred. No new thread, allocation, lock,
 * IOLog/console output, MMIO, device I/O, GPU timing, symbol discovery or
 * boot-argument echo; a row dropped under ring contention is not retried.
 */
#ifndef NABU_LOG_EARLY_SMP_H
#define NABU_LOG_EARLY_SMP_H
extern "C" {
extern volatile uint32_t armcpu_registered,armcpu_gic_ready;
extern volatile uint32_t armcpu_nabu_boot_phase,armcpu_nabu_register_phase[8];
extern volatile int32_t armcpu_nabu_register_rc[8];
extern volatile uint32_t armcpu_smp_requested,armcpu_smp_running,armcpu_smp_conduit,armcpu_boot_mpidr;
extern volatile uint32_t armcpu_smp_step[8],armcpu_smp_mpidr[8],armcpu_smp_seen_mpidr[8],armcpu_smp_fail[8];
extern volatile uint32_t armcpu_smp_sys[8][5],armcpu_core_timer[8],armcpu_core_sgi[8];
extern volatile int32_t armcpu_smp_psci_rc[8];
extern volatile uint64_t armcpu_timer_interrupts,armcpu_ipi_interrupts,armcpu_ipi_sent;
extern volatile uint64_t armcpu_irq_long_drains;
extern volatile uint32_t armcpu_irq_phase,armcpu_irq_id,armcpu_irq_drain_most;
extern unsigned int real_ncpus;
extern uint32_t processor_avail_count;
}
static void nabuLogEarlySmpPoll(void)
{
  static unsigned gated=0,enabled=0;
  if(!gated) {
    gated=1;
    unsigned flag=0;
    enabled=PE_parse_boot_argn("nabu-smp-watch",&flag,sizeof(flag)) && flag==1;
  }
  if(!enabled) return;
  enum { NABU_SMP_MAX_SAMPLES=32 };
  static unsigned samples=0;
  static uint64_t next=0;
  if(samples>=NABU_SMP_MAX_SAMPLES || next==~0ULL) return;
  const uint64_t now=mach_absolute_time();
  if(now<next) return;
  clock_interval_to_deadline(1000,kMillisecondScale,&next);
  if(next<=now) next=~0ULL; /* overflow or a frozen clock cannot repeat samples */
  const unsigned sample=++samples;
  char line[384];
#define NABU_SMP_EMIT(...) do { \
    int emitted=snprintf(line,sizeof(line),__VA_ARGS__); \
    if(emitted>0 && (unsigned)emitted<sizeof(line)) \
      nabu_capture_append(line,(unsigned)emitted); \
  } while(0)
  if(sample==1) {
    unsigned cpus=0,sheng=0,ipi=0,diag=0,ui_watch=0,ui_task=0;
    const unsigned have_cpus=PE_parse_boot_argn("cpus",&cpus,4)?1:0;
    const unsigned have_sheng=PE_parse_boot_argn("sheng-smp",&sheng,4)?1:0;
    PE_parse_boot_argn("armcpu-self-ipi",&ipi,4);
    PE_parse_boot_argn("armcpu-diagnostics",&diag,4);
    PE_parse_boot_argn("nabu-ui-watch",&ui_watch,4);
    PE_parse_boot_argn("nabu-ui-task-watch",&ui_task,4);
    NABU_SMP_EMIT("NabuSMP: cfg sample=%u cpus=%u have_cpus=%u sheng=%u have_sheng=%u self_ipi=%u diag=%u ui_watch=%u ui_task=%u\n",
        sample,cpus,have_cpus,sheng,have_sheng,ipi,diag,ui_watch,ui_task);
  }
  NABU_SMP_EMIT("NabuSMP: smp=%u now=%llu snapshot=non-atomic render_proof=0 reg=%u gic=%u smp_wanted=%u secondary_run=%u conduit=%u boot_mpidr=%x ncpus=%u avail=%u boot_phase=%u\n",
      sample,(unsigned long long)now,armcpu_registered,armcpu_gic_ready,
      armcpu_smp_requested,armcpu_smp_running,armcpu_smp_conduit,armcpu_boot_mpidr,
      real_ncpus,processor_avail_count,armcpu_nabu_boot_phase);
  NABU_SMP_EMIT("NabuSMP: smp=%u timer=%llu ipi=%llu sent=%llu irq_phase=%u irq_id=%u long_drains=%llu drain_most=%u\n",
      sample,(unsigned long long)armcpu_timer_interrupts,
      (unsigned long long)armcpu_ipi_interrupts,(unsigned long long)armcpu_ipi_sent,
      armcpu_irq_phase,armcpu_irq_id,(unsigned long long)armcpu_irq_long_drains,armcpu_irq_drain_most);
  for(unsigned slot=0;slot<8;++slot)
    NABU_SMP_EMIT("NabuSMP: smp=%u slot=%u step=%u mpidr=%x seen=%x fail=%x psci=%d el=%x sctlr=%x timer=%u sgi=%u reg_phase=%u reg_rc=%d\n",
        sample,slot,armcpu_smp_step[slot],armcpu_smp_mpidr[slot],armcpu_smp_seen_mpidr[slot],
        armcpu_smp_fail[slot],armcpu_smp_psci_rc[slot],armcpu_smp_sys[slot][0],
        armcpu_smp_sys[slot][1],armcpu_core_timer[slot],armcpu_core_sgi[slot],
        armcpu_nabu_register_phase[slot],armcpu_nabu_register_rc[slot]);
#undef NABU_SMP_EMIT
}
#endif

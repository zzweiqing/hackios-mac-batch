"""Reversible, explicitly enabled UI exec and first-main-thread observations."""

CONTRACT = {'version': 6,
 'trigger': 'nabu-ui-watch=1',
 'targets': ['SpringBoard', 'backboardd', 'runningboardd'],
 'paths': ['/System/Library/CoreServices/SpringBoard.app/SpringBoard',
           '/usr/libexec/backboardd',
           '/usr/libexec/runningboardd'],
 'symbols': ['_nabu_ui_watch_snapshot',
             '_nabu_ui_watch_exit_note',
             '_nabu_ui_watch_activation',
             '_nabu_ui_watch_signature',
             '_nabu_ui_watch_release_ready',
             '_nabu_ui_watch_released',
             '_nabu_ui_watch_activate_image_v2',
             '_nabu_ui_watch_thread_state',
             '_nabu_ui_watch_task_snapshot',
             '_nabu_ui_watch_thread_wait_owner',
             '_nabu_ui_watch_task_wait_snapshot',
             '_nabu_ui_watch_thread_wait_chain',
             '_nabu_ui_watch_task_wait_chain_snapshot'],
 'symbols_by_object': {'kern_exec.c': ['_nabu_ui_watch_snapshot',
                                       '_nabu_ui_watch_exit_note',
                                       '_nabu_ui_watch_activation',
                                       '_nabu_ui_watch_signature',
                                       '_nabu_ui_watch_release_ready',
                                       '_nabu_ui_watch_released',
                                       '_nabu_ui_watch_activate_image_v2'],
                       'thread.c': ['_nabu_ui_watch_thread_state', '_nabu_ui_watch_task_snapshot',
                                    '_nabu_ui_watch_thread_wait_owner',
                                    '_nabu_ui_watch_task_wait_snapshot',
                                    '_nabu_ui_watch_thread_wait_chain',
                                    '_nabu_ui_watch_task_wait_chain_snapshot']},
 'symbol_references_by_object': {'kern_exit.c': ['_nabu_ui_watch_exit_note']},
 'max_samples': 64,
 'interval_us': 10000000,
 'max_threads': 3,
 'max_events': 96,
 'max_exec_contexts': 0,
 'max_line_bytes': 256,
 'first_incarnation_only': True,
 'target_association': 'activation-call-output',
 'spawn_branch_observation': True,
 'user_memory_read': False,
 'scheduler_changed': False,
 'new_worker': False,
 'runtime_qualified': False,
 'task_trigger': 'nabu-ui-task-watch=1',
 'task_scan_limit': 128,
 'task_row_limit': 32,
 'task_new_references': 0,
 'task_wait_tag_scope': 'thread-specific',
 'task_snapshot_atomic': False,
 'wait_trigger': 'nabu-ui-wait-owner=1',
 'wait_requires': ['nabu-ui-watch=1', 'nabu-ui-task-watch=1'],
 'wait_hints': [2, 4, 5, 10, 16, 18],
 'wait_max_hops': 3,
 'wait_target_line_limit': 16,
 'wait_sample_line_limit': 48,
 'wait_total_line_limit': 1536,
 'wait_name_bytes': 15,
 'wait_lock_mode': 'try-only',
 'wait_new_references': 0,
 'wait_owner_field_read': False,
 'wait_debugger_helpers': False,
 'wait_chain_trigger': 'nabu-ui-wait-owner=2',
 'wait_chain_links': 3,
 'wait_chain_fields': 10,
 'wait_chain_sample_line_limit': 12,
 'wait_chain_total_line_limit': 512,
 'wait_chain_dedup_table': 16,
 'wait_chain_max_turnstile_locks': 12,
 'wait_chain_max_thread_locks': 3}
PREFIX = '#define nabu_gpu_userprobe_exec_snapshot nabu_ui_watch_snapshot\n'
SUFFIX = '#undef nabu_gpu_userprobe_exec_snapshot\n'

EXEC_HELPER = r'''/* NABU_UI_WATCH_V2: bounded observation, no exec/scheduler policy change.
 * This is a BSD unit: struct thread and sched locks are not visible here. The
 * scheduler fields are read by nabu_ui_watch_thread_state in osfmk/kern/thread.c. */
extern int nabu_ui_watch_thread_state(thread_t, uint32_t *, uint32_t *, uint64_t *);
extern int nabu_ui_watch_task_snapshot(thread_t, unsigned, uint64_t [32][5], uint32_t [4]);
/* NABU_UI_WATCH_WAIT_V1: optional, separately enabled wait-owner rows. */
extern int nabu_ui_watch_task_wait_snapshot(thread_t, unsigned, uint64_t [32][5], uint32_t [4],
    uint64_t [32][11], char [32][2][16]);
/* NABU_UI_WATCH_CHAIN_V1: nabu-ui-wait-owner=2 additionally records a bounded
 * cross-task owner chain per emitted wait row; =1 keeps the v5 record. */
extern int nabu_ui_watch_task_wait_chain_snapshot(thread_t, unsigned, uint64_t [32][5],
    uint32_t [4], uint64_t [32][11], char [32][2][16], uint64_t [32][3][10],
    char [32][3][2][16]);
/* XNU thread state bits; thread.h's definitions are private to osfmk. */
enum { NABU_UI_TH_TERMINATE = 0x10, NABU_UI_TH_TERMINATE2 = 0x20 };

enum { NABU_UI_TARGETS = 3, NABU_UI_MAX_EVENTS = 96, NABU_UI_MAX_SAMPLES = 64 };
enum { NABU_UI_EMPTY = 0, NABU_UI_CLAIMING = 1, NABU_UI_READY = 2, NABU_UI_CLOSED = 3 };
struct nabu_ui_slot {
    unsigned phase;
    thread_t thread;
    int pid;
    uint64_t uniqueid, tid, first_seq, first_us;
    uint64_t latest_tid;
    unsigned exit_observed, instances;
};
struct nabu_ui_event {
    unsigned ready, emitted, target;
    int pid, result;
    uint64_t uniqueid, tid, seq, us;
    const char *stage;
};
static struct nabu_ui_slot nabu_ui_slots[NABU_UI_TARGETS];
static struct nabu_ui_event nabu_ui_events[NABU_UI_MAX_EVENTS];
static const char *const nabu_ui_names[NABU_UI_TARGETS] = {
    "SpringBoard", "backboardd", "runningboardd"
};
static const char *const nabu_ui_paths[NABU_UI_TARGETS] = {
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
    "/usr/libexec/backboardd", "/usr/libexec/runningboardd"
};
static int nabu_ui_enabled_cache = -1;
static unsigned nabu_ui_closed, nabu_ui_event_count, nabu_ui_event_dropped, nabu_ui_seen_mask;
static unsigned nabu_ui_sample_busy, nabu_ui_sample_contended, nabu_ui_samples, nabu_ui_text_dropped;
static uint64_t nabu_ui_next_us;
/* Only the existing single-writer snapshot gate accesses these buffers.
 * Keep the 1,280-byte rows off the writer's kernel stack. */
static uint64_t nabu_ui_task_rows[32][5];
static uint32_t nabu_ui_task_meta[4];
static int nabu_ui_task_enabled_cache = -1;
/* Wait-owner storage uses the same single-writer gate: 2,816 + 1,024 bytes
 * stay off the kernel stack. Token tables mirror the osfmk enum values. */
enum { NABU_UI_WAIT_TARGET_LINES = 16, NABU_UI_WAIT_SAMPLE_LINES = 48,
       NABU_UI_WAIT_TOTAL_LINES = 1536 };
static uint64_t nabu_ui_wait_rows[32][11];
static char nabu_ui_wait_names[32][2][16];
static int nabu_ui_wait_enabled_cache = -1;
static unsigned nabu_ui_wait_total, nabu_ui_wait_total_suppressed;
/* v6 chain storage uses the same single-writer gate: 7,680 + 3,072 bytes stay
 * off the kernel stack. The next-code table mirrors the private osfmk enum. */
enum { NABU_UI_CHAIN_SAMPLE_LINES = 12, NABU_UI_CHAIN_TOTAL_LINES = 512,
       NABU_UI_CHAIN_LINKS = 3, NABU_UI_CHAIN_DEDUP = 16 };
static uint64_t nabu_ui_chain_rows[32][3][10];
static char nabu_ui_chain_names[32][3][2][16];
static uint64_t nabu_ui_chain_dedup[NABU_UI_CHAIN_DEDUP];
static unsigned nabu_ui_chain_dedup_count, nabu_ui_chain_total, nabu_ui_chain_total_suppressed;
static unsigned nabu_ui_chain_sample_chains, nabu_ui_chain_sample_emitted,
                nabu_ui_chain_sample_dedup, nabu_ui_chain_sample_suppressed,
                nabu_ui_chain_sample_dropped;
static const char *const nabu_ui_chain_next[12] = {
    "thread", "none", "workq", "other", "not_waiting", "no_ts", "ts_busy",
    "hop_busy", "hop_max", "cycle", "lock_busy", "link_max"
};
static const char *const nabu_ui_wait_ts[3] = {"none", "busy", "present"};
static const char *const nabu_ui_wait_kinds[6] = {
    "none", "thread", "turnstile", "workq", "other", "-"
};
static const char *const nabu_ui_wait_stops[9] = {
    "thread", "workq", "none", "no_ts", "ts_busy", "hop_busy", "hop_max", "cycle", "unknown"
};
extern void nabu_capture_append(const char *, unsigned);
extern void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6]);
extern void nabu_service_wait_snapshot(void);

static int
nabu_ui_enabled(void)
{
    int value = __atomic_load_n(&nabu_ui_enabled_cache, __ATOMIC_ACQUIRE);
    if (value < 0) {
        unsigned requested = 0;
        value = PE_parse_boot_argn("nabu-ui-watch", &requested, sizeof(requested)) && requested == 1;
        int unset = -1;
        __atomic_compare_exchange_n(&nabu_ui_enabled_cache, &unset, value, 0,
            __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        value = __atomic_load_n(&nabu_ui_enabled_cache, __ATOMIC_ACQUIRE);
    }
    return value == 1;
}

static uint64_t
nabu_ui_now_us(void)
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000;
}

static int
nabu_ui_target(const char *name, int path)
{
    if (!name) return -1;
    for (unsigned i = 0; i < NABU_UI_TARGETS; ++i) {
        if (!strcmp(name, path ? nabu_ui_paths[i] : nabu_ui_names[i])) return (int)i;
    }
    return -1;
}

int
nabu_ui_watch_activate_image_v2(struct image_params *imgp, int *target)
{
    *target = -1;
    /* The scalar is copied while excpath is valid, directly to this caller.
     * No shared exec table or pointer survives the synchronous activation. */
    return exec_activate_image(imgp, target);
}

static void
nabu_ui_emit(const char *line, int bytes)
{
    if (bytes > 0 && bytes < 256) nabu_capture_append(line, (unsigned)bytes);
    else __atomic_fetch_add(&nabu_ui_text_dropped, 1, __ATOMIC_RELAXED);
}

static unsigned
nabu_ui_event_note(unsigned target, proc_t p, thread_t thread, const char *stage, int result)
{
    if (!nabu_ui_enabled() || __atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) return 0;
    __atomic_fetch_or(&nabu_ui_seen_mask, 1U << target, __ATOMIC_RELAXED);
    unsigned at = __atomic_load_n(&nabu_ui_event_count, __ATOMIC_RELAXED);
    if (at >= NABU_UI_MAX_EVENTS || !__atomic_compare_exchange_n(&nabu_ui_event_count,
            &at, at + 1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        __atomic_fetch_add(&nabu_ui_event_dropped, 1, __ATOMIC_RELAXED);
        return 0;
    }
    struct nabu_ui_event *event = &nabu_ui_events[at];
    event->target = target;
    event->pid = p ? proc_getpid(p) : 0;
    event->uniqueid = p ? proc_uniqueid(p) : 0;
    event->tid = thread ? thread_tid(thread) : 0;
    event->seq = at + 1;
    event->us = nabu_ui_now_us();
    event->stage = stage;
    event->result = result;
    __atomic_store_n(&event->ready, 1, __ATOMIC_RELEASE);
    return at + 1;
}

void
nabu_ui_watch_activation(proc_t p, int target, unsigned returned, int result)
{
    if (!nabu_ui_enabled()) return;
    if (target >= 0 && target < NABU_UI_TARGETS) nabu_ui_event_note((unsigned)target, p, NULL,
        returned ? "activation_return" : "activation_enter", result);
}

void
nabu_ui_watch_signature(proc_t p, int target, int result, int spawn)
{
    if (!nabu_ui_enabled() || !p) return;
    if (target >= 0 && target < NABU_UI_TARGETS)
        nabu_ui_event_note((unsigned)target, p, NULL,
            spawn ? "spawn_signature_return" : "signature_return", result);
}

static void
nabu_ui_publish_thread(proc_t p, thread_t thread, int target, unsigned release_seq)
{
    if (!thread) return;
    if (nabu_ui_target(p->p_comm, 0) != target) {
        nabu_ui_event_note((unsigned)target, p, thread, "identity_mismatch", 0);
        return;
    }
    struct nabu_ui_slot *slot = &nabu_ui_slots[target];
    const uint64_t tid = thread_tid(thread);
    __atomic_store_n(&slot->latest_tid, tid, __ATOMIC_RELEASE);
    __atomic_fetch_add(&slot->instances, 1, __ATOMIC_RELAXED);
    unsigned expected = NABU_UI_EMPTY;
    if (!__atomic_compare_exchange_n(&slot->phase, &expected, NABU_UI_CLAIMING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (expected == NABU_UI_READY && slot->tid != tid)
            nabu_ui_event_note((unsigned)target, p, thread, "new_instance", 0);
        return;
    }
    /* The caller already holds the main-thread reference returned by exec. */
    thread_reference(thread);
    slot->thread = thread;
    slot->pid = proc_getpid(p);
    slot->uniqueid = proc_uniqueid(p);
    slot->tid = tid;
    slot->first_seq = release_seq;
    slot->first_us = nabu_ui_now_us();
    expected = NABU_UI_CLAIMING;
    if (!__atomic_compare_exchange_n(&slot->phase, &expected, NABU_UI_READY, 0,
            __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        /* A closing writer leaves cleanup to an in-flight publisher. */
        __atomic_store_n(&slot->thread, (thread_t)NULL, __ATOMIC_RELAXED);
        thread_deallocate_safe(thread);
    }
}

void
nabu_ui_watch_release_ready(proc_t p, thread_t thread, int target, int error, int committed, int no_exec)
{
    if (!nabu_ui_enabled() || !p ||
        __atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) return;
    if (target < 0 || target >= NABU_UI_TARGETS) return;
    if (no_exec) {
        unsigned release_seq = nabu_ui_event_note((unsigned)target, p, thread,
            error ? "spawn_release_failed" : "spawn_release_ready", error);
        if (!error && committed) nabu_ui_publish_thread(p, thread, target, release_seq);
        return;
    }
    unsigned release_seq = nabu_ui_event_note((unsigned)target, p, thread,
        !committed ? "not_committed" : error ? "final_error" : "release_ready", error);
    if (error || !committed) return;
    nabu_ui_publish_thread(p, thread, target, release_seq);
}

void
nabu_ui_watch_released(proc_t p, thread_t thread, int target, int error, int committed, int no_exec)
{
    if (!nabu_ui_enabled() || !p) return;
    if (target >= 0 && target < NABU_UI_TARGETS) nabu_ui_event_note((unsigned)target, p, thread,
        no_exec ? (committed && !error ? "spawn_released" : "spawn_release_failed") :
        (committed && !error ? "exec_released" : "release_failed"), error);
}

void
nabu_ui_watch_exit_note(proc_t p, int status)
{
    if (!nabu_ui_enabled() || !p) return;
    int target = nabu_ui_target(p->p_comm, 0);
    if (target < 0) return;
    struct nabu_ui_slot *slot = &nabu_ui_slots[target];
    int pid = proc_getpid(p);
    uint64_t uid = proc_uniqueid(p);
    int known = 0;
    if (__atomic_load_n(&slot->phase, __ATOMIC_ACQUIRE) == NABU_UI_READY &&
        slot->pid == pid && slot->uniqueid == uid) {
        __atomic_store_n(&slot->exit_observed, 1, __ATOMIC_RELEASE);
        known = 1;
    }
    for (unsigned i = 0; !known && i < NABU_UI_MAX_EVENTS; ++i) {
        struct nabu_ui_event *event = &nabu_ui_events[i];
        if (__atomic_load_n(&event->ready, __ATOMIC_ACQUIRE) && event->target == (unsigned)target &&
            event->pid == pid && event->uniqueid == uid) known = 1;
    }
    if (known) nabu_ui_event_note((unsigned)target, p, NULL, "exit_observed", status);
}

static void
nabu_ui_close(void)
{
    __atomic_store_n(&nabu_ui_closed, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < NABU_UI_TARGETS; ++i) {
        struct nabu_ui_slot *slot = &nabu_ui_slots[i];
        unsigned phase = __atomic_exchange_n(&slot->phase, NABU_UI_CLOSED, __ATOMIC_ACQ_REL);
        if (phase == NABU_UI_READY) {
            thread_t thread = __atomic_exchange_n(&slot->thread, (thread_t)NULL, __ATOMIC_ACQ_REL);
            if (thread) thread_deallocate_safe(thread);
        }
    }
}

/* Format one wait-owner row. Fields that were not read print '-', never a
 * placeholder number. Out-of-range codes refuse the row instead of guessing. */
static int
nabu_ui_wait_format(char *line, unsigned size, unsigned sample, unsigned target, uint64_t tid,
    uint32_t hint, const uint64_t owner[11], const char names[2][16])
{
    if (owner[1] > 2 || owner[2] > 5 || owner[4] > 2 || owner[5] > 3 || owner[8] > 3 ||
        owner[9] > 8 || owner[10] > 0xff || names[0][15] || names[1][15]) return -1;
    char inh_tid[24] = "-", inh_state[16] = "-", inh_hint[16] = "-", flags[8] = "-";
    if (owner[2] == 1) snprintf(inh_tid, sizeof(inh_tid), "%llu", (unsigned long long)owner[3]);
    if (owner[5] == 1 || owner[5] == 3) {
        snprintf(inh_state, sizeof(inh_state), "%x", (unsigned)owner[6]);
        snprintf(inh_hint, sizeof(inh_hint), "%u", (unsigned)owner[7]);
    } else if (owner[5] == 2) {
        snprintf(inh_state, sizeof(inh_state), "busy");
    }
    if (owner[1] == 2) snprintf(flags, sizeof(flags), "%x", (unsigned)owner[10]);
    return snprintf(line, size,
        "NabuUIWait: sample=%u target=%s tid=%llu hint=%u ts=%s inh_kind=%s inh_tid=%s inh_same_task=%s inh_state=%s inh_hint=%s flags=%s hops=%u stop=%s name=%s inh_name=%s\n",
        sample, nabu_ui_names[target], (unsigned long long)tid, hint, nabu_ui_wait_ts[owner[1]],
        nabu_ui_wait_kinds[owner[2]], inh_tid, owner[4] == 2 ? "-" : owner[4] ? "1" : "0",
        inh_state, inh_hint, flags, (unsigned)owner[8], nabu_ui_wait_stops[owner[9]],
        names[0], names[1]);
}

/* Format one owner-chain link row. Fields the walk did not read print '-',
 * never a placeholder number; out-of-range codes refuse the row like v5. */
static int
nabu_ui_owner_format(char *line, unsigned size, unsigned sample, unsigned target,
    uint64_t waiter, unsigned link, const uint64_t rec[10], const char names[2][16])
{
    if (rec[0] != 1 || !link || link > 3 || rec[4] > 2 || rec[5] > 3 || rec[8] > 3 ||
        rec[9] > 11 || names[0][15] || names[1][15]) return -1;
    char tid[24] = "-", pid[24] = "-", uniq[24] = "-", same[8] = "-",
         state[16] = "-", hint[16] = "-";
    const char *name = "-", *proc = "-";
    if (rec[1]) {
        snprintf(tid, sizeof(tid), "%llu", (unsigned long long)rec[1]);
        name = names[0];
        if (names[1][0]) proc = names[1];
    }
    if (rec[2] != UINT64_MAX)
        snprintf(pid, sizeof(pid), "%lld", (long long)rec[2]);
    if (rec[3] != UINT64_MAX)
        snprintf(uniq, sizeof(uniq), "%llu", (unsigned long long)rec[3]);
    if (rec[4] < 2) snprintf(same, sizeof(same), "%u", (unsigned)rec[4]);
    if (rec[5] == 1 || rec[5] == 3) {
        snprintf(state, sizeof(state), "%x", (unsigned)rec[6]);
        snprintf(hint, sizeof(hint), "%u", (unsigned)rec[7]);
    }
    return snprintf(line, size,
        "NabuUIOwner: sample=%u target=%s waiter=%llu link=%u tid=%s pid=%s uniq=%s "
        "proc=%s name=%s same=%s state=%s hint=%s hops=%u next=%s\n",
        sample, nabu_ui_names[target], (unsigned long long)waiter, link, tid, pid,
        uniq, proc, name, same, state, hint, (unsigned)rec[8], nabu_ui_chain_next[rec[9]]);
}

/* Called right after an emitted NabuUIWait row whose inheritor is a thread:
 * emit one line per recorded link, bounded per sample and per boot. Chains
 * whose link-1 owner TID was already emitted in this sample are deduplicated;
 * a chain that does not fit the remaining budget is suppressed whole so an
 * emitted chain never ends in a missing link. */
static void
nabu_ui_owner_emit(char line[256], unsigned sample, unsigned target, unsigned row)
{
    unsigned links = 0;
    while (links < NABU_UI_CHAIN_LINKS && nabu_ui_chain_rows[row][links][0] == 1) ++links;
    if (!links || !nabu_ui_chain_rows[row][0][1]) return;
    const uint64_t first = nabu_ui_chain_rows[row][0][1];
    for (unsigned i = 0; i < nabu_ui_chain_dedup_count; ++i) {
        if (nabu_ui_chain_dedup[i] == first) {
            ++nabu_ui_chain_sample_dedup;
            return;
        }
    }
    if (nabu_ui_chain_dedup_count >= NABU_UI_CHAIN_DEDUP ||
        nabu_ui_chain_sample_emitted + links > NABU_UI_CHAIN_SAMPLE_LINES ||
        nabu_ui_chain_total + links > NABU_UI_CHAIN_TOTAL_LINES) {
        nabu_ui_chain_sample_suppressed += links;
        nabu_ui_chain_total_suppressed += links;
        return;
    }
    nabu_ui_chain_dedup[nabu_ui_chain_dedup_count++] = first;
    for (unsigned k = 0; k < links; ++k) {
        const int bytes = nabu_ui_owner_format(line, 256, sample, target,
            nabu_ui_task_rows[row][0], k + 1, nabu_ui_chain_rows[row][k],
            (const char (*)[16])nabu_ui_chain_names[row][k]);
        if (bytes > 0 && bytes < 256) {
            nabu_capture_append(line, (unsigned)bytes);
            ++nabu_ui_chain_sample_emitted;
            ++nabu_ui_chain_total;
        } else {
            ++nabu_ui_chain_sample_dropped;
            __atomic_fetch_add(&nabu_ui_text_dropped, 1, __ATOMIC_RELAXED);
        }
    }
    ++nabu_ui_chain_sample_chains;
}

void
nabu_ui_watch_snapshot(uint32_t out[6])
{
    nabu_gpu_userprobe_exec_snapshot(out);
    nabu_service_wait_snapshot();
    if (!nabu_ui_enabled() || __atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) return;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&nabu_ui_sample_busy, &expected, 1, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        __atomic_fetch_add(&nabu_ui_sample_contended, 1, __ATOMIC_RELAXED);
        return;
    }
    uint64_t now = nabu_ui_now_us();
    if (nabu_ui_samples >= NABU_UI_MAX_SAMPLES || now < nabu_ui_next_us) {
        __atomic_store_n(&nabu_ui_sample_busy, 0, __ATOMIC_RELEASE);
        return;
    }
    nabu_ui_next_us = now > UINT64_MAX - 10000000 ? UINT64_MAX : now + 10000000;
    const unsigned sample = ++nabu_ui_samples;
    /* The build flag and nabu-ui-watch must already be enabled. Task sampling
     * is a second, default-off runtime choice independent of display wrapping. */
    if (nabu_ui_task_enabled_cache < 0) {
        unsigned requested = 0;
        nabu_ui_task_enabled_cache = PE_parse_boot_argn("nabu-ui-task-watch", &requested,
            sizeof(requested)) && requested == 1;
    }
    /* Wait-owner rows are a third, default-off choice. Without task sampling
     * the argument is not even read, so v4 output stays byte-identical. The
     * value 2 keeps every v5 row and adds bounded owner-chain rows. */
    if (nabu_ui_task_enabled_cache == 1 && nabu_ui_wait_enabled_cache < 0) {
        unsigned requested = 0;
        nabu_ui_wait_enabled_cache = PE_parse_boot_argn("nabu-ui-wait-owner", &requested,
            sizeof(requested)) && (requested == 1 || requested == 2) ? (int)requested : 0;
    }
    const int wait_owner = nabu_ui_task_enabled_cache == 1 &&
        (nabu_ui_wait_enabled_cache == 1 || nabu_ui_wait_enabled_cache == 2);
    const int wait_chain = nabu_ui_wait_enabled_cache == 2;
    if (wait_chain) {
        nabu_ui_chain_dedup_count = 0;
        nabu_ui_chain_sample_chains = 0;
        nabu_ui_chain_sample_emitted = 0;
        nabu_ui_chain_sample_dedup = 0;
        nabu_ui_chain_sample_suppressed = 0;
        nabu_ui_chain_sample_dropped = 0;
    }
    unsigned wait_eligible = 0, wait_emitted = 0, wait_suppressed = 0, wait_dropped = 0;
    char line[256];
    unsigned event_count = __atomic_load_n(&nabu_ui_event_count, __ATOMIC_ACQUIRE);
    if (event_count > NABU_UI_MAX_EVENTS) event_count = NABU_UI_MAX_EVENTS;
    unsigned pending = 0;
    for (unsigned i = 0; i < event_count; ++i) {
        struct nabu_ui_event *event = &nabu_ui_events[i];
        if (!__atomic_load_n(&event->ready, __ATOMIC_ACQUIRE)) { ++pending; continue; }
        if (event->emitted) continue;
        nabu_ui_emit(line, snprintf(line, sizeof(line),
            "NabuUI: event=%llu target=%s pid=%d uid=%llu tid=%llu us=%llu stage=%s result=%d\n",
            (unsigned long long)event->seq, nabu_ui_names[event->target], event->pid,
            (unsigned long long)event->uniqueid, (unsigned long long)event->tid,
            (unsigned long long)event->us, event->stage, event->result));
        event->emitted = 1;
    }
    for (unsigned i = 0; i < NABU_UI_TARGETS; ++i) {
        struct nabu_ui_slot *slot = &nabu_ui_slots[i];
        unsigned phase = __atomic_load_n(&slot->phase, __ATOMIC_ACQUIRE);
        if (phase != NABU_UI_READY) {
            nabu_ui_emit(line, snprintf(line, sizeof(line),
                "NabuUI: sample=%u target=%s status=%s phase=%u first_incarnation=1\n",
                sample, nabu_ui_names[i], phase == NABU_UI_EMPTY &&
                    !(__atomic_load_n(&nabu_ui_seen_mask, __ATOMIC_RELAXED) & (1U << i)) ?
                    "not_observed" : "not_published", phase));
            continue;
        }
        thread_t thread = __atomic_load_n(&slot->thread, __ATOMIC_ACQUIRE);
        uint32_t state = 0, hint = 0;
        uint64_t wait = 0;
        const char *status = "sample_unavailable";
        if (thread) {
            int sampled = nabu_ui_watch_thread_state(thread, &state, &hint, &wait);
            status = sampled == 0 ? "sample_ok" : sampled == 1 ? "lock_busy" : "sample_unavailable";
        }
        unsigned exited = __atomic_load_n(&slot->exit_observed, __ATOMIC_ACQUIRE);
        unsigned instances = __atomic_load_n(&slot->instances, __ATOMIC_RELAXED);
        uint64_t latest_tid = __atomic_load_n(&slot->latest_tid, __ATOMIC_ACQUIRE);
        nabu_ui_emit(line, snprintf(line, sizeof(line),
            "NabuUI: sample=%u target=%s pid=%d uid=%llu tid=%llu status=%s state=%x hint=%u wait_tag=%llx exit=%u stale=%u instances=%u first_incarnation=1\n",
            sample, nabu_ui_names[i], slot->pid, (unsigned long long)slot->uniqueid,
            (unsigned long long)slot->tid, status, state, hint, (unsigned long long)wait,
            exited, exited || latest_tid != slot->tid ||
            (state & (NABU_UI_TH_TERMINATE | NABU_UI_TH_TERMINATE2)), instances));
    }
    if (nabu_ui_task_enabled_cache == 1) {
        for (unsigned i = 0; i < NABU_UI_TARGETS; ++i) {
            struct nabu_ui_slot *slot = &nabu_ui_slots[i];
            if (__atomic_load_n(&slot->phase, __ATOMIC_ACQUIRE) != NABU_UI_READY) continue;
            thread_t anchor = __atomic_load_n(&slot->thread, __ATOMIC_ACQUIRE);
            const unsigned rotation = (sample - 1) * 32;
            const int sampled = wait_chain ?
                nabu_ui_watch_task_wait_chain_snapshot(anchor, rotation, nabu_ui_task_rows,
                    nabu_ui_task_meta, nabu_ui_wait_rows, nabu_ui_wait_names,
                    nabu_ui_chain_rows, nabu_ui_chain_names) :
                wait_owner ?
                nabu_ui_watch_task_wait_snapshot(anchor, rotation, nabu_ui_task_rows,
                    nabu_ui_task_meta, nabu_ui_wait_rows, nabu_ui_wait_names) :
                nabu_ui_watch_task_snapshot(anchor, rotation,
                    nabu_ui_task_rows, nabu_ui_task_meta);
            unsigned exited = __atomic_load_n(&slot->exit_observed, __ATOMIC_ACQUIRE);
            unsigned stale = exited ||
                __atomic_load_n(&slot->latest_tid, __ATOMIC_ACQUIRE) != slot->tid;
            nabu_ui_emit(line, snprintf(line, sizeof(line),
                "NabuUITask: sample=%u target=%s pid=%d uid=%llu status=%s total=%u scanned=%u rows=%u omitted=%u rotation=%u stale=%u snapshot=non-atomic\n",
                sample, nabu_ui_names[i], slot->pid, (unsigned long long)slot->uniqueid,
                sampled == 0 ? "sample_ok" : sampled == 1 ? "lock_busy" : "sample_unavailable",
                nabu_ui_task_meta[0], nabu_ui_task_meta[1], nabu_ui_task_meta[2],
                nabu_ui_task_meta[3], rotation, stale));
            if (sampled != 0) continue;
            for (unsigned j = 0; j < nabu_ui_task_meta[2] && j < 32; ++j) {
                const uint64_t *row = nabu_ui_task_rows[j];
                nabu_ui_emit(line, snprintf(line, sizeof(line),
                    "NabuUITask: sample=%u target=%s pid=%d uid=%llu tid=%llu status=%s state=%x hint=%u wait_tag=%llx\n",
                    sample, nabu_ui_names[i], slot->pid, (unsigned long long)slot->uniqueid,
                    (unsigned long long)row[0], row[4] == 0 ? "sample_ok" :
                    row[4] == 1 ? "lock_busy" : "sample_unavailable", (unsigned)row[1],
                    (unsigned)row[2], (unsigned long long)row[3]));
            }
            if (!wait_owner) continue;
            /* Formatted after the task lock was released; rows whose scheduler
             * sample failed never carry an owner record. Each target gets its
             * own share so one busy process cannot hide another. Lock-type
             * waits go first, PortReceive (often an idle receiver) second, and
             * the start row moves by 16 every 4 samples so a crowded
             * window does not suppress the same rows forever. */
            const unsigned wait_rows = nabu_ui_task_meta[2] < 32 ? nabu_ui_task_meta[2] : 32;
            const unsigned wait_shift = wait_rows ? ((sample - 1) / 4 * 16) % wait_rows : 0;
            unsigned target_emitted = 0;
            for (unsigned pass = 0; pass < 2; ++pass) {
                for (unsigned k = 0; k < wait_rows; ++k) {
                    const unsigned j = (k + wait_shift) % wait_rows;
                    if (nabu_ui_wait_rows[j][0] != 1 || nabu_ui_task_rows[j][4] != 0) continue;
                    if ((nabu_ui_task_rows[j][2] == 2) != (pass == 1)) continue;
                    ++wait_eligible;
                    if (target_emitted >= NABU_UI_WAIT_TARGET_LINES ||
                            wait_emitted >= NABU_UI_WAIT_SAMPLE_LINES ||
                            nabu_ui_wait_total >= NABU_UI_WAIT_TOTAL_LINES) {
                        ++wait_suppressed;
                        continue;
                    }
                    const int bytes = nabu_ui_wait_format(line, sizeof(line), sample, i,
                        nabu_ui_task_rows[j][0], (uint32_t)nabu_ui_task_rows[j][2],
                        nabu_ui_wait_rows[j], (const char (*)[16])nabu_ui_wait_names[j]);
                    if (bytes > 0 && bytes < 256) {
                        nabu_capture_append(line, (unsigned)bytes);
                        ++target_emitted;
                        ++wait_emitted;
                        ++nabu_ui_wait_total;
                        if (wait_chain && nabu_ui_wait_rows[j][2] == 1)
                            nabu_ui_owner_emit(line, sample, i, j);
                    } else {
                        ++wait_dropped;
                        __atomic_fetch_add(&nabu_ui_text_dropped, 1, __ATOMIC_RELAXED);
                    }
                }
            }
        }
    }
    if (wait_owner) {
        nabu_ui_wait_total_suppressed += wait_suppressed;
        nabu_ui_emit(line, snprintf(line, sizeof(line),
            "NabuUIWait: budget sample=%u eligible=%u emitted=%u suppressed=%u dropped=%u total_emitted=%u total_suppressed=%u target_limit=%u sample_limit=%u total_limit=%u\n",
            sample, wait_eligible, wait_emitted, wait_suppressed, wait_dropped, nabu_ui_wait_total,
            nabu_ui_wait_total_suppressed, (unsigned)NABU_UI_WAIT_TARGET_LINES,
            (unsigned)NABU_UI_WAIT_SAMPLE_LINES, (unsigned)NABU_UI_WAIT_TOTAL_LINES));
    }
    if (wait_chain) {
        nabu_ui_emit(line, snprintf(line, sizeof(line),
            "NabuUIOwner: budget sample=%u chains=%u emitted=%u dedup=%u suppressed=%u "
            "dropped=%u total_emitted=%u total_suppressed=%u sample_limit=12 "
            "total_limit=512 link_limit=3\n",
            sample, nabu_ui_chain_sample_chains, nabu_ui_chain_sample_emitted,
            nabu_ui_chain_sample_dedup, nabu_ui_chain_sample_suppressed,
            nabu_ui_chain_sample_dropped, nabu_ui_chain_total,
            nabu_ui_chain_total_suppressed));
    }
    nabu_ui_emit(line, snprintf(line, sizeof(line),
        "NabuUI: budget sample=%u us=%llu events=%u pending=%u dropped=%u texts_dropped=%u target_link=direct sample_contended=%u closing=%u snapshot=non-atomic\n",
        sample, (unsigned long long)now, event_count, pending,
        __atomic_load_n(&nabu_ui_event_dropped, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_ui_text_dropped, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_ui_sample_contended, __ATOMIC_RELAXED), sample == NABU_UI_MAX_SAMPLES));
    if (sample == NABU_UI_MAX_SAMPLES) nabu_ui_close();
    __atomic_store_n(&nabu_ui_sample_busy, 0, __ATOMIC_RELEASE);
}

'''


def _once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('UI watch source drift: ' + before[:90])
    return text.replace(before, after, 1)


def exec_source(text, restore=False):
    marker = '/* NABU_UI_WATCH_V'
    if marker in text:
        if text.count(EXEC_HELPER) != 1 or any(text.count(after) != 1 for _, after in EXEC_PAIRS):
            raise ValueError('UI watch exec source changed after patching')
        if not restore:
            return text
        for before, after in reversed(EXEC_PAIRS):
            text = _once(text, after, before)
        return _once(text, EXEC_HELPER, '')
    if restore:
        return text
    if 'NABU_GPU_USERPROBE_PROCESS_V1' not in text or 'NABU_GPU_USERPROBE_JOB_V1' not in text:
        raise ValueError('UI watch requires the original GPU probe source first')
    text = _once(text, 'static int\nexec_activate_image(struct image_params *imgp)\n{\n',
                 EXEC_HELPER + 'static int\nexec_activate_image(struct image_params *imgp)\n{\n')
    for before, after in EXEC_PAIRS:
        text = _once(text, before, after)
    return text


def exit_source(text, restore=False):
    marker = '/* NABU_UI_WATCH_EXIT_V1 */'
    if marker in text:
        if any(text.count(after) != 1 for _, after in EXIT_PAIRS):
            raise ValueError('UI watch exit source changed after patching')
        if restore:
            for before, after in reversed(EXIT_PAIRS):
                text = _once(text, after, before)
        return text
    if restore:
        return text
    if 'NABU_GPU_USERPROBE_EXIT_V1' not in text:
        raise ValueError('UI watch requires the original GPU exit source first')
    for before, after in EXIT_PAIRS:
        text = _once(text, before, after)
    return text

EXEC_PAIRS = (
    ('static int exec_activate_image(struct image_params *imgp);\n',
     'static int exec_activate_image(struct image_params *imgp, int *nabu_ui_target_out);\n'),
    ('static int\nexec_activate_image(struct image_params *imgp)\n{\n',
     'static int\nexec_activate_image(struct image_params *imgp, int *nabu_ui_target_out)\n{\n'),
    (r'''	/* NABU_GPU_USERPROBE_JOB_V1 */
	uint32_t nabu_probe = 0;
	if (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1) {
		extern void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6]);
		extern void (*nabu_log_probe_process_snapshot)(uint32_t *);
		__atomic_store_n(&nabu_log_probe_process_snapshot, nabu_gpu_userprobe_exec_snapshot, __ATOMIC_RELEASE);
		native_gpu_addon_install(p, scratch);
		/* Four files, five with the owner-signed Turnip library for the Vulkan known-image test,
		 * or eight/nine/ten with the owner-signed NativeAdrenoMetal bundle (nine: publish marker,
		 * ten/eleven: publish marker with the pipeline-cache pack and/or the client list). */
		if ((native_gpu_addon_files != 4 && native_gpu_addon_files != 5 && native_gpu_addon_files != 8 &&
		    native_gpu_addon_files != 9 && native_gpu_addon_files != 10 && native_gpu_addon_files != 11) ||
		    native_gpu_addon_failed || native_gpu_addon_error) {
			printf("NabuGPU: userprobe addon refused files=%d failed=%d error=%d render_proof=0\n",
			    native_gpu_addon_files, native_gpu_addon_failed, native_gpu_addon_error);
			return;
		}
		static const char source[] = "/private/var/ngpu/daemons";
		static const char point[] = "/System/Library/LaunchDaemons";
		native_gpu_addon_mount(p, scratch, 0x600, source, sizeof(source), point, sizeof(point),
		    "/System/Library/LaunchDaemons/com.apple.backboardd.plist",
		    "/System/Library/LaunchDaemons/org.hackios.nabu-gpu-userprobe.plist",
		    &native_gpu_addon2_stage, &native_gpu_addon2_status);
		printf("NabuGPU: userprobe addon files=%d written=%d same=%d job_stage=%d job_status=%d render_proof=0\n",
		    native_gpu_addon_files, native_gpu_addon_written, native_gpu_addon_same,
		    native_gpu_addon2_stage, native_gpu_addon2_status);
		if (native_gpu_addon2_stage != 5 || native_gpu_addon2_status) return;
		/* The platform sandbox lets xpcproxy exec a regular file outside /private/var
		 * only, so the cached job names the probe through this /usr/bin union view
		 * (UniXNU T733 does the same for its owner executable). */
		static const char bin_source[] = "/private/var/ngpu/bin";
		static const char bin_point[] = "/usr/bin";
		native_gpu_addon_mount(p, scratch, 0x800, bin_source, sizeof(bin_source), bin_point, sizeof(bin_point),
		    "/usr/bin/IOMFB_FDR_Loader", "/usr/bin/nabu-gpu-userprobe",
		    &native_gpu_addon3_stage, &native_gpu_addon3_status);
		printf("NabuGPU: userprobe bin_stage=%d bin_status=%d render_proof=0\n",
		    native_gpu_addon3_stage, native_gpu_addon3_status);
		if (native_gpu_addon3_stage != 5 || native_gpu_addon3_status) return;
		/* The original launchd accepts system jobs from its verified cache.
		 * Keep every original job and let its original loader authenticate this
		 * owner-signed cache through the explicitly supplied trust module. */
		static const char cache_source[] = "/private/var/ngpu/cache";
		static const char cache_point[] = "/System/Library/xpc";
		native_gpu_addon_mount(p, scratch, 0x400, cache_source, sizeof(cache_source),
		    cache_point, sizeof(cache_point), "/System/Library/xpc/foreground_user_endpoints.plist",
		    "/System/Library/xpc/launchd.plist.sig", &native_gpu_addon_stage, &native_gpu_addon_status);
		printf("NabuGPU: userprobe cache_stage=%d cache_status=%d owner_signed=1 original_jobs_preserved=1 render_proof=0\n",
		    native_gpu_addon_stage, native_gpu_addon_status);
		if (native_gpu_addon_stage != 5 || native_gpu_addon_status ||
		    (native_gpu_addon_files < 8 || native_gpu_addon_files > 11)) return;
		/* NABU_GPU_USERPROBE_PLUGIN_V1: the original Metal discovery loads
		 * /System/Library/Extensions/<MetalPluginName>.bundle; present the owner bundle there,
		 * with the sealed A10 bundle still visible below it. Scratch 0xa00..0xb1a, below mkdir's 0xc00. */
		static volatile int nabu_gpu_plugin_stage = 0, nabu_gpu_plugin_status = -1;
		const int publish = native_gpu_addon_files >= 9;
		vnode_t marker = NULLVP;
		if (!publish && !vnode_lookup("/private/var/ngpu/addons/NativeAdrenoMetal.publish", 0, &marker, vfs_context_current())) {
			/* A test-mode addon must not inherit a publish marker from an earlier boot. */
			vnode_put(marker);
			nabu_gpu_plugin_status = EEXIST;
		} else {
			static const char plugin_source[] = "/private/var/ngpu/addons";
			static const char plugin_point[] = "/System/Library/Extensions";
			native_gpu_addon_mount(p, scratch, 0xa00, plugin_source, sizeof(plugin_source), plugin_point,
			    sizeof(plugin_point), "/System/Library/Extensions/AGXMetalA10.bundle",
			    "/System/Library/Extensions/NativeAdrenoMetal.bundle/Info.plist",
			    &nabu_gpu_plugin_stage, &nabu_gpu_plugin_status);
		}
		printf("NabuGPU: userprobe plugin_stage=%d plugin_status=%d publish=%d render_proof=0\n",
		    nabu_gpu_plugin_stage, nabu_gpu_plugin_status, publish);
		return;
	}
''',
     r'''#define nabu_gpu_userprobe_exec_snapshot nabu_ui_watch_snapshot
	/* NABU_GPU_USERPROBE_JOB_V1 */
	uint32_t nabu_probe = 0;
	if (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1) {
		extern void nabu_gpu_userprobe_exec_snapshot(uint32_t out[6]);
		extern void (*nabu_log_probe_process_snapshot)(uint32_t *);
		__atomic_store_n(&nabu_log_probe_process_snapshot, nabu_gpu_userprobe_exec_snapshot, __ATOMIC_RELEASE);
		native_gpu_addon_install(p, scratch);
		/* Four files, five with the owner-signed Turnip library for the Vulkan known-image test,
		 * or eight/nine/ten with the owner-signed NativeAdrenoMetal bundle (nine: publish marker,
		 * ten/eleven: publish marker with the pipeline-cache pack and/or the client list). */
		if ((native_gpu_addon_files != 4 && native_gpu_addon_files != 5 && native_gpu_addon_files != 8 &&
		    native_gpu_addon_files != 9 && native_gpu_addon_files != 10 && native_gpu_addon_files != 11) ||
		    native_gpu_addon_failed || native_gpu_addon_error) {
			printf("NabuGPU: userprobe addon refused files=%d failed=%d error=%d render_proof=0\n",
			    native_gpu_addon_files, native_gpu_addon_failed, native_gpu_addon_error);
			return;
		}
		static const char source[] = "/private/var/ngpu/daemons";
		static const char point[] = "/System/Library/LaunchDaemons";
		native_gpu_addon_mount(p, scratch, 0x600, source, sizeof(source), point, sizeof(point),
		    "/System/Library/LaunchDaemons/com.apple.backboardd.plist",
		    "/System/Library/LaunchDaemons/org.hackios.nabu-gpu-userprobe.plist",
		    &native_gpu_addon2_stage, &native_gpu_addon2_status);
		printf("NabuGPU: userprobe addon files=%d written=%d same=%d job_stage=%d job_status=%d render_proof=0\n",
		    native_gpu_addon_files, native_gpu_addon_written, native_gpu_addon_same,
		    native_gpu_addon2_stage, native_gpu_addon2_status);
		if (native_gpu_addon2_stage != 5 || native_gpu_addon2_status) return;
		/* The platform sandbox lets xpcproxy exec a regular file outside /private/var
		 * only, so the cached job names the probe through this /usr/bin union view
		 * (UniXNU T733 does the same for its owner executable). */
		static const char bin_source[] = "/private/var/ngpu/bin";
		static const char bin_point[] = "/usr/bin";
		native_gpu_addon_mount(p, scratch, 0x800, bin_source, sizeof(bin_source), bin_point, sizeof(bin_point),
		    "/usr/bin/IOMFB_FDR_Loader", "/usr/bin/nabu-gpu-userprobe",
		    &native_gpu_addon3_stage, &native_gpu_addon3_status);
		printf("NabuGPU: userprobe bin_stage=%d bin_status=%d render_proof=0\n",
		    native_gpu_addon3_stage, native_gpu_addon3_status);
		if (native_gpu_addon3_stage != 5 || native_gpu_addon3_status) return;
		/* The original launchd accepts system jobs from its verified cache.
		 * Keep every original job and let its original loader authenticate this
		 * owner-signed cache through the explicitly supplied trust module. */
		static const char cache_source[] = "/private/var/ngpu/cache";
		static const char cache_point[] = "/System/Library/xpc";
		native_gpu_addon_mount(p, scratch, 0x400, cache_source, sizeof(cache_source),
		    cache_point, sizeof(cache_point), "/System/Library/xpc/foreground_user_endpoints.plist",
		    "/System/Library/xpc/launchd.plist.sig", &native_gpu_addon_stage, &native_gpu_addon_status);
		printf("NabuGPU: userprobe cache_stage=%d cache_status=%d owner_signed=1 original_jobs_preserved=1 render_proof=0\n",
		    native_gpu_addon_stage, native_gpu_addon_status);
		if (native_gpu_addon_stage != 5 || native_gpu_addon_status ||
		    (native_gpu_addon_files < 8 || native_gpu_addon_files > 11)) return;
		/* NABU_GPU_USERPROBE_PLUGIN_V1: the original Metal discovery loads
		 * /System/Library/Extensions/<MetalPluginName>.bundle; present the owner bundle there,
		 * with the sealed A10 bundle still visible below it. Scratch 0xa00..0xb1a, below mkdir's 0xc00. */
		static volatile int nabu_gpu_plugin_stage = 0, nabu_gpu_plugin_status = -1;
		const int publish = native_gpu_addon_files >= 9;
		vnode_t marker = NULLVP;
		if (!publish && !vnode_lookup("/private/var/ngpu/addons/NativeAdrenoMetal.publish", 0, &marker, vfs_context_current())) {
			/* A test-mode addon must not inherit a publish marker from an earlier boot. */
			vnode_put(marker);
			nabu_gpu_plugin_status = EEXIST;
		} else {
			static const char plugin_source[] = "/private/var/ngpu/addons";
			static const char plugin_point[] = "/System/Library/Extensions";
			native_gpu_addon_mount(p, scratch, 0xa00, plugin_source, sizeof(plugin_source), plugin_point,
			    sizeof(plugin_point), "/System/Library/Extensions/AGXMetalA10.bundle",
			    "/System/Library/Extensions/NativeAdrenoMetal.bundle/Info.plist",
			    &nabu_gpu_plugin_stage, &nabu_gpu_plugin_status);
		}
		printf("NabuGPU: userprobe plugin_stage=%d plugin_status=%d publish=%d render_proof=0\n",
		    nabu_gpu_plugin_stage, nabu_gpu_plugin_status, publish);
		return;
	}
#undef nabu_gpu_userprobe_exec_snapshot
'''),
    (r'''	int nabu_probe_target = 0; /* NABU_GPU_USERPROBE_EXEC_V1 */
''',
     r'''	int nabu_probe_target = 0; /* NABU_GPU_USERPROBE_EXEC_V1 */
	int nabu_ui_activation_target = -1;
'''),
    (r'''	nabu_probe_target = !strcmp(excpath, "/usr/bin/nabu-gpu-userprobe") ||
	    !strcmp(excpath, "/private/var/ngpu/bin/nabu-gpu-userprobe");
	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(0, proc_getpid(p), 0);
''',
     r'''	nabu_probe_target = !strcmp(excpath, "/usr/bin/nabu-gpu-userprobe") ||
	    !strcmp(excpath, "/private/var/ngpu/bin/nabu-gpu-userprobe");
	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(0, proc_getpid(p), 0);
	if (nabu_ui_enabled() && !__atomic_load_n(&nabu_ui_closed, __ATOMIC_ACQUIRE)) {
		nabu_ui_activation_target = nabu_ui_target(excpath, 1);
		*nabu_ui_target_out = nabu_ui_activation_target;
		nabu_ui_watch_activation(p, nabu_ui_activation_target, 0, 0);
	}
'''),
    (r'''	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(1, proc_getpid(p), error);
''',
     r'''	if (nabu_probe_target) nabu_gpu_userprobe_exec_note(1, proc_getpid(p), error);
	nabu_ui_watch_activation(p, nabu_ui_activation_target, 1, error);
'''),
    (r'''	boolean_t exec_done = FALSE;
	os_reason_t exec_failure_reason = NULL;
''',
     r'''	boolean_t exec_done = FALSE;
	os_reason_t exec_failure_reason = NULL;
	int nabu_ui_exec_target = -1;
'''),
    (r'''	boolean_t exec_done = FALSE;
	void *inherit = NULL;
''',
     r'''	boolean_t exec_done = FALSE;
	void *inherit = NULL;
	int nabu_ui_exec_target = -1;
'''),
    (r'''	error = exec_activate_image(imgp);
#if defined(HAS_APPLE_PAC)
''',
     r'''	error = nabu_ui_watch_activate_image_v2(imgp, &nabu_ui_exec_target);
#if defined(HAS_APPLE_PAC)
'''),
    (r'''	error = exec_activate_image(imgp);
	/* thread and task ref returned for vfexec case */
''',
     r'''	error = nabu_ui_watch_activate_image_v2(imgp, &nabu_ui_exec_target);
	/* thread and task ref returned for vfexec case */
'''),
    (r'''		error = process_signature(p, imgp);
	}

#if defined(HAS_APPLE_PAC)
''',
     r'''		error = process_signature(p, imgp);
		nabu_ui_watch_signature(p, nabu_ui_exec_target, error, 0);
	}

#if defined(HAS_APPLE_PAC)
'''),
    (r'''		error = process_signature(p, imgp);

		/*
		 * Pay for our earlier safety; deliver the delayed signals from
''',
     r'''		error = process_signature(p, imgp);
		nabu_ui_watch_signature(p, nabu_ui_exec_target, error, spawn_no_exec);

		/*
		 * Pay for our earlier safety; deliver the delayed signals from
'''),
    (r'''		/* wake up the new thread */
		task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
''',
     r'''		/* wake up the new thread */
		nabu_ui_watch_release_ready(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), spawn_no_exec);
		task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
		nabu_ui_watch_released(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), spawn_no_exec);
'''),
    (r'''			/* wake up the new exec thread */
			task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
''',
     r'''			/* wake up the new exec thread */
			nabu_ui_watch_release_ready(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), 0);
			task_clear_return_wait(get_threadtask(imgp->ip_new_thread), clearwait_flags);
			nabu_ui_watch_released(p, imgp->ip_new_thread, nabu_ui_exec_target, error, exec_done && !task_is_exec_copy(get_threadtask(imgp->ip_new_thread)), 0);
'''),
)

EXIT_PAIRS = (
    (r'''	/* NABU_GPU_USERPROBE_EXIT_V1: a successful exit must also leave evidence. */
	extern void nabu_gpu_userprobe_exit_note(int, int);
	nabu_gpu_userprobe_exit_note(proc_getpid(p), rv);
''',
     r'''	/* NABU_GPU_USERPROBE_EXIT_V1: a successful exit must also leave evidence. */
	extern void nabu_gpu_userprobe_exit_note(int, int);
	nabu_gpu_userprobe_exit_note(proc_getpid(p), rv);
	/* NABU_UI_WATCH_EXIT_V1 */
	extern void nabu_ui_watch_exit_note(proc_t, int);
	nabu_ui_watch_exit_note(p, rv);
'''),
)

THREAD_HELPER = r'''/* NABU_UI_WATCH_THREAD_V1: scheduler fields stay in this private osfmk unit. */
int
nabu_ui_watch_thread_state(thread_t thread, uint32_t *state, uint32_t *hint, uint64_t *wait_tag)
{
	if (thread == THREAD_NULL || state == NULL || hint == NULL || wait_tag == NULL) return 2;
	uint64_t event = 0, tag = 0;
	spl_t s = splsched();
	if (!simple_lock_try(&thread->sched_lock, &thread_lck_grp)) {
		splx(s);
		return 1;
	}
	*state = (uint32_t)thread->state;
	*hint = (uint32_t)thread->block_hint;
	event = (uint64_t)thread->wait_event;
	thread_unlock(thread);
	splx(s);
	if (event) {
		tag = event ^ thread_tid(thread);
		tag = (tag ^ (tag >> 30)) * 0xbf58476d1ce4e5b9ULL;
		tag = (tag ^ (tag >> 27)) * 0x94d049bb133111ebULL;
		tag = (tag ^ (tag >> 31)) & 0xffffffff;
	}
	*wait_tag = tag;
	return 0;
}
/* NABU_UI_WATCH_WAIT_V1: optional wait-owner record, never called unless the
 * BSD caller saw nabu-ui-wait-owner=1. Every lock below is a try-lock at
 * splsched; a failed try is reported and nothing waits or spins. XNU's order is
 * turnstile lock -> thread lock and turnstile lock -> inheritor turnstile lock.
 * This path already holds the waiter's thread lock, so its turnstile lock must
 * stay try-only: a try never waits, so it cannot close a lock cycle. While its
 * thread lock is held the waiter cannot leave its turnstile waitq
 * (thread_update_waiting_turnstile_priority_chain), so that turnstile stays
 * live. Each held turnstile lock pins ts_inheritor and the reference the
 * turnstile owns on it (turnstile_stash_inheritor), so the inheritor thread or
 * turnstile stays valid until that lock is dropped. No reference is added,
 * nothing is allocated, no user memory is read, no debugger helper is used.
 * Owner fields: valid, turnstile status, inheritor kind, inheritor TID,
 * same task, inheritor sample, inheritor state, inheritor hint, hops, stop,
 * last inheritor flags. Names: waiter, inheritor (15 bytes, sanitized). */
enum { NABU_UI_WAIT_FIELDS = 11, NABU_UI_WAIT_MAX_HOPS = 3, NABU_UI_WAIT_NAME = 16 };
enum { NABU_UI_WAIT_TS_NONE = 0, NABU_UI_WAIT_TS_BUSY = 1, NABU_UI_WAIT_TS_PRESENT = 2 };
enum { NABU_UI_WAIT_KIND_NONE = 0, NABU_UI_WAIT_KIND_THREAD = 1, NABU_UI_WAIT_KIND_TURNSTILE = 2,
       NABU_UI_WAIT_KIND_WORKQ = 3, NABU_UI_WAIT_KIND_OTHER = 4, NABU_UI_WAIT_KIND_UNREAD = 5 };
enum { NABU_UI_WAIT_SAME_NO = 0, NABU_UI_WAIT_SAME_YES = 1, NABU_UI_WAIT_SAME_UNREAD = 2 };
enum { NABU_UI_WAIT_INH_UNREAD = 0, NABU_UI_WAIT_INH_OK = 1, NABU_UI_WAIT_INH_BUSY = 2,
       NABU_UI_WAIT_INH_SELF = 3 };
enum { NABU_UI_WAIT_STOP_THREAD = 0, NABU_UI_WAIT_STOP_WORKQ = 1, NABU_UI_WAIT_STOP_NONE = 2,
       NABU_UI_WAIT_STOP_NO_TS = 3, NABU_UI_WAIT_STOP_TS_BUSY = 4, NABU_UI_WAIT_STOP_HOP_BUSY = 5,
       NABU_UI_WAIT_STOP_HOP_MAX = 6, NABU_UI_WAIT_STOP_CYCLE = 7, NABU_UI_WAIT_STOP_UNKNOWN = 8 };

static int
nabu_ui_wait_hint(uint32_t hint)
{
	/* PortReceive, PortSend, PortSendInTransit, UserLock,
	 * WorkloopSyncWait and SleepWithInheritor (block_hint.h). */
	return hint == 2 || hint == 4 || hint == 5 || hint == 10 || hint == 16 || hint == 18;
}

static void
nabu_ui_wait_name(thread_t thread, char out[NABU_UI_WAIT_NAME])
{
	/* bsd_getthreadname copies MAXTHREADNAMESIZE bytes from kernel memory that
	 * uthread_destroy frees only after the last thread reference. */
	char raw[MAXTHREADNAMESIZE];
	for (unsigned i = 0; i < MAXTHREADNAMESIZE; ++i) raw[i] = 0;
	thread_get_thread_name(thread, raw);
	unsigned at = 0;
	for (; at + 1 < NABU_UI_WAIT_NAME && raw[at]; ++at) {
		const unsigned char c = (unsigned char)raw[at];
		out[at] = (c > 0x20 && c < 0x7f && c != '=') ? (char)c : '?';
	}
	for (; at < NABU_UI_WAIT_NAME; ++at) out[at] = 0;
}

/* Called with the waiter's scheduler lock held at splsched; returns with that
 * lock still held and every turnstile lock taken here released. */
static void
nabu_ui_wait_owner_locked(thread_t waiter, uint64_t owner[NABU_UI_WAIT_FIELDS],
    char inheritor_name[NABU_UI_WAIT_NAME])
{
	struct turnstile *held[NABU_UI_WAIT_MAX_HOPS + 1];
	unsigned locked = 0, hops = 0;
	owner[0] = 1;
	owner[1] = NABU_UI_WAIT_TS_NONE;
	owner[2] = NABU_UI_WAIT_KIND_UNREAD;
	owner[4] = NABU_UI_WAIT_SAME_UNREAD;
	owner[5] = NABU_UI_WAIT_INH_UNREAD;
	owner[9] = NABU_UI_WAIT_STOP_NO_TS;
	struct turnstile *ts = thread_get_waiting_turnstile(waiter);
	if (ts == TURNSTILE_NULL) return;
	if (!waitq_lock_try(&ts->ts_waitq)) {
		owner[1] = NABU_UI_WAIT_TS_BUSY;
		owner[9] = NABU_UI_WAIT_STOP_TS_BUSY;
		return;
	}
	owner[1] = NABU_UI_WAIT_TS_PRESENT;
	held[locked++] = ts;
	for (;;) {
		void *inheritor = (void *)ts->ts_inheritor;
		const unsigned flags = (unsigned)ts->ts_inheritor_flags;
		owner[10] = flags & 0xff;
		if (inheritor == TURNSTILE_INHERITOR_NULL) {
			owner[2] = NABU_UI_WAIT_KIND_NONE;
			owner[9] = NABU_UI_WAIT_STOP_NONE;
			break;
		}
		if (flags & TURNSTILE_INHERITOR_THREAD) {
			thread_t holder = (thread_t)inheritor;
			owner[2] = NABU_UI_WAIT_KIND_THREAD;
			owner[9] = NABU_UI_WAIT_STOP_THREAD;
			owner[3] = thread_tid(holder);
			owner[4] = get_threadtask(holder) == get_threadtask(waiter) ?
			    NABU_UI_WAIT_SAME_YES : NABU_UI_WAIT_SAME_NO;
			if (holder == waiter) {
				/* Already locked by this path: never try a held lock again. */
				owner[5] = NABU_UI_WAIT_INH_SELF;
				owner[6] = (uint32_t)waiter->state;
				owner[7] = (uint32_t)waiter->block_hint;
			} else if (simple_lock_try(&holder->sched_lock, &thread_lck_grp)) {
				owner[5] = NABU_UI_WAIT_INH_OK;
				owner[6] = (uint32_t)holder->state;
				owner[7] = (uint32_t)holder->block_hint;
				thread_unlock(holder);
			} else {
				owner[5] = NABU_UI_WAIT_INH_BUSY;
			}
			nabu_ui_wait_name(holder, inheritor_name);
			break;
		}
		if (flags & TURNSTILE_INHERITOR_WORKQ) {
			/* A workqueue pointer is not a thread; it is never dereferenced. */
			owner[2] = NABU_UI_WAIT_KIND_WORKQ;
			owner[9] = NABU_UI_WAIT_STOP_WORKQ;
			break;
		}
		if (!(flags & TURNSTILE_INHERITOR_TURNSTILE)) {
			owner[2] = NABU_UI_WAIT_KIND_OTHER;
			owner[9] = NABU_UI_WAIT_STOP_UNKNOWN;
			break;
		}
		struct turnstile *next = (struct turnstile *)inheritor;
		owner[2] = NABU_UI_WAIT_KIND_TURNSTILE;
		if (hops >= NABU_UI_WAIT_MAX_HOPS) {
			owner[9] = NABU_UI_WAIT_STOP_HOP_MAX;
			break;
		}
		unsigned cycle = 0;
		for (unsigned i = 0; i < locked; ++i) cycle |= held[i] == next;
		if (cycle) {
			owner[9] = NABU_UI_WAIT_STOP_CYCLE;
			break;
		}
		if (!waitq_lock_try(&next->ts_waitq)) {
			owner[9] = NABU_UI_WAIT_STOP_HOP_BUSY;
			break;
		}
		held[locked++] = next;
		++hops;
		ts = next;
	}
	owner[8] = hops;
	while (locked) waitq_unlock(&held[--locked]->ts_waitq);
}

/* Sibling of nabu_ui_watch_thread_state with the same lifetime contract: the
 * caller keeps the thread valid. Scheduler fields and the owner walk come from
 * one hold of the waiter's scheduler lock. */
int
nabu_ui_watch_thread_wait_owner(thread_t thread, uint32_t *state, uint32_t *hint,
    uint64_t *wait_tag, uint64_t owner[NABU_UI_WAIT_FIELDS], char names[2][NABU_UI_WAIT_NAME])
{
	if (thread == THREAD_NULL || state == NULL || hint == NULL || wait_tag == NULL ||
	    owner == NULL || names == NULL) return 2;
	for (unsigned i = 0; i < NABU_UI_WAIT_FIELDS; ++i) owner[i] = 0;
	for (unsigned i = 0; i < 2; ++i)
		for (unsigned j = 0; j < NABU_UI_WAIT_NAME; ++j) names[i][j] = 0;
	uint64_t event = 0, tag = 0;
	spl_t s = splsched();
	if (!simple_lock_try(&thread->sched_lock, &thread_lck_grp)) {
		splx(s);
		return 1;
	}
	*state = (uint32_t)thread->state;
	*hint = (uint32_t)thread->block_hint;
	event = (uint64_t)thread->wait_event;
	if ((*state & TH_WAIT) && nabu_ui_wait_hint(*hint))
		nabu_ui_wait_owner_locked(thread, owner, names[1]);
	thread_unlock(thread);
	splx(s);
	if (event) {
		tag = event ^ thread_tid(thread);
		tag = (tag ^ (tag >> 30)) * 0xbf58476d1ce4e5b9ULL;
		tag = (tag ^ (tag >> 27)) * 0x94d049bb133111ebULL;
		tag = (tag ^ (tag >> 31)) & 0xffffffff;
	}
	*wait_tag = tag;
	if (owner[0]) nabu_ui_wait_name(thread, names[0]);
	return 0;
}
/* NABU_UI_WATCH_TASK_V1: anchor reference owns the task lifetime.
 * Task list and scheduler locks are try-only. Copy scalars, release the task
 * lock, then format in the BSD caller; never call the recorder under this lock.
 * Rows: TID, state, hint, thread-specific wait tag, scheduler sample result.
 * Meta: task count, scanned entries, returned rows, omitted rows.
 * Owners and names stay NULL unless the optional wait-owner record is enabled.
 */
static int
nabu_ui_task_scan(thread_t anchor, unsigned rotation, uint64_t rows[32][5], uint32_t meta[4],
    uint64_t owners[32][NABU_UI_WAIT_FIELDS], char names[32][2][NABU_UI_WAIT_NAME])
{
    if (rows == NULL || meta == NULL) return 2;
    for (unsigned i = 0; i < 4; ++i) meta[i] = 0;
    for (unsigned i = 0; i < 32; ++i)
        for (unsigned j = 0; j < 5; ++j) rows[i][j] = 0;
    if (owners != NULL && names != NULL) {
        for (unsigned i = 0; i < 32; ++i) {
            for (unsigned j = 0; j < NABU_UI_WAIT_FIELDS; ++j) owners[i][j] = 0;
            for (unsigned j = 0; j < 2; ++j)
                for (unsigned k = 0; k < NABU_UI_WAIT_NAME; ++k) names[i][j][k] = 0;
        }
    }
    /* thread_deallocate's last-reference path drops this task reference.
     * The retained anchor therefore keeps its task alive during this call. */
    if (anchor == THREAD_NULL) return 2;
    task_t task = get_threadtask(anchor);
    if (task == TASK_NULL) return 2;
    if (!task_lock_try(task)) return 1;
    const uint32_t count = task->thread_count > 0 ? (uint32_t)task->thread_count : 0;
    const uint32_t limit = count < 128 ? count : 128;
    const uint32_t start = limit ? rotation % limit : 0;
    unsigned scanned = 0, returned = 0;
    thread_t thread;
    queue_iterate(&task->threads, thread, thread_t, task_threads) {
        if (scanned >= limit) break;
        const unsigned index = scanned++;
        if ((index + limit - start) % limit >= 32) continue;
        if (returned >= 32) break;
        uint32_t state = 0, hint = 0;
        uint64_t wait = 0;
        const uint64_t tid = thread_tid(thread);
        /* This helper uses one scheduler try-lock, never waits for it, and
         * restores splsched before returning. Task list ownership keeps this
         * thread valid until its scalar fields have been copied. */
        const int sampled = owners == NULL || names == NULL ?
            nabu_ui_watch_thread_state(thread, &state, &hint, &wait) :
            nabu_ui_watch_thread_wait_owner(thread, &state, &hint, &wait,
                owners[returned], names[returned]);
        rows[returned][0] = tid;
        rows[returned][1] = state;
        rows[returned][2] = hint;
        rows[returned][3] = wait;
        rows[returned][4] = (uint64_t)sampled;
        ++returned;
    }
    meta[0] = count;
    meta[1] = scanned;
    meta[2] = returned;
    meta[3] = count > returned ? count - returned : 0;
    task_unlock(task);
    return 0;
}

int
nabu_ui_watch_task_snapshot(thread_t anchor, unsigned rotation,
    uint64_t rows[32][5], uint32_t meta[4])
{
    return nabu_ui_task_scan(anchor, rotation, rows, meta, NULL, NULL);
}

int
nabu_ui_watch_task_wait_snapshot(thread_t anchor, unsigned rotation,
    uint64_t rows[32][5], uint32_t meta[4],
    uint64_t owners[32][NABU_UI_WAIT_FIELDS], char names[32][2][NABU_UI_WAIT_NAME])
{
    if (owners == NULL || names == NULL) {
        /* Clear the scalar outputs without sampling; never fall back silently. */
        (void)nabu_ui_task_scan(THREAD_NULL, rotation, rows, meta, NULL, NULL);
        return 2;
    }
    return nabu_ui_task_scan(anchor, rotation, rows, meta, owners, names);
}
/* NABU_UI_WATCH_CHAIN_V1: nabu-ui-wait-owner=2 records a bounded cross-task
 * owner chain. Entered exactly where the v5 record is, with the waiter's
 * scheduler lock held at splsched; the link-1 record fills the v5 owner fields
 * so the emitted wait-owner row is unchanged. Every lock below is a try-lock;
 * all turnstile and holder locks taken here are released in reverse
 * acquisition order before returning. A recorded holder that is itself in an
 * inheritable wait keeps its scheduler lock and becomes the next link's
 * waiter. Cycle checks cover every held turnstile and every locked thread.
 * No references, no allocation, no blocking locks, no user memory. Bounds:
 * 3 links, 12 turnstile locks, 3 holder locks.
 * Link fields: valid, TID, pid, uniqueid, same task as the first waiter,
 * holder scheduler status, holder state, holder hint, turnstile hops, next
 * code. Names per link: thread, process (15 bytes, sanitized). */
enum { NABU_UI_CHAIN_FIELDS = 10, NABU_UI_CHAIN_LINKS = 3 };
enum { NABU_UI_CHAIN_HOLD_TS = 0, NABU_UI_CHAIN_HOLD_THREAD = 1 };
enum { NABU_UI_CHAIN_NEXT_THREAD = 0, NABU_UI_CHAIN_NEXT_NONE = 1,
       NABU_UI_CHAIN_NEXT_WORKQ = 2, NABU_UI_CHAIN_NEXT_OTHER = 3,
       NABU_UI_CHAIN_NEXT_NOT_WAITING = 4, NABU_UI_CHAIN_NEXT_NO_TS = 5,
       NABU_UI_CHAIN_NEXT_TS_BUSY = 6, NABU_UI_CHAIN_NEXT_HOP_BUSY = 7,
       NABU_UI_CHAIN_NEXT_HOP_MAX = 8, NABU_UI_CHAIN_NEXT_CYCLE = 9,
       NABU_UI_CHAIN_NEXT_LOCK_BUSY = 10, NABU_UI_CHAIN_NEXT_LINK_MAX = 11 };

/* task_best_name copies the process name without locks; it is trusted only
 * after get_bsdtask_info accepted the task's proc pointer, so a task without
 * a proc leaves an empty (printed '-') name here. */
static void
nabu_ui_wait_proc_name(task_t task, char out[NABU_UI_WAIT_NAME])
{
	char raw[33];
	for (unsigned i = 0; i < sizeof(raw); ++i) raw[i] = 0;
	task_best_name(task, raw, sizeof(raw));
	unsigned at = 0;
	for (; at + 1 < NABU_UI_WAIT_NAME && raw[at]; ++at) {
		const unsigned char c = (unsigned char)raw[at];
		out[at] = (c > 0x20 && c < 0x7f && c != '=') ? (char)c : '?';
	}
	for (; at < NABU_UI_WAIT_NAME; ++at) out[at] = 0;
}

/* Called with the waiter's scheduler lock held at splsched; returns with that
 * lock still held and every turnstile/thread lock taken here released. Each
 * held turnstile lock pins its inheritor reference (turnstile_stash_inheritor)
 * exactly as in the v5 walk, so a recorded holder's task and scheduler fields
 * are read while that reference keeps the thread valid. task_pid,
 * get_task_uniqueid and get_bsdtask_info are lock-free field readers; the
 * process name is read only when the task still has a proc. */
static void
nabu_ui_wait_chain_locked(thread_t waiter, uint64_t owner[NABU_UI_WAIT_FIELDS],
    char inheritor_name[NABU_UI_WAIT_NAME],
    uint64_t chain[NABU_UI_CHAIN_LINKS][NABU_UI_CHAIN_FIELDS],
    char chain_names[NABU_UI_CHAIN_LINKS][2][NABU_UI_WAIT_NAME])
{
	struct { void *object; unsigned kind; } held[12 + NABU_UI_CHAIN_LINKS];
	unsigned locked = 0;
	owner[0] = 1;
	owner[1] = NABU_UI_WAIT_TS_NONE;
	owner[2] = NABU_UI_WAIT_KIND_UNREAD;
	owner[4] = NABU_UI_WAIT_SAME_UNREAD;
	owner[5] = NABU_UI_WAIT_INH_UNREAD;
	owner[9] = NABU_UI_WAIT_STOP_NO_TS;
	struct turnstile *ts = thread_get_waiting_turnstile(waiter);
	if (ts == TURNSTILE_NULL) return;
	chain[0][0] = 1;
	chain[0][4] = NABU_UI_WAIT_SAME_UNREAD;
	chain[0][5] = NABU_UI_WAIT_INH_UNREAD;
	if (!waitq_lock_try(&ts->ts_waitq)) {
		owner[1] = NABU_UI_WAIT_TS_BUSY;
		owner[9] = NABU_UI_WAIT_STOP_TS_BUSY;
		chain[0][9] = NABU_UI_CHAIN_NEXT_TS_BUSY;
		return;
	}
	owner[1] = NABU_UI_WAIT_TS_PRESENT;
	held[locked].object = ts;
	held[locked].kind = NABU_UI_CHAIN_HOLD_TS;
	++locked;
	unsigned link = 0;
	for (;;) {
		uint64_t *rec = chain[link];
		char (*names)[NABU_UI_WAIT_NAME] = chain_names[link];
		unsigned hops = 0;
		thread_t holder = THREAD_NULL;
		unsigned next = NABU_UI_CHAIN_NEXT_OTHER;
		rec[0] = 1;
		rec[2] = UINT64_MAX;
		rec[3] = UINT64_MAX;
		rec[4] = NABU_UI_WAIT_SAME_UNREAD;
		rec[5] = NABU_UI_WAIT_INH_UNREAD;
		for (;;) {
			void *inheritor = (void *)ts->ts_inheritor;
			const unsigned flags = (unsigned)ts->ts_inheritor_flags;
			if (link == 0) owner[10] = flags & 0xff;
			if (inheritor == TURNSTILE_INHERITOR_NULL) {
				next = NABU_UI_CHAIN_NEXT_NONE;
				if (link == 0) {
					owner[2] = NABU_UI_WAIT_KIND_NONE;
					owner[9] = NABU_UI_WAIT_STOP_NONE;
				}
				break;
			}
			if (flags & TURNSTILE_INHERITOR_THREAD) {
				holder = (thread_t)inheritor;
				next = NABU_UI_CHAIN_NEXT_THREAD;
				break;
			}
			if (flags & TURNSTILE_INHERITOR_WORKQ) {
				next = NABU_UI_CHAIN_NEXT_WORKQ;
				if (link == 0) {
					owner[2] = NABU_UI_WAIT_KIND_WORKQ;
					owner[9] = NABU_UI_WAIT_STOP_WORKQ;
				}
				break;
			}
			if (!(flags & TURNSTILE_INHERITOR_TURNSTILE)) {
				next = NABU_UI_CHAIN_NEXT_OTHER;
				if (link == 0) {
					owner[2] = NABU_UI_WAIT_KIND_OTHER;
					owner[9] = NABU_UI_WAIT_STOP_UNKNOWN;
				}
				break;
			}
			struct turnstile *hop = (struct turnstile *)inheritor;
			if (link == 0) owner[2] = NABU_UI_WAIT_KIND_TURNSTILE;
			if (hops >= NABU_UI_WAIT_MAX_HOPS) {
				next = NABU_UI_CHAIN_NEXT_HOP_MAX;
				if (link == 0) owner[9] = NABU_UI_WAIT_STOP_HOP_MAX;
				break;
			}
			unsigned cycle = 0;
			for (unsigned i = 0; i < locked; ++i)
				cycle |= held[i].kind == NABU_UI_CHAIN_HOLD_TS &&
				    held[i].object == (void *)hop;
			if (cycle) {
				next = NABU_UI_CHAIN_NEXT_CYCLE;
				if (link == 0) owner[9] = NABU_UI_WAIT_STOP_CYCLE;
				break;
			}
			if (!waitq_lock_try(&hop->ts_waitq)) {
				next = NABU_UI_CHAIN_NEXT_HOP_BUSY;
				if (link == 0) owner[9] = NABU_UI_WAIT_STOP_HOP_BUSY;
				break;
			}
			held[locked].object = hop;
			held[locked].kind = NABU_UI_CHAIN_HOLD_TS;
			++locked;
			++hops;
			ts = hop;
		}
		rec[8] = hops;
		if (link == 0) owner[8] = hops;
		if (holder == THREAD_NULL) {
			rec[9] = next;
			break;
		}
		/* Terminal thread H: identity reads while the held turnstile pins it.
		 * The link-1 record mirrors these fields into the v5 owner record. */
		rec[1] = thread_tid(holder);
		task_t htask = get_threadtask(holder);
		rec[4] = htask == get_threadtask(waiter) ? NABU_UI_WAIT_SAME_YES :
		    NABU_UI_WAIT_SAME_NO;
		if (htask != TASK_NULL) {
			rec[2] = (uint64_t)(long long)task_pid(htask);
			rec[3] = get_task_uniqueid(htask);
			if (get_bsdtask_info(htask) != NULL)
				nabu_ui_wait_proc_name(htask, names[1]);
		}
		nabu_ui_wait_name(holder, names[0]);
		if (link == 0) {
			owner[2] = NABU_UI_WAIT_KIND_THREAD;
			owner[3] = rec[1];
			owner[4] = rec[4];
			owner[9] = NABU_UI_WAIT_STOP_THREAD;
			for (unsigned i = 0; i < NABU_UI_WAIT_NAME; ++i)
				inheritor_name[i] = names[0][i];
		}
		unsigned self = holder == waiter;
		for (unsigned i = 0; i < locked; ++i)
			self |= held[i].kind == NABU_UI_CHAIN_HOLD_THREAD &&
			    held[i].object == (void *)holder;
		if (self) {
			/* Already locked by this walk: never try a held lock again. */
			rec[5] = NABU_UI_WAIT_INH_SELF;
			rec[6] = (uint32_t)holder->state;
			rec[7] = (uint32_t)holder->block_hint;
			rec[9] = NABU_UI_CHAIN_NEXT_CYCLE;
			if (link == 0) {
				owner[5] = NABU_UI_WAIT_INH_SELF;
				owner[6] = rec[6];
				owner[7] = rec[7];
			}
			break;
		}
		if (!simple_lock_try(&holder->sched_lock, &thread_lck_grp)) {
			rec[5] = NABU_UI_WAIT_INH_BUSY;
			rec[9] = NABU_UI_CHAIN_NEXT_LOCK_BUSY;
			if (link == 0) owner[5] = NABU_UI_WAIT_INH_BUSY;
			break;
		}
		held[locked].object = holder;
		held[locked].kind = NABU_UI_CHAIN_HOLD_THREAD;
		++locked;
		rec[5] = NABU_UI_WAIT_INH_OK;
		rec[6] = (uint32_t)holder->state;
		rec[7] = (uint32_t)holder->block_hint;
		if (link == 0) {
			owner[5] = NABU_UI_WAIT_INH_OK;
			owner[6] = rec[6];
			owner[7] = rec[7];
		}
		if (!((holder->state & TH_WAIT) && nabu_ui_wait_hint(holder->block_hint))) {
			rec[9] = NABU_UI_CHAIN_NEXT_NOT_WAITING;
			break;
		}
		if (link + 1 >= NABU_UI_CHAIN_LINKS) {
			rec[9] = NABU_UI_CHAIN_NEXT_LINK_MAX;
			break;
		}
		ts = thread_get_waiting_turnstile(holder);
		if (ts == TURNSTILE_NULL) {
			rec[9] = NABU_UI_CHAIN_NEXT_NO_TS;
			break;
		}
		rec[9] = NABU_UI_CHAIN_NEXT_THREAD;
		unsigned held_ts = 0;
		for (unsigned i = 0; i < locked; ++i)
			held_ts |= held[i].kind == NABU_UI_CHAIN_HOLD_TS &&
			    held[i].object == (void *)ts;
		/* A held turnstile is never tried again: that is a cycle, not busy. */
		if (held_ts || !waitq_lock_try(&ts->ts_waitq)) {
			rec = chain[link + 1];
			rec[0] = 1;
			rec[2] = UINT64_MAX;
			rec[3] = UINT64_MAX;
			rec[4] = NABU_UI_WAIT_SAME_UNREAD;
			rec[5] = NABU_UI_WAIT_INH_UNREAD;
			rec[9] = held_ts ? NABU_UI_CHAIN_NEXT_CYCLE : NABU_UI_CHAIN_NEXT_TS_BUSY;
			break;
		}
		held[locked].object = ts;
		held[locked].kind = NABU_UI_CHAIN_HOLD_TS;
		++locked;
		++link;
	}
	while (locked) {
		--locked;
		if (held[locked].kind == NABU_UI_CHAIN_HOLD_TS)
			waitq_unlock(&((struct turnstile *)held[locked].object)->ts_waitq);
		else
			thread_unlock((thread_t)held[locked].object);
	}
}

/* v6 sibling of nabu_ui_watch_thread_wait_owner: identical scalars and v5
 * owner output plus the bounded chain records, from one hold of the waiter's
 * scheduler lock. */
int
nabu_ui_watch_thread_wait_chain(thread_t thread, uint32_t *state, uint32_t *hint,
    uint64_t *wait_tag, uint64_t owner[NABU_UI_WAIT_FIELDS],
    char names[2][NABU_UI_WAIT_NAME],
    uint64_t chain[NABU_UI_CHAIN_LINKS][NABU_UI_CHAIN_FIELDS],
    char chain_names[NABU_UI_CHAIN_LINKS][2][NABU_UI_WAIT_NAME])
{
	if (thread == THREAD_NULL || state == NULL || hint == NULL || wait_tag == NULL ||
	    owner == NULL || names == NULL || chain == NULL || chain_names == NULL) return 2;
	for (unsigned i = 0; i < NABU_UI_WAIT_FIELDS; ++i) owner[i] = 0;
	for (unsigned i = 0; i < 2; ++i)
		for (unsigned j = 0; j < NABU_UI_WAIT_NAME; ++j) names[i][j] = 0;
	for (unsigned i = 0; i < NABU_UI_CHAIN_LINKS; ++i) {
		for (unsigned j = 0; j < NABU_UI_CHAIN_FIELDS; ++j) chain[i][j] = 0;
		for (unsigned j = 0; j < 2; ++j)
			for (unsigned k = 0; k < NABU_UI_WAIT_NAME; ++k) chain_names[i][j][k] = 0;
	}
	uint64_t event = 0, tag = 0;
	spl_t s = splsched();
	if (!simple_lock_try(&thread->sched_lock, &thread_lck_grp)) {
		splx(s);
		return 1;
	}
	*state = (uint32_t)thread->state;
	*hint = (uint32_t)thread->block_hint;
	event = (uint64_t)thread->wait_event;
	if ((*state & TH_WAIT) && nabu_ui_wait_hint(*hint))
		nabu_ui_wait_chain_locked(thread, owner, names[1], chain, chain_names);
	thread_unlock(thread);
	splx(s);
	if (event) {
		tag = event ^ thread_tid(thread);
		tag = (tag ^ (tag >> 30)) * 0xbf58476d1ce4e5b9ULL;
		tag = (tag ^ (tag >> 27)) * 0x94d049bb133111ebULL;
		tag = (tag ^ (tag >> 31)) & 0xffffffff;
	}
	*wait_tag = tag;
	if (owner[0]) nabu_ui_wait_name(thread, names[0]);
	return 0;
}

/* Task scan for the chain record: identical bounds and rotation to
 * nabu_ui_task_scan, kept separate so the v5 entry points stay unchanged. */
static int
nabu_ui_task_scan_chain(thread_t anchor, unsigned rotation, uint64_t rows[32][5],
    uint32_t meta[4], uint64_t owners[32][NABU_UI_WAIT_FIELDS],
    char names[32][2][NABU_UI_WAIT_NAME],
    uint64_t chain[32][NABU_UI_CHAIN_LINKS][NABU_UI_CHAIN_FIELDS],
    char chain_names[32][NABU_UI_CHAIN_LINKS][2][NABU_UI_WAIT_NAME])
{
    if (rows == NULL || meta == NULL) return 2;
    for (unsigned i = 0; i < 4; ++i) meta[i] = 0;
    for (unsigned i = 0; i < 32; ++i)
        for (unsigned j = 0; j < 5; ++j) rows[i][j] = 0;
    if (owners == NULL || names == NULL || chain == NULL || chain_names == NULL) return 2;
    for (unsigned i = 0; i < 32; ++i) {
        for (unsigned j = 0; j < NABU_UI_WAIT_FIELDS; ++j) owners[i][j] = 0;
        for (unsigned j = 0; j < 2; ++j)
            for (unsigned k = 0; k < NABU_UI_WAIT_NAME; ++k) names[i][j][k] = 0;
        for (unsigned j = 0; j < NABU_UI_CHAIN_LINKS; ++j) {
            for (unsigned k = 0; k < NABU_UI_CHAIN_FIELDS; ++k) chain[i][j][k] = 0;
            for (unsigned k = 0; k < 2; ++k)
                for (unsigned n = 0; n < NABU_UI_WAIT_NAME; ++n)
                    chain_names[i][j][k][n] = 0;
        }
    }
    /* thread_deallocate's last-reference path drops this task reference.
     * The retained anchor therefore keeps its task alive during this call. */
    if (anchor == THREAD_NULL) return 2;
    task_t task = get_threadtask(anchor);
    if (task == TASK_NULL) return 2;
    if (!task_lock_try(task)) return 1;
    const uint32_t count = task->thread_count > 0 ? (uint32_t)task->thread_count : 0;
    const uint32_t limit = count < 128 ? count : 128;
    const uint32_t start = limit ? rotation % limit : 0;
    unsigned scanned = 0, returned = 0;
    thread_t thread;
    queue_iterate(&task->threads, thread, thread_t, task_threads) {
        if (scanned >= limit) break;
        const unsigned index = scanned++;
        if ((index + limit - start) % limit >= 32) continue;
        if (returned >= 32) break;
        uint32_t state = 0, hint = 0;
        uint64_t wait = 0;
        const uint64_t tid = thread_tid(thread);
        /* Same try-only sampler contract as the v5 scan; each returned row
         * also fills its chain links under the same single scheduler hold. */
        const int sampled =
            nabu_ui_watch_thread_wait_chain(thread, &state, &hint, &wait,
                owners[returned], names[returned], chain[returned],
                chain_names[returned]);
        rows[returned][0] = tid;
        rows[returned][1] = state;
        rows[returned][2] = hint;
        rows[returned][3] = wait;
        rows[returned][4] = (uint64_t)sampled;
        ++returned;
    }
    meta[0] = count;
    meta[1] = scanned;
    meta[2] = returned;
    meta[3] = count > returned ? count - returned : 0;
    task_unlock(task);
    return 0;
}

int
nabu_ui_watch_task_wait_chain_snapshot(thread_t anchor, unsigned rotation,
    uint64_t rows[32][5], uint32_t meta[4],
    uint64_t owners[32][NABU_UI_WAIT_FIELDS], char names[32][2][NABU_UI_WAIT_NAME],
    uint64_t chain[32][NABU_UI_CHAIN_LINKS][NABU_UI_CHAIN_FIELDS],
    char chain_names[32][NABU_UI_CHAIN_LINKS][2][NABU_UI_WAIT_NAME])
{
    if (owners == NULL || names == NULL || chain == NULL || chain_names == NULL) {
        /* Clear the scalar outputs without sampling; never fall back silently. */
        (void)nabu_ui_task_scan(THREAD_NULL, rotation, rows, meta, NULL, NULL);
        return 2;
    }
    return nabu_ui_task_scan_chain(anchor, rotation, rows, meta, owners, names,
        chain, chain_names);
}
'''

THREAD_ANCHORS = (r'''/* Drop a thread refcount safely without triggering a zfree */
void
thread_deallocate_safe(thread_t thread)
{
''',)


def thread_source(text, restore=False):
    pairs = tuple((before, THREAD_HELPER + before) for before in THREAD_ANCHORS)
    marker = '/* NABU_UI_WATCH_THREAD_V1:'
    if marker in text:
        if text.count(THREAD_HELPER) != 1 or any(text.count(after) != 1 for _, after in pairs):
            raise ValueError('UI watch thread source changed after patching')
        if restore:
            for before, after in reversed(pairs):
                text = _once(text, after, before)
        return text
    if restore:
        return text
    for before, after in pairs:
        text = _once(text, before, after)
    return text

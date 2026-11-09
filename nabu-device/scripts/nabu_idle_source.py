"""Prepare an explicit nabu shallow-idle cache isolation candidate."""
import hashlib
from pathlib import Path


MACRO = 'XNU_NABU_SHALLOW_IDLE'
MARKER = '#define NABU_IDLE_SOURCE_VERSION 1\n'
SIGNATURE = 'void __attribute__((noreturn))\ncpu_idle(void)\n{\n'
CACHE = '#if !defined(APPLE_ARM64_ARCH_FAMILY)\n\t\tplatform_cache_idle_enter();\n#endif\n'
BEFORE = '\t\t__builtin_arm_dsb(DSB_SY);\n#if HAS_RETENTION_STATE\n'
AFTER = '\t\t__builtin_arm_wfi();\n#endif\n'
CONTRACT = {
    'version': 1,
    'macro': MACRO,
    'default': 0,
    'slots': 8,
    'snapshot_words': 5,
    'snapshot': 'four counters followed by last stage; independent volatile reads',
    'stages': ['cache_before', 'cache_after', 'wfi_before', 'wfi_after'],
    'cache_counters': 'bracket the skipped generic cache call; do not claim cache maintenance occurred',
    'producer_context': 'ordinary cpu_idle context with its original interrupt and preemption state',
    'consumer_context': 'existing ESP writer normal thread, outside transport and console locks',
    'changes_dma_cache_apis': False,
    'changes_interrupt_state': False,
    'changes_scheduler': False,
    'changes_writer': False,
    'runtime_qualified': False,
    'symbols': ['_nabu_idle_note', '_nabu_idle_snapshot', '_nabu_idle_counters', '_nabu_idle_identity'],
}
HELPER = r'''#define NABU_IDLE_SOURCE_VERSION 1
#ifndef XNU_NABU_SHALLOW_IDLE
#define XNU_NABU_SHALLOW_IDLE 0
#endif
#if XNU_NABU_SHALLOW_IDLE != 0 && XNU_NABU_SHALLOW_IDLE != 1
#error XNU_NABU_SHALLOW_IDLE_must_be_zero_or_one
#endif
#if XNU_NABU_SHALLOW_IDLE && defined(APPLE_ARM64_ARCH_FAMILY)
#error XNU_NABU_SHALLOW_IDLE_requires_generic_arm64
#endif
#if XNU_NABU_SHALLOW_IDLE
const char nabu_idle_identity[] __attribute__((used)) =
    "NABUIDLE_SOURCE_SHA256=__NABU_SOURCE_ID__";
volatile uint64_t nabu_idle_counters[8][5];
unsigned nabu_idle_snapshot(unsigned slot, uint64_t *output, unsigned words);

static __attribute__((noinline, used)) void
nabu_idle_note(unsigned stage, unsigned slot)
{
    if (stage >= 4 || slot >= 8) return;
    nabu_idle_counters[slot][stage]++;
    nabu_idle_counters[slot][4] = stage + 1;
}

__attribute__((noinline, used)) unsigned
nabu_idle_snapshot(unsigned slot, uint64_t *output, unsigned words)
{
    if (slot >= 8 || !output || words < 5) return 0;
    for (unsigned index = 0; index < 5; index++)
        output[index] = nabu_idle_counters[slot][index];
    return 1;
}
#endif

'''
CACHE_NEW = '''#if !defined(APPLE_ARM64_ARCH_FAMILY)
#if XNU_NABU_SHALLOW_IDLE
\t\tnabu_idle_note(0, cpu_data_ptr->cpu_number);
\t\tnabu_idle_note(1, cpu_data_ptr->cpu_number);
#else
\t\tplatform_cache_idle_enter();
#endif
#endif
'''
BEFORE_NEW = '''#if XNU_NABU_SHALLOW_IDLE
\t\tnabu_idle_note(2, cpu_data_ptr->cpu_number);
#endif
''' + BEFORE
AFTER_NEW = AFTER + '''#if XNU_NABU_SHALLOW_IDLE
\t\tnabu_idle_note(3, cpu_data_ptr->cpu_number);
#endif
'''


def identity():
    return hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def function(text):
    if text.count(SIGNATURE) != 1:
        raise ValueError('Expected unique noreturn cpu_idle definition')
    start = text.index(SIGNATURE)
    end = text.find('\n}\n', start)
    if end < 0:
        raise ValueError('Missing cpu_idle closing boundary')
    return text[start:end + 3]


def _edit(text, restore):
    helper = HELPER.replace('__NABU_SOURCE_ID__', identity())
    pairs = [(CACHE, CACHE_NEW), (BEFORE, BEFORE_NEW), (AFTER, AFTER_NEW)]
    body = function(text)
    for original, changed in pairs:
        before, after = (changed, original) if restore else (original, changed)
        if body.count(before) != 1:
            raise ValueError('Nabu idle production source drift: ' + before[:80])
        body = body.replace(before, after, 1)
    original_body = function(text)
    result = text.replace(original_body, body, 1)
    if restore:
        if result.count(helper + SIGNATURE) != 1:
            raise ValueError('Nabu idle helper or identity drift')
        return result.replace(helper + SIGNATURE, SIGNATURE, 1)
    return result.replace(SIGNATURE, helper + SIGNATURE, 1)


def source(text, enabled=False, restore=False):
    if type(enabled) is not bool or type(restore) is not bool:
        raise ValueError('Nabu idle source flags must be Boolean')
    newline = '\r\n' if '\r\n' in text else '\n'
    if newline == '\r\n' and text.count('\r\n') != text.count('\n'):
        raise ValueError('Mixed source line endings')
    normalized = text.replace('\r\n', '\n')
    present = MARKER in normalized
    if not present and ('NABU_IDLE_SOURCE_VERSION' in normalized or 'nabu_idle_' in normalized):
        raise ValueError('Unrecognized nabu idle injection')
    if present:
        baseline = _edit(normalized, True)
        if _edit(baseline, False) != normalized:
            raise ValueError('Nabu idle injected body drift')
        result = normalized if enabled and not restore else baseline
    else:
        result = _edit(normalized, False) if enabled and not restore else normalized
    return result.replace('\n', newline)


def metadata(text):
    restored = source(text, restore=True)
    if restored == text or source(restored, enabled=True) != text:
        raise ValueError('Missing nabu idle production injection')
    return dict(
        enabled=True, compiled=True, contract=CONTRACT,
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        embedded_source_identity=identity(),
        actual_source_sha256=hashlib.sha256(text.encode()).hexdigest(),
        original_source_sha256=hashlib.sha256(restored.encode()).hexdigest(),
        runtime_qualified=False,
    )

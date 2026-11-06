"""Bind nabu's seeded Data overlay to explicit initialization and checked GPT."""
import hashlib
from pathlib import Path


CONTRACT = {'version': 1, 'mode_argument': 'nabu-data-persist', 'default_mode': 0,
            'tail_argument': 'nabu-data-tail-lba', 'reset_argument': 'sheng-data-reset',
            'initialization_requires_reset': True, 'gpt_check_before_open': True,
            'runtime_qualified': False}

POLICY = r'''
extern "C" __attribute__((noinline, used)) bool nabu_data_persist_allow_open(
    int header, unsigned mode, bool reset)
{
  IOLog("NABUDATA_SOURCE_SHA256=__SOURCE_ID__ mode=%u header=%d reset=%u\n",
        mode, header, unsigned(reset));
  // A normal resume must never silently replace a blank, damaged or foreign seed.
  // Read-only probes can report any header, but cannot initialize it.
  return mode == 1 || (mode == 2 && (header == 0 || reset));
}

'''

OPEN_OLD = '''        persist::Open result = overlayBits && stage ? overlay.open(ops, pages, seedHash, mode == 1, overlayBits, discardRequested())
                                                          : persist::Open::Failed;'''
OPEN_NEW = '''        uint8_t headerBlock[persist::kBlock];
        bool allowed = overlayBits && stage && native_data_persist_gpt == 0 &&
                       ops.read(0, 1, headerBlock);
        if (allowed) {
          overlay.header = persist::checkHeader(headerBlock, pages, seedHash, nullptr);
          allowed = nabu_data_persist_allow_open(overlay.header, mode, discardRequested());
        }
        persist::Open result = allowed ? overlay.open(ops, pages, seedHash, mode == 1, overlayBits, discardRequested())
                                      : persist::Open::Failed;'''

AFTER_OLD = '        native_data_persist_gpt_after = native_ufs_store_gpt_check();\n'
AFTER_NEW = AFTER_OLD + '''        if (native_data_persist_gpt_after != 0) {
          overlay.active = false;
          directFailed = true;
          native_data_persist_state = 4;
        }
'''

UNLOCK_OLD = '    IOLockUnlock(gate);\n  }\n\n  bool available()'
UNLOCK_NEW = '''    if (mode) {
      IOLog("NABU DATA STORE mode=%u state=%u header=%u gpt=%u after=%u first=%llu pages=%llu present=%llu loaded=%llu errors=%llu\\n",
            mode, unsigned(native_data_persist_state), unsigned(native_data_persist_header),
            unsigned(native_data_persist_gpt), unsigned(native_data_persist_gpt_after),
            (unsigned long long)native_data_persist_first_lba,
            (unsigned long long)native_data_persist_pages, (unsigned long long)native_data_persist_present,
            (unsigned long long)native_data_persist_loaded, (unsigned long long)native_data_persist_errors);
    }
    IOLockUnlock(gate);
  }

  bool available()'''


def identity():
    return hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('NativeRamBlock nabu persistence source drift: ' + old[:90])
    return text.replace(old, new, 1)


def source(text):
    text = once(text, 'extern "C" {\n', POLICY.replace('__SOURCE_ID__', identity()) + 'extern "C" {\n')
    text = once(text, OPEN_OLD, OPEN_NEW)
    text = once(text, AFTER_OLD, AFTER_NEW)
    return once(text, UNLOCK_OLD, UNLOCK_NEW)


def metadata(text):
    if text.count(POLICY.replace('__SOURCE_ID__', identity())) != 1 or OPEN_NEW not in text:
        raise ValueError('Missing nabu persistence source contract')
    return dict(contract=CONTRACT, generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                embedded_source_identity=identity(), actual_source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                symbol='_nabu_data_persist_allow_open', runtime_qualified=False)

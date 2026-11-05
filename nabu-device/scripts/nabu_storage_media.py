"""Publish nonrotational media characteristics without changing storage I/O policy."""
import hashlib
from pathlib import Path

CONTRACT = {
    'version': 1,
    'property': 'Device Characteristics',
    'key': 'Medium Type',
    'value': 'Solid State',
    'before_parent_start': True,
    'preserves_existing_characteristics': True,
    'changes_write_protection': False,
    'changes_persistence': False,
}
ANCHORS = {
    'ram': 'bool NativeRamBlock::start(IOService *provider)\n{\n',
    'ufs': 'bool NativeUfsBlock::start (IOService *provider)\n{\n',
}
HELPER = r'''#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSString.h>

extern "C" const char nabu___NABU_KIND___storage_media_identity[] __attribute__((used)) =
    "NABUMEDIA_SOURCE_SHA256=__NABU_SOURCE_ID__";

extern "C" __attribute__((noinline)) bool
nabu___NABU_KIND___publish_solid_state(IOService *device)
{
  OSObject *property = device->getProperty("Device Characteristics");
  OSDictionary *existing = OSDynamicCast(OSDictionary, property);
  if (property && !existing) return false;
  OSDictionary *characteristics = existing ? OSDictionary::withDictionary(existing) : OSDictionary::withCapacity(1);
  if (!characteristics) return false;
  OSString *medium = OSString::withCString("Solid State");
  const bool published = medium && characteristics->setObject("Medium Type", medium) &&
      device->setProperty("Device Characteristics", characteristics);
  if (medium) medium->release();
  characteristics->release();
  return published;
}

'''


def identity():
    return hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def fragments(kind):
    if kind not in ANCHORS:
        raise ValueError('Unknown storage media target: ' + kind)
    helper = HELPER.replace('__NABU_KIND__', kind).replace('__NABU_SOURCE_ID__', identity())
    call = f'  if (!nabu_{kind}_publish_solid_state(this)) return false;\n'
    return ANCHORS[kind], helper + ANCHORS[kind] + call


def source(text, kind, restore=False):
    before, after = fragments(kind)
    symbol = f'nabu_{kind}_publish_solid_state'
    if symbol in text:
        if text.count(after) != 1:
            raise ValueError('Storage media helper changed after preparation')
        return text.replace(after, before, 1) if restore else text
    if restore:
        return text
    if text.count(before) != 1:
        raise ValueError('Expected one storage start anchor for ' + kind)
    return text.replace(before, after, 1)


def metadata(kind, text):
    _, injected = fragments(kind)
    if text.count(injected) != 1:
        raise ValueError('Cannot bind a missing storage media helper')
    return dict(contract=CONTRACT, kind=kind, generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                embedded_source_identity=identity(), symbol=f'_nabu_{kind}_publish_solid_state',
                actual_source_sha256=hashlib.sha256(text.encode()).hexdigest(), runtime_qualified=False)

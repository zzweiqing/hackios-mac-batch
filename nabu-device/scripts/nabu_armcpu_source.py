"""Select the timer INTID from the board's ADT, preserving the legacy default."""

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


def patch_source(text):
    for old, new in (
            ('static const uint32_t kSgiPpiEnable = 0xffffU | (1U << 27);\n', TIMER_HELPER),
            ('  armcpu_gic_stride = static_cast<uint32_t> (gRedistStride);\n',
             TIMER_PROPERTY + '  armcpu_gic_stride = static_cast<uint32_t> (gRedistStride);\n'),
            ('    if ((id & 0xffffff) == 27) {\n', '    if ((id & 0xffffff) == gTimerIntid) {\n')):
        if text.count(old) != 1:
            raise ValueError('ArmCpu timer source drift: ' + old[:90])
        text = text.replace(old, new, 1)
    return text

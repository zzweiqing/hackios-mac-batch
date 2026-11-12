/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Bounded wire codecs shared by the kernel control path and host harnesses.
 * Protocol reference: ios-flame 745c4341af86089efb0df851fa8a27fb8face624,
 * phone/wifi/{link,qmi,rmtfs,pdmapper,tftp,wlfw}.c, and Linux QMI/QRTR.
 */
#ifndef NABU_WIFI_PROTOCOL_H
#define NABU_WIFI_PROTOCOL_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace nabu_wifi {
namespace wire {
inline uint16_t le16(const uint8_t *p) { return uint16_t(p[0]) | uint16_t(p[1]) << 8; }
inline uint32_t le32(const uint8_t *p) { return uint32_t(le16(p)) | uint32_t(le16(p + 2)) << 16; }
inline uint64_t le64(const uint8_t *p) { return uint64_t(le32(p)) | uint64_t(le32(p + 4)) << 32; }
inline void put16(uint8_t *p, uint16_t v) { p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); }
inline void put32(uint8_t *p, uint32_t v) { put16(p, uint16_t(v)); put16(p + 2, uint16_t(v >> 16)); }
inline void put64(uint8_t *p, uint64_t v) { put32(p, uint32_t(v)); put32(p + 4, uint32_t(v >> 32)); }
inline uint16_t be16(const uint8_t *p) { return uint16_t(p[0]) << 8 | p[1]; }
inline void putBe16(uint8_t *p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }

enum { kPacketBytes = 17408, kQmiRequest = 0, kQmiResponse = 2, kQmiIndication = 4 };
enum QrtrType { Data = 1, Hello, Bye, NewServer, DelServer, DelClient, ResumeTx,
                Exit, Ping, NewLookup, DelLookup };
enum GlinkCommand { Version = 0, VersionAck, Open, Close, OpenAck, Intent,
                    RxDone, IntentRequest, IntentRequestAck, TxData,
                    CloseAck = 11, TxDataCont, ReadNotify, RxDoneReuse, Signals };
static const uint32_t kAppsNode = 1, kControlPort = 0xfffffffeu, kBroadcastNode = 0xffffffffu;
static const uint32_t kRmtfsPort = 0x10, kPdPort = 0x11, kTftpPort = 0x12, kWlfwPort = 0x13;
static const uint32_t kWlfwDaemonPort = 0x14;

struct QrtrPacket {
    uint32_t type, source_node, source_port, destination_node, destination_port, confirm;
    const uint8_t *payload;
    size_t bytes;
    static bool parse(const uint8_t *p, size_t n, QrtrPacket &out) {
        if (!p || n < 32 || le32(p) != 1 || n > kPacketBytes) return false;
        const size_t bytes = le32(p + 20);
        if (bytes > n - 32 || ((bytes + 3) & ~size_t(3)) != n - 32 || le32(p + 16) > 1) return false;
        for (size_t i = 32 + bytes; i < n; ++i) if (p[i]) return false;
        out = QrtrPacket{le32(p + 4), le32(p + 8), le32(p + 12),
                         le32(p + 24), le32(p + 28), le32(p + 16), p + 32, bytes};
        return out.type >= Data && out.type <= DelLookup;
    }
};

struct QmiMessage {
    uint8_t type;
    uint16_t transaction, id;
    const uint8_t *tlvs;
    size_t bytes;
    static bool parse(const uint8_t *p, size_t n, QmiMessage &out) {
        if (!p || n < 7 || n - 7 != le16(p + 5) ||
            (p[0] != kQmiRequest && p[0] != kQmiResponse && p[0] != kQmiIndication)) return false;
        /* Reject duplicate tags, including otherwise-unknown optional fields. */
        uint8_t seen[32] = {};
        for (size_t at = 7; at < n;) {
            if (n - at < 3) return false;
            const unsigned tag = p[at];
            const size_t length = le16(p + at + 1);
            if ((seen[tag / 8] & (1u << (tag % 8))) || length > n - at - 3) return false;
            seen[tag / 8] |= uint8_t(1u << (tag % 8));
            at += 3 + length;
        }
        out = QmiMessage{p[0], le16(p + 1), le16(p + 3), p + 7, n - 7};
        return true;
    }
    const uint8_t *get(uint8_t tag, size_t &length) const {
        length = 0;
        for (size_t at = 0; at < bytes;) {
            const size_t n = le16(tlvs + at + 1);
            if (tlvs[at] == tag) { length = n; return tlvs + at + 3; }
            at += 3 + n;
        }
        return nullptr;
    }
    bool u32(uint8_t tag, uint32_t &value) const {
        size_t n;
        const uint8_t *p = get(tag, n);
        if (!p || n != 4) return false;
        value = le32(p);
        return true;
    }
    bool result(uint16_t &error) const {
        size_t n;
        const uint8_t *p = get(2, n);
        if (!p || n != 4 || le16(p) > 1) return false;
        error = le16(p + 2);
        return le16(p) == 0 && error == 0;
    }
};

template <size_t Capacity>
class QmiBuffer {
public:
    uint8_t data[Capacity];
    size_t bytes;
    QmiBuffer(uint8_t type, uint16_t txn, uint16_t id) : data{}, bytes(7) {
        reset(type, txn, id);
    }
    void reset(uint8_t type, uint16_t txn, uint16_t id) {
        static_assert(Capacity >= 7 && Capacity <= 65535, "Bounded QMI buffer capacity");
        memset(data, 0, 7);
        bytes = 7;
        data[0] = type; put16(data + 1, txn); put16(data + 3, id);
    }
    bool tlv(uint8_t tag, const void *value, size_t n) {
        if (bytes > sizeof(data) || n > sizeof(data) - bytes || n + 3 > sizeof(data) - bytes || (n && !value)) {
            bytes = sizeof(data) + 1;
            return false;
        }
        data[bytes] = tag; put16(data + bytes + 1, uint16_t(n));
        if (n) memcpy(data + bytes + 3, value, n);
        bytes += 3 + n;
        return true;
    }
    void u32(uint8_t tag, uint32_t value) { uint8_t p[4]; put32(p, value); tlv(tag, p, 4); }
    void u64(uint8_t tag, uint64_t value) { uint8_t p[8]; put64(p, value); tlv(tag, p, 8); }
    void result(uint16_t error) { uint8_t p[4]; put16(p, error ? 1 : 0); put16(p + 2, error); tlv(2, p, 4); }
    size_t finish() {
        if (bytes > sizeof(data)) return 0;
        put16(data + 5, uint16_t(bytes - 7));
        return bytes;
    }
};
using QmiBuilder = QmiBuffer<1024>;

struct Capability {
    bool valid;
    uint32_t chip_id, chip_family, board_id, soc_id, firmware_version;
    bool soc_valid, firmware_valid, chip_valid, board_valid;
};
inline bool capability(const QmiMessage &m, Capability &out) {
    uint16_t error;
    size_t n;
    if (m.type != kQmiResponse || m.id != 0x24 || !m.result(error)) return false;
    const uint8_t *chip = m.get(0x10, n);
    if (chip && n != 8) return false;
    Capability value{};
    // ath10k uses 0xff IDs when these optional fields are absent.
    value.chip_id = 0xff;
    value.board_id = 0xff;
    value.chip_valid = chip != nullptr;
    if (chip) {
        value.chip_id = le32(chip);
        value.chip_family = le32(chip + 4);
    }
    const uint8_t *board = m.get(0x11, n);
    if (board && n != 4) return false;
    value.board_valid = board != nullptr;
    if (board) value.board_id = le32(board);
    const uint8_t *soc = m.get(0x12, n);
    if (soc && n != 4) return false;
    value.soc_valid = soc != nullptr;
    if (soc) value.soc_id = le32(soc);
    const uint8_t *fw = m.get(0x13, n);
    /* Aggregate QMI_STRING carries a one-byte length inside the TLV. */
    if (fw && (n < 5 || fw[4] > 32 || n != size_t(5 + fw[4]))) return false;
    value.firmware_valid = fw != nullptr;
    if (fw) value.firmware_version = le32(fw);
    value.valid = true;
    out = value;
    return true;
}

/* RFC 1350/2347 NUL-delimited strings. No truncation or implicit terminator. */
inline bool string(const uint8_t *p, size_t n, size_t &at, char *out, size_t capacity) {
    if (!p || at >= n || !out || !capacity) return false;
    size_t end = at;
    while (end < n && p[end]) ++end;
    if (end == n || end == at || end - at >= capacity) return false;
    memcpy(out, p + at, end - at); out[end - at] = 0; at = end + 1;
    return true;
}
inline bool decimal(const char *s, uint64_t &out) {
    if (!s || !*s) return false;
    uint64_t v = 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || v > (UINT64_MAX - unsigned(*s - '0')) / 10) return false;
        v = v * 10 + unsigned(*s - '0');
    }
    out = v;
    return true;
}

/* Small schema reader for the supplied service-registry JSON. Unsupported
 * string escapes and excessive nesting fail, with no unbounded token tree. */
class Json {
public:
    Json(const uint8_t *p, size_t n) : p_(p), n_(n), at_(0) {}
    void space() { while (at_ < n_ && (p_[at_] == ' ' || p_[at_] == '\t' || p_[at_] == '\r' || p_[at_] == '\n')) ++at_; }
    bool take(char c) { space(); if (at_ == n_ || p_[at_] != uint8_t(c)) return false; ++at_; return true; }
    bool end() { space(); return at_ == n_; }
    bool text(char *out, size_t capacity) {
        if (!capacity || !take('"')) return false;
        size_t length = 0;
        while (at_ < n_ && p_[at_] != '"') {
            const uint8_t c = p_[at_++];
            if (c < 32 || c > 126 || c == '\\' || length + 1 >= capacity) return false;
            out[length++] = char(c);
        }
        if (!take('"')) return false;
        out[length] = 0;
        return true;
    }
    bool number(uint32_t &value) {
        space(); uint64_t result = 0; const size_t start = at_;
        while (at_ < n_ && p_[at_] >= '0' && p_[at_] <= '9') {
            result = result * 10 + (p_[at_++] - '0');
            if (result > UINT32_MAX) return false;
        }
        if (at_ == start || (at_ > start + 1 && p_[start] == '0')) return false;
        value = uint32_t(result); return true;
    }
    bool skip(unsigned depth = 0) {
        if (depth > 12) return false;
        space();
        if (at_ == n_) return false;
        if (p_[at_] == '"') { char text_buffer[160]; return text(text_buffer, sizeof(text_buffer)); }
        const bool object = p_[at_] == '{';
        if (object || p_[at_] == '[') {
            ++at_;
            const char close = object ? '}' : ']';
            if (take(close)) return true;
            do {
                if (object) { char key[80]; if (!text(key, sizeof(key)) || !take(':')) return false; }
                if (!skip(depth + 1)) return false;
                if (take(close)) return true;
            } while (take(','));
            return false;
        }
        uint32_t value;
        return number(value);
    }
private:
    const uint8_t *p_;
    size_t n_, at_;
};
} // namespace wire
} // namespace nabu_wifi
#endif

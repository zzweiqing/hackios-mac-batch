// SPDX-License-Identifier: BSD-2-Clause-Patent
// Nabu QUAT TDM clock/control trial; no PCM route or amplifier output enable.
// Original DT/vendor wire contract: log/host/audio-v150/afe-tdm-contract.md.
#pragma once
#include "NabuAudio.h"
// Imported from https://github.com/buhuo666/XIAOMI-PAD-5_nabu-on-IOS
// Commit 56c7364f5c083583b07eea24dded38a9ee932e5f
// Source SHA-256 97d4b908f9a8a8dd0cb97cdf5456360589e26d6f10b6f70f930b1b51a005ec00
#if XNU_NABU_AUDIO
#include <stdint.h>

namespace NabuAudioAfeTdm {
static constexpr uint16_t Port=0x9030,Group=0x9130;
static constexpr uint32_t MaxPayload=76,CommandTimeout=1000;
inline uint16_t u16(const uint8_t *p) {return uint16_t(p[0])|uint16_t(p[1])<<8;}
inline uint32_t u32(const uint8_t *p) {return uint32_t(u16(p))|uint32_t(u16(p+2))<<16;}
inline void put16(uint8_t *p,uint16_t n) {p[0]=uint8_t(n);p[1]=uint8_t(n>>8);}
inline void put32(uint8_t *p,uint32_t n) {put16(p,uint16_t(n));put16(p+2,uint16_t(n>>16));}

struct Result {
    bool island_configured,clock_sent,clock_on,group_configured,group_sent,group_on;
    bool port_configured,slots_configured,start_sent,started;
    bool stop_sent,stopped,group_off_sent,group_off,clock_off_sent,clock_off;
    bool failed,timeout,cleanup_failed;
    uint32_t failed_phase,failed_opcode,status,cleanup_opcode,cleanup_status,commands,ignored;
};

// Transport::afe_send(opcode,token,payload,bytes) accepts APR's post-header bytes.
// The transport supplies a 20-byte APR header: AFE service4, APPS5 -> ADSP4,
// src/dest ports0. A false return means that no request was queued.
template<class Transport> class Trial {
    enum Phase {Idle,Island,ClockOn,GroupConfig,GroupOn,PortConfig,Slots,Start,
                Hold,Stop,GroupOff,ClockOff,Done};
    Transport &transport;
    Phase phase=Idle;
    Result r{};
    uint32_t phase_start=0,next_token=0x200,command=0,command_token=0;
    bool timing=false,waiting=false;

    void transition(Phase next) {phase=next;timing=false;waiting=false;}
    bool cleaning() const {return phase==Stop||phase==GroupOff||phase==ClockOff;}
    void unwind() {
        if(r.start_sent&&!r.stop_sent)transition(Stop);
        else if(r.group_sent&&!r.group_off_sent)transition(GroupOff);
        else if(r.clock_sent&&!r.clock_off_sent)transition(ClockOff);
        else transition(Done);
    }
    void after_cleanup() {
        if(phase==Stop)transition(r.group_sent?GroupOff:(r.clock_sent?ClockOff:Done));
        else if(phase==GroupOff)transition(r.clock_sent?ClockOff:Done);
        else transition(Done);
    }
    void failure(uint32_t opcode,uint32_t status,bool timeout=false) {
        if(!r.failed) {r.failed=true;r.failed_phase=phase;r.failed_opcode=opcode;r.status=status;}
        r.timeout|=timeout;
        if(cleaning()) {
            if(!r.cleanup_failed) {r.cleanup_opcode=opcode;r.cleanup_status=status;}
            r.cleanup_failed=true;after_cleanup();
        } else unwind();
    }
    // Original Android exposes Instance ID Support=On. All parameter commands
    // therefore use 16-byte param_hdr_v3 (instance0), not the legacy header.
    static uint8_t *parameter(uint8_t *p,bool port,uint32_t module,uint32_t id,uint32_t size) {
        uint32_t prefix=port?20:16;
        if(port) {put16(p,Port);put32(p+16,16+size);}
        else put32(p+12,16+size);
        p+=prefix;put32(p,module);put32(p+8,id);put32(p+12,size);
        return p+16;
    }
    void control() {
        uint8_t payload[MaxPayload]{};uint8_t *p=nullptr;uint32_t bytes=0;
        command=0x100fc; // AFE_SVC_CMD_SET_PARAM_V2
        switch(phase) {
        case Island:
            command=0x100fa;bytes=44;p=parameter(payload,true,0x1020c,0x102b4,8);
            put32(p,1);break; // version1, island disabled; first config for AFE>=4
        case ClockOn:case ClockOff:
            bytes=52;p=parameter(payload,false,0x1028f,0x10290,20);
            put32(p,1);put32(p+4,0x206);put32(p+8,12288000);
            put16(p+12,4);put32(p+16,phase==ClockOn?1:0);break;
        case GroupConfig:
            bytes=76;p=parameter(payload,false,0x10254,0x1029e,44);
            put32(p,1);put16(p+4,Group);put16(p+8,Port);put16(p+10,0x9032);
            for(unsigned i=2;i<8;++i)put16(p+8+i*2,0xffff);
            put32(p+24,8);put32(p+28,48000);put32(p+32,32);
            put16(p+36,8);put16(p+38,32);put32(p+40,0xff);break;
        case GroupOn:case GroupOff:
            bytes=36;p=parameter(payload,false,0x10254,0x10256,4);
            put16(p,Group);put16(p+2,phase==GroupOn?1:0);break;
        case PortConfig:
            command=0x100fa;bytes=72;p=parameter(payload,true,0x1020c,0x1029d,36);
            put32(p,1);put32(p+4,2);put32(p+8,48000);put32(p+12,24);
            put16(p+18,1);put16(p+20,1);put16(p+22,8);
            put16(p+26,1);put16(p+28,1);put16(p+30,32);put32(p+32,3);break;
        case Slots:
            command=0x100fa;bytes=64;p=parameter(payload,true,0x1028a,0x10297,28);
            put32(p,1);put16(p+4,2);put16(p+6,24);put16(p+14,4);
            for (unsigned i = 2; i < 8; ++i) {
                put16(p + 12 + i * 2, 0xffff);
            }
            break;
        case Start:case Stop:
            command=phase==Start?0x100e5:0x100e6;bytes=4;put16(payload,Port);break;
        default:return;
        }
        if(!transport.afe_send(command,next_token,payload,bytes))return;
        command_token=next_token++;++r.commands;waiting=true;
        if(phase==ClockOn)r.clock_sent=true;
        if(phase==GroupOn)r.group_sent=true;
        if(phase==Start)r.start_sent=true;
        if(phase==Stop)r.stop_sent=true;
        if(phase==GroupOff)r.group_off_sent=true;
        if(phase==ClockOff)r.clock_off_sent=true;
    }
public:
    constexpr explicit Trial(Transport &owner):transport(owner) {}
    void begin(uint32_t now) {
        r={};next_token=0x200;command=0;command_token=0;
        transition(Island);phase_start=now;timing=true;
    }
    void receive(const uint8_t *data,uint32_t bytes,uint32_t now) {
        (void)now;
        if(!waiting||bytes<20) {++r.ignored;return;}
        uint16_t field=u16(data);uint32_t header=((field>>4)&15)*4,total=u16(data+2);
        if((field&15)>1||header<20||total<header||total>bytes||total-header<8||
           data[4]!=4||data[5]!=4||u16(data+6)||data[8]!=4||data[9]!=5||u16(data+10)||
           u32(data+12)!=command_token||u32(data+16)!=0x110e8||u32(data+header)!=command) {
            ++r.ignored;return;
        }
        uint32_t status=u32(data+header+4);waiting=false;
        if(status) {failure(command,status);return;}
        switch(phase) {
        case Island:r.island_configured=true;transition(ClockOn);break;
        case ClockOn:r.clock_on=true;transition(GroupConfig);break;
        case GroupConfig:r.group_configured=true;transition(GroupOn);break;
        case GroupOn:r.group_on=true;transition(PortConfig);break;
        case PortConfig:r.port_configured=true;transition(Slots);break;
        case Slots:r.slots_configured=true;transition(Start);break;
        case Start:r.started=true;transition(Hold);break;
        case Stop:r.stopped=true;after_cleanup();break;
        case GroupOff:r.group_off=true;after_cleanup();break;
        case ClockOff:r.clock_off=true;after_cleanup();break;
        default:++r.ignored;
        }
    }
    void step(uint32_t now) {
        if(phase==Idle||phase==Hold||phase==Done)return;
        // A synchronous amplifier trial can hold the clock for 90 seconds.
        // A new cleanup phase starts timing here, never at the pre-hold time.
        if(!timing) {phase_start=now;timing=true;}
        if(now-phase_start>=CommandTimeout) {
            failure(command,0xffffffff,true);
            return; // next phase gets its own deadline on the next step
        }
        if(!waiting)control();
    }
    bool ready() const {return phase==Hold;}
    void finish() {if(phase!=Idle&&phase!=Done&&!cleaning())unwind();}
    bool done() const {return phase==Done;}
    const Result &result() const {return r;}
};
} // namespace NabuAudioAfeTdm
#endif

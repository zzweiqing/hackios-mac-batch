// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded non-tunneled PCM-to-PCM trial: no ADM/AFE or physical audio endpoint.
#pragma once
#include "NabuAudio.h"
// Imported from https://github.com/buhuo666/XIAOMI-PAD-5_nabu-on-IOS
// Commit 56c7364f5c083583b07eea24dded38a9ee932e5f
// Source SHA-256 1597da2526c22f7e53e1ea73184dd16b0bbdadc6ea0fc8eea08b7bb5fa1d0431
#if XNU_NABU_AUDIO
#include <stdint.h>

namespace NabuAudioAsmPcm {
static constexpr uint32_t InputBytes=4096, OutputOffset=8192, OutputBytes=4096;
static constexpr uint16_t Port=0x101; // Host-owned session1/stream1.
inline uint16_t u16(const uint8_t *p) { return uint16_t(p[0])|uint16_t(p[1])<<8; }
inline uint32_t u32(const uint8_t *p) { return uint32_t(u16(p))|uint32_t(u16(p+2))<<16; }
inline void put16(uint8_t *p,uint16_t n) { p[0]=uint8_t(n);p[1]=uint8_t(n>>8); }
inline void put32(uint8_t *p,uint32_t n) { put16(p,uint16_t(n));put16(p+2,uint16_t(n>>16)); }
// Distinct, low-amplitude signed 24-bit left/right samples in the high24 bits.
inline uint32_t sample(unsigned frame,unsigned channel) {
    int32_t n=channel ? -int32_t(3*(frame%97)+1) : int32_t(5*(frame%89)+1);
    return uint32_t(n)*256u;
}
struct Result {
    bool open_sent,opened,input_format,output_format,running;
    bool read_sent,write_sent,eos_sent,read_done,write_done,close_sent,closed;
    bool timeout,failed;
    uint32_t failed_opcode,status,commands,ignored;
    uint32_t read_token,write_token,read_status,write_status,read_bytes,read_offset,read_flags,read_frames;
};
template<class Transport> class Trial {
    enum Phase { Idle,Open,InputFormat,OutputFormat,Run,Transfer,Close,Done };
    Transport &transport;
    Phase phase=Idle;
    Result r{};
    uint64_t address=0;
    uint32_t handle=0,now=0,phase_start=0,next_token=0x100;
    uint32_t command=0,command_token=0;
    bool waiting=false;
    void transition(Phase next) { phase=next;phase_start=now;waiting=false; }
    void failure(uint32_t opcode,uint32_t status,bool timeout=false) {
        if(!r.failed) { r.failed=true;r.failed_opcode=opcode;r.status=status;r.timeout=timeout; }
        if(phase==Close) {if(timeout||opcode==0x10bcd)transition(Done);}
        else if(r.open_sent)transition(Close);
        else transition(Done);
    }
    static void format(uint8_t *out) {
        put16(out,2);put16(out+2,24);put32(out+4,48000);put16(out+8,1);
        out[12]=1;out[13]=2; // L/R, unused entries and reserved bytes stay zero.
    }
    bool send(uint32_t opcode,const uint8_t *payload,uint32_t bytes,uint32_t &token) {
        token=next_token;
        if(!transport.pcm_send(opcode,token,payload,bytes))return false;
        ++next_token;++r.commands;return true;
    }
    void control() {
        uint8_t payload[36]{};uint32_t opcode=0,bytes=0;
        switch(phase) {
        case Open:
            opcode=0x10d8d;bytes=20;put32(payload+4,0x10c68); // no postprocessing
            put32(payload+8,0x10da5);put32(payload+12,0x10da5);put16(payload+16,24);break;
        case InputFormat:
            opcode=0x10d98;bytes=24;put32(payload,20);format(payload+4);break;
        case OutputFormat:
            opcode=0x10c10;bytes=36;put32(payload,0x10da3);put32(payload+4,28);
            put32(payload+12,20);format(payload+16);break; // frames_per_buf=0, as vendor PCM path
        case Run:opcode=0x10daa;bytes=12;break; // run immediately
        case Close:opcode=0x10bcd;break;
        default:return;
        }
        if(send(opcode,payload,bytes,command_token)) {
            command=opcode;waiting=true;
            if(phase==Open)r.open_sent=true;
            if(phase==Close)r.close_sent=true;
        }
    }
public:
    constexpr explicit Trial(Transport &owner):transport(owner) {}
    void begin(uint64_t dma_address,uint32_t map_handle,uint32_t time) {
        address=dma_address;handle=map_handle;now=time;transition(Open);
    }
    void receive(const uint8_t *data,uint32_t bytes,uint32_t time) {
        now=time;
        if(phase==Idle||phase==Done) {++r.ignored;return;}
        if(bytes<20) {++r.ignored;return;}
        uint16_t field=u16(data);uint32_t header=((field>>4)&15)*4,total=u16(data+2);
        if((field&15)>1||header<20||total<header||total>bytes||data[4]!=7||data[5]!=4||
            data[8]!=7||data[9]!=5||u16(data+6)!=Port||u16(data+10)!=Port) {++r.ignored;return;}
        uint32_t token=u32(data+12),opcode=u32(data+16),size=total-header;
        const uint8_t *p=data+header;
        if(opcode==0x110e8&&size>=8) {
            uint32_t original=u32(p),status=u32(p+4);
            if(waiting&&token==command_token&&original==command) {
                waiting=false;
                if(status) {failure(original,status);return;}
                switch(phase) {
                case Open:r.opened=true;transition(InputFormat);break;
                case InputFormat:r.input_format=true;transition(OutputFormat);break;
                case OutputFormat:r.output_format=true;transition(Run);break;
                case Run:r.running=true;transition(Transfer);break;
                case Close:r.closed=true;transition(Done);break;
                default:++r.ignored;
                }
                return;
            }
            if(status&&((r.read_sent&&token==r.read_token&&original==0x10dac)||
                (r.write_sent&&token==r.write_token&&original==0x10dab))) {failure(original,status);return;}
        } else if(opcode==0x10d99&&size>=16&&r.write_sent&&!r.write_done&&token==r.write_token&&
            u32(p)==uint32_t(address)&&u32(p+4)==uint32_t(address>>32)&&u32(p+8)==handle) {
            r.write_done=true;r.write_status=u32(p+12);
            if(r.write_status)failure(0x10dab,r.write_status);
            return;
        } else if(opcode==0x10d9a&&size>=44&&r.read_sent&&!r.read_done&&token==r.read_token&&
            u32(p+4)==uint32_t(address+OutputOffset)&&u32(p+8)==uint32_t((address+OutputOffset)>>32)&&u32(p+12)==handle) {
            uint32_t status=u32(p),length=u32(p+16),offset=u32(p+20);
            if(!status&&(offset>OutputBytes||length>OutputBytes-offset)) {failure(opcode,0xfffffffe);return;}
            r.read_done=true;r.read_status=status;r.read_bytes=length;r.read_offset=offset;
            r.read_flags=u32(p+32);r.read_frames=u32(p+36);
            if(status)failure(0x10dac,status);
            return;
        }
        ++r.ignored;
    }
    void step(uint32_t time) {
        now=time;if(phase==Idle||phase==Done)return;
        if(now-phase_start>=(phase==Transfer?1500u:1000u)) {
            failure(phase==Transfer?0x10dac:command,0xffffffff,true);
            if(phase==Done)return;
        }
        if(phase==Transfer) {
            if(r.read_done&&r.write_done) {transition(Close);control();return;}
            uint8_t payload[32]{};
            if(!r.read_sent) {
                put32(payload,uint32_t(address+OutputOffset));put32(payload+4,uint32_t((address+OutputOffset)>>32));
                put32(payload+8,handle);put32(payload+12,OutputBytes);put32(payload+16,1);
                r.read_sent=send(0x10dac,payload,20,r.read_token);if(!r.read_sent)return;
            }
            if(!r.write_sent) {
                put32(payload,uint32_t(address));put32(payload+4,uint32_t(address>>32));
                put32(payload+8,handle);put32(payload+12,InputBytes);put32(payload+16,1);
                r.write_sent=send(0x10dab,payload,32,r.write_token);if(!r.write_sent)return;
            }
            if(!r.eos_sent) {uint32_t token;r.eos_sent=send(0x10bdb,nullptr,0,token);}
        } else if(!waiting)control();
    }
    bool done() const {return phase==Done;}
    const Result &result() const {return r;}
};
} // namespace NabuAudioAsmPcm
#endif

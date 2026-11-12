// SPDX-License-Identifier: BSD-2-Clause-Patent
// Nabu AFE0x9030 -> ADM COPP -> ASM1/1 playback; original vendor APR layouts.
// Mapping and AFE lifetime belong to the caller; this trial never unmaps DMA.
#pragma once
#include "NabuAudio.h"
// Imported from https://github.com/buhuo666/XIAOMI-PAD-5_nabu-on-IOS
// Commit 56c7364f5c083583b07eea24dded38a9ee932e5f
// Source SHA-256 c40b9ba24e8cec56413d4e60c5e845ceb74bc7631a80e1e9131920c5ae278bfe
#if XNU_NABU_AUDIO
#include <stdint.h>

namespace NabuAudioPlayback {
static constexpr uint16_t AfePort=0x9030,StreamPort=0x101;
static constexpr uint32_t PeriodBytes=4096,PeriodFrames=1024,Periods=4;
static constexpr uint32_t TotalPeriods=141,MaxPayload=32; // 3.008s at48k stereo S16
inline uint16_t u16(const uint8_t *p){return uint16_t(p[0])|uint16_t(p[1])<<8;}
inline uint32_t u32(const uint8_t *p){return uint32_t(u16(p))|uint32_t(u16(p+2))<<16;}
inline void put16(uint8_t *p,uint16_t n){p[0]=uint8_t(n);p[1]=uint8_t(n>>8);}
inline void put32(uint8_t *p,uint32_t n){put16(p,uint16_t(n));put16(p+2,uint16_t(n>>16));}
struct Result {
    bool adm_open_sent,adm_opened,asm_open_sent,asm_opened,routed,formatted,run_sent,running;
    bool play_started,eos_sent,eos_acked,rendered,close_sent,closed,copp_close_sent,copp_closed;
    bool failed,timeout,mapping_retained;
    uint32_t copp_id,commands,writes,completions,bytes_sent,bytes_completed,pending_mask,underflows;
    uint32_t first_write_ms,last_done_ms,eos_event_token,failed_opcode,status,ignored;
};

// playback_send(service,port,opcode,token,payload,bytes): false means not queued.
// playback_fill(period,first_frame,frame_count): fill that free DMA slot and
// publish its CPU cache lines before returning. No busy period is refilled.
template<class Transport> class Trial {
    enum Phase {Idle,AdmOpen,AsmOpen,Route,Format,Run,Hold,Data,Drain,Close,CoppClose,Done};
    Transport &transport;Phase phase=Idle;Result r{};
    uint64_t address=0;uint32_t handle=0,phase_start=0,next_token=0x400;
    uint32_t command=0,command_token=0,period_token[Periods]{};
    uint16_t command_port=0;uint8_t command_service=0;
    bool timing=false,waiting=false,continuous_mode=false;
    void transition(Phase next){phase=next;timing=false;waiting=false;}
    void after_close(){transition(r.adm_opened?CoppClose:Done);}
    void failure(uint32_t opcode,uint32_t status,bool timeout=false){
        if(!r.failed){r.failed=true;r.failed_opcode=opcode;r.status=status;}
        r.timeout|=timeout;
        if(phase==CoppClose)transition(Done);
        else if(phase==Close){r.mapping_retained=true;after_close();}
        else if(r.asm_open_sent)transition(Close);
        else after_close();
    }
    void write_failure(uint32_t opcode,uint32_t status){
        if(phase!=Close&&phase!=CoppClose)failure(opcode,status);
        else if(!r.failed){r.failed=true;r.failed_opcode=opcode;r.status=status;}
    }
    void control(){
        uint8_t p[MaxPayload]{};uint32_t bytes=0;
        command_service=7;command_port=StreamPort;
        switch(phase){
        case AdmOpen:
            command_service=8;command_port=AfePort;command=0x10326;bytes=28;
            put16(p+2,1);put16(p+4,AfePort);put16(p+6,0xffff);put32(p+8,0x10312);
            put16(p+12,2);put16(p+14,24);put32(p+16,48000);p[20]=1;p[21]=2;break;
        case AsmOpen:
            command=0x10db3;bytes=16;put16(p+6,16);put32(p+8,0x10c68);put32(p+12,0x10da5);break;
        case Route:
            command_service=8;command_port=0;command=0x10325;bytes=16;
            put32(p+4,1);put16(p+8,1);put16(p+10,1);put16(p+12,uint16_t(r.copp_id));break;
        case Format:
            command=0x10d98;bytes=24;put32(p,20);put16(p+4,2);put16(p+6,16);
            put32(p+8,48000);put16(p+12,1);p[16]=1;p[17]=2;break;
        case Run:command=0x10daa;bytes=12;break;
        case Drain:command=0x10bdb;break;
        case Close:command=0x10bcd;break;
        case CoppClose:command_service=8;command_port=uint16_t(r.copp_id);command=0x10327;break;
        default:return;
        }
        if(!transport.playback_send(command_service,command_port,command,next_token,p,bytes))return;
        command_token=next_token++;++r.commands;waiting=true;
        if(phase==AdmOpen)r.adm_open_sent=true;
        if(phase==AsmOpen)r.asm_open_sent=true;
        if(phase==Run)r.run_sent=true;
        if(phase==Drain)r.eos_sent=true;
        if(phase==Close)r.close_sent=true;
        if(phase==CoppClose)r.copp_close_sent=true;
    }
    void write_periods(uint32_t now){
        for(unsigned i=0;i<Periods&&(continuous_mode||r.writes<TotalPeriods);++i){
            if(r.pending_mask&(1u<<i))continue;
            transport.playback_fill(i,r.writes*PeriodFrames,PeriodFrames);
            uint64_t at=address+PeriodBytes*i;uint8_t p[32]{};
            put32(p,uint32_t(at));put32(p+4,uint32_t(at>>32));put32(p+8,handle);
            put32(p+12,PeriodBytes);put32(p+16,r.writes+1);
            uint32_t token=0x80000000u|(r.writes+1);
            if(!transport.playback_send(7,StreamPort,0x10dab,token,p,sizeof(p)))return;
            if(!r.writes)r.first_write_ms=now;
            ++r.writes;++r.commands;r.bytes_sent+=PeriodBytes;
            period_token[i]=token;r.pending_mask|=1u<<i;
        }
        if(!continuous_mode&&r.writes==TotalPeriods)transition(Drain);
    }
public:
    constexpr explicit Trial(Transport &owner):transport(owner){}
    void begin(uint64_t dma_address,uint32_t map_handle,uint32_t now,bool continuous=false){
        address=dma_address;handle=map_handle;r={};r.copp_id=0xffff;next_token=0x400;
        continuous_mode=continuous;
        for(unsigned i=0;i<Periods;++i)period_token[i]=0;
        transition(AdmOpen);phase_start=now;timing=true;
    }
    bool ready()const{return phase==Hold;}
    void play(){if(phase==Hold){r.play_started=true;transition(Data);}}
    void finish(){
        if(phase==Data)transition(Drain);
        else if(phase!=Idle&&phase!=Done&&phase!=Drain&&phase!=Close&&phase!=CoppClose){
            if(r.asm_open_sent)transition(Close);else after_close();
        }
    }
    void receive(const uint8_t *data,uint32_t bytes,uint32_t now){
        if(bytes<20||phase==Idle||phase==Done){++r.ignored;return;}
        uint16_t field=u16(data);uint32_t h=((field>>4)&15)*4,total=u16(data+2);
        if((field&15)>1||h<20||total<h||total>bytes||data[5]!=4||data[9]!=5||
           data[4]!=data[8]){++r.ignored;return;}
        uint8_t svc=data[4];uint16_t src=u16(data+6),dest=u16(data+10);
        uint32_t token=u32(data+12),opcode=u32(data+16),size=total-h;const uint8_t *p=data+h;
        bool stream=svc==7&&src==StreamPort&&dest==StreamPort;
        if(stream&&opcode==0x10c17){++r.underflows;return;}
        if(stream&&opcode==0x10d99&&size>=16){
            for(unsigned i=0;i<Periods;++i){
                uint64_t at=address+PeriodBytes*i;
                if((r.pending_mask&(1u<<i))&&token==period_token[i]&&u32(p)==uint32_t(at)&&
                   u32(p+4)==uint32_t(at>>32)&&u32(p+8)==handle){
                    r.pending_mask&=~(1u<<i);
                    if(u32(p+12)){write_failure(opcode,u32(p+12));return;}
                    ++r.completions;r.bytes_completed+=PeriodBytes;r.last_done_ms=now;
                    // Continuous playback has no lifetime deadline. Keep the
                    // existing six-second deadline for stalled data delivery.
                    if(continuous_mode&&phase==Data)phase_start=now;
                    return;
                }
            }
        }
        // RENDERED_EOS is a stream event; original q6asm excludes it from
        // command-token matching. A basic EOS acknowledgment is not rendering.
        if(stream&&opcode==0x10c1c&&phase==Drain&&r.eos_sent){
            r.rendered=true;r.eos_event_token=token;return;
        }
        if(opcode==0x110e8&&size>=8&&stream&&u32(p)==0x10dab&&u32(p+4)){
            for(unsigned i=0;i<Periods;++i)if((r.pending_mask&(1u<<i))&&token==period_token[i]){
                write_failure(0x10dab,u32(p+4));return;
            }
        }
        // ADM OPEN can reply from the newly created COPP; its destination is
        // our requested host port. Other controls reply from the target port.
        if(!waiting||svc!=command_service||dest!=command_port||
           (phase!=AdmOpen&&src!=command_port)||token!=command_token){++r.ignored;return;}
        if(phase==AdmOpen&&opcode==0x10329&&size>=8){
            if(u32(p)){failure(command,u32(p));return;}
            r.copp_id=u16(p+4);r.adm_opened=true;transition(AsmOpen);return;
        }
        if(opcode!=0x110e8||size<8||u32(p)!=command){++r.ignored;return;}
        if(u32(p+4)){failure(command,u32(p+4));return;}
        switch(phase){
        case AdmOpen:break; // Wait for the response that carries the COPP ID.
        case AsmOpen:r.asm_opened=true;transition(Route);break;
        case Route:r.routed=true;transition(Format);break;
        case Format:r.formatted=true;transition(Run);break;
        case Run:r.running=true;transition(Hold);break;
        case Drain:r.eos_acked=true;break; // Still await rendered event and every WRITE_DONE.
        case Close:r.closed=true;after_close();break;
        case CoppClose:r.copp_closed=true;transition(Done);break;
        default:++r.ignored;
        }
    }
    void step(uint32_t now){
        if(phase==Idle||phase==Hold||phase==Done)return;
        if(!timing){phase_start=now;timing=true;}
        if(now-phase_start>=(phase==Data?6000u:1000u)){
            failure(phase==Data?0x10dab:command,0xffffffff,true);return;
        }
        if(phase==Data){write_periods(now);return;}
        if(phase==Drain&&r.rendered&&!r.pending_mask){transition(Close);return;}
        if(!waiting)control();
    }
    bool done()const{return phase==Done;}
    const Result &result()const{return r;}
};
} // namespace NabuAudioPlayback
#endif

// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
// Derived from buhuo666/XIAOMI-PAD-5_nabu-on-IOS at
// 56c7364f5c083583b07eea24dded38a9ee932e5f. Original inputs are retained.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Message router for one observed WLFW firmware instance, not a GLINK owner.
// Native callers serialize EVERY state operation with their queue lock.
// Only the GLINK owner calls begin_send/begin_callback; it releases that lock
// before using the returned lease, then locks again for finish_send/callback.
// No method invokes a callback, waits, touches MMIO, or asserts firmware ready.
struct NabuAth10kQrtr {
    static constexpr unsigned port_count=4, queue_count=4, payload_limit=8192;
    static constexpr uint32_t first_port=0x4020, last_port=0xfffffffdu;
    static constexpr uint32_t wlfw_service=0x45,wlfw_version=1;
    using Receive=void (*)(void *,uint32_t,uint32_t,const void *,size_t);
    using Server=void (*)(void *,bool,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
    using PortId=uint32_t;
    enum Result { Ok, Invalid, Full, TooLarge, Closed, NotConnected, Busy, Empty, InstanceLost };
    struct Endpoint {
        uint32_t service=0,version=0,instance=0,node=0,port=0;
        bool same(const Endpoint &b) const {
            return service==b.service&&version==b.version&&instance==b.instance&&node==b.node&&port==b.port;
        }
    };
    struct Send {
        uint64_t ticket=0,epoch=0;
        PortId local=0;
        uint32_t node=0,port=0;
        const uint8_t *data=nullptr;
        size_t bytes=0;
    };
    struct Callback {
        enum Kind { Arrival, Removal, Data } kind=Data;
        uint64_t ticket=0,epoch=0;
        PortId local=0;
        Receive receive=nullptr;
        Server server=nullptr;
        void *context=nullptr;
        Endpoint endpoint{};
        const uint8_t *data=nullptr;
        size_t bytes=0;
        // Invoke only once, on the owner thread and outside the queue lock.
        // Keep context alive through finish_callback, even after begin_close.
        void invoke() const {
            if(kind==Data) { if(receive)receive(context,endpoint.node,endpoint.port,data,bytes); }
            else if(server)server(context,kind==Arrival,endpoint.service,endpoint.version,
                endpoint.instance,endpoint.node,endpoint.port);
        }
    };

private:
    struct Port {
        PortId id=0;
        Receive receive=nullptr;
        Server server=nullptr;
        void *context=nullptr;
        bool closing=false,lookup=false,notified=false;
        uint32_t wanted_instance=0;
        int notice=0; // +1 arrival, -1 removal; no synthetic QMI payload.
        Endpoint notice_peer{};
    } ports[port_count]{};
    struct Packet {
        bool pending=false,leased=false;
        uint64_t sequence=0,epoch=0;
        PortId local=0;
        uint32_t node=0,port=0;
        size_t bytes=0;
        uint8_t data[payload_limit]{};
    } tx[queue_count]{},rx[queue_count]{};
    Endpoint peer{};
    bool live=false,present=false;
    uint64_t epoch_value=0,sequence=0,tickets=0;
    PortId next_port=first_port;
    int sending=-1,receiving=-1;
    PortId calling=0;
    uint64_t send_ticket=0,callback_ticket=0;

    Port *find(PortId id) {
        for(auto &p:ports)if(id&&p.id==id)return &p;
        return nullptr;
    }
    const Port *find(PortId id) const {
        for(const auto &p:ports)if(id&&p.id==id)return &p;
        return nullptr;
    }
    bool matches(const Port &p) const {
        return p.lookup&&(!p.wanted_instance||p.wanted_instance==peer.instance);
    }
    static void discard(Packet (&queue)[queue_count],PortId id=0) {
        for(auto &q:queue)if(!id||q.local==id)q.pending=false;
        // A leased slot stays allocated until its owner finishes using it.
    }
    int oldest(Packet (&queue)[queue_count]) {
        int at=-1;
        for(unsigned i=0;i<queue_count;++i)if(queue[i].pending&&!queue[i].leased&&
            (at<0||queue[i].sequence<queue[at].sequence))at=(int)i;
        return at;
    }
    Result enqueue_packet(Packet (&queue)[queue_count],PortId local,uint32_t node,uint32_t port,
        const void *data,size_t bytes) {
        if(bytes>payload_limit)return TooLarge;
        if(!bytes||!data)return Invalid;
        for(auto &q:queue)if(!q.pending&&!q.leased) {
            q.sequence=++sequence;q.epoch=epoch_value;q.local=local;q.node=node;q.port=port;q.bytes=bytes;
            memcpy(q.data,data,bytes);q.pending=true;return Ok;
        }
        return Full;
    }
    bool usable(PortId id) const {
        const Port *p=find(id);return p&&!p->closing&&live&&present;
    }

public:
    uint64_t epoch() const {return epoch_value;}
    bool instance_live() const {return live;}
    bool has_leases() const {return calling||sending>=0;}
    bool owns_port(PortId id) const {return id>=first_port&&id<next_port;}
    // A replacement firmware instance requires retirement of every old handle.
    Result start_instance() {
        if(live||calling||sending>=0)return Busy;
        for(const auto &p:ports)if(p.id)return Busy;
        if(epoch_value==UINT64_MAX)return Full;
        ++epoch_value;live=true;present=false;peer={};return Ok;
    }
    Result open(Receive receive,Server server,void *context,PortId &out) {
        out=0;if(!live)return NotConnected;
        if(next_port>last_port)return Full;
        for(auto &p:ports)if(!p.id) {
            p={};p.id=next_port++;p.receive=receive;p.server=server;p.context=context;
            out=p.id;return Ok;
        }
        return Full;
    }
    // This adapter has one WLFW lookup per port. instance=0 is a wildcard.
    Result lookup(PortId id,uint32_t service,uint32_t version,uint32_t instance) {
        Port *p=find(id);if(!p||p->closing)return Closed;
        if(!live)return NotConnected;
        if(service!=wlfw_service||version!=wlfw_version)return Invalid;
        if(p->lookup)return p->wanted_instance==instance?Ok:Busy;
        p->lookup=true;p->wanted_instance=instance;
        if(present&&matches(*p)){p->notice=1;p->notice_peer=peer;}
        return Ok;
    }
    // Called only for an actual QRTR NEW_SERVER observation. A changed endpoint
    // invalidates this instance; it is not silently adopted by existing handles.
    Result announce(const Endpoint &observed) {
        if(!live)return NotConnected;
        if(observed.service!=wlfw_service||observed.version!=wlfw_version||observed.node==1)return Invalid;
        if(present) {
            if(peer.same(observed))return Ok;
            invalidate();return InstanceLost;
        }
        peer=observed;present=true;
        for(auto &p:ports)if(p.id&&!p.closing&&matches(p)){p.notice=1;p.notice_peer=peer;}
        return Ok;
    }
    Result announce_at(uint64_t observed_epoch,const Endpoint &observed) {
        if(!observed_epoch||observed_epoch!=epoch_value)return InstanceLost;
        return announce(observed);
    }
    Result withdraw(const Endpoint &observed) {
        if(!live||!present||!peer.same(observed))return NotConnected;
        invalidate();return Ok;
    }
    Result withdraw_at(uint64_t observed_epoch,const Endpoint &observed) {
        if(!observed_epoch||observed_epoch!=epoch_value)return InstanceLost;
        return withdraw(observed);
    }
    // PFR/BYE/endpoint loss: retain handles for orderly QMI teardown, discard
    // pending datagrams, and report disappearance only to observers told of it.
    void invalidate() {
        live=false;present=false;discard(tx);discard(rx);
        for(auto &p:ports)if(p.id&&!p.closing) {
            p.notice=p.notified?-1:0;
            if(p.notified)p.notice_peer=peer;
        }
    }
    Result send(PortId id,uint32_t node,uint32_t port,const void *data,size_t bytes) {
        Port *p=find(id);if(!p||p->closing)return Closed;
        if(!usable(id)||node!=peer.node||port!=peer.port)return NotConnected;
        return enqueue_packet(tx,id,node,port,data,bytes);
    }
    Result send_at(uint64_t observed_epoch,PortId id,uint32_t node,uint32_t port,const void *data,size_t bytes) {
        if(!observed_epoch||observed_epoch!=epoch_value)return InstanceLost;
        return send(id,node,port,data,bytes);
    }
    // Called by the owner after QRTR framing and confirm handling. Identity is
    // checked before QMI helpers, whose response lookup is transaction-based.
    Result receive(PortId id,uint32_t node,uint32_t port,const void *data,size_t bytes) {
        Port *p=find(id);if(!p||p->closing)return Closed;
        if(!usable(id)||node!=peer.node||port!=peer.port)return NotConnected;
        return enqueue_packet(rx,id,node,port,data,bytes);
    }
    Result receive_at(uint64_t observed_epoch,PortId id,uint32_t node,uint32_t port,const void *data,size_t bytes) {
        if(!observed_epoch||observed_epoch!=epoch_value)return InstanceLost;
        return receive(id,node,port,data,bytes);
    }
    Result begin_send(Send &out) {
        out={};if(sending>=0)return Busy;
        int i=oldest(tx);if(i<0)return Empty;
        Packet &q=tx[i];q.pending=false;q.leased=true;sending=i;send_ticket=++tickets;
        out={send_ticket,q.epoch,q.local,q.node,q.port,q.data,q.bytes};return Ok;
    }
    // sent=false means GLINK had no intent/space: retry the copied datagram,
    // unless close/loss occurred while it was leased. No QMI success is implied.
    Result finish_send(uint64_t ticket,bool sent) {
        if(sending<0||ticket!=send_ticket)return Invalid;
        Packet &q=tx[sending];q.leased=false;
        q.pending=!sent&&usable(q.local)&&q.epoch==epoch_value;
        sending=-1;send_ticket=0;return Ok;
    }
    Result begin_callback(Callback &out) {
        out={};if(calling)return Busy;
        for(auto &p:ports)if(p.id&&!p.closing&&p.notice) {
            int notice=p.notice;p.notice=0;p.notified=notice>0;
            if(!p.server)continue;
            calling=p.id;callback_ticket=++tickets;receiving=-1;
            out.kind=notice>0?Callback::Arrival:Callback::Removal;
            out.ticket=callback_ticket;out.epoch=epoch_value;out.local=p.id;
            out.server=p.server;out.context=p.context;out.endpoint=p.notice_peer;return Ok;
        }
        for(int i=oldest(rx);i>=0;i=oldest(rx)) {
            Packet &q=rx[i];q.pending=false;
            Port *p=find(q.local);if(!p||p->closing||!p->receive)continue;
            q.leased=true;receiving=i;calling=p->id;callback_ticket=++tickets;
            out.kind=Callback::Data;out.ticket=callback_ticket;out.epoch=q.epoch;
            out.local=p->id;out.receive=p->receive;out.context=p->context;out.endpoint=peer;
            out.data=q.data;out.bytes=q.bytes;return Ok;
        }
        return Empty;
    }
    Result finish_callback(uint64_t ticket) {
        if(!calling||ticket!=callback_ticket)return Invalid;
        if(receiving>=0)rx[receiving].leased=false;
        calling=0;receiving=-1;callback_ticket=0;return Ok;
    }
    // begin_close is a cancellation request, NOT synchronous hakios_qrtr_ops.close.
    // Native close must wait for finish_close==Ok before returning/freeing the
    // QMI context. From an owner callback, defer qmi_handle_release to a worker;
    // never block waiting for this same callback, or claim it has finished.
    Result begin_close(PortId id) {
        Port *p=find(id);if(!p)return Closed;
        p->closing=true;p->notice=0;discard(tx,id);discard(rx,id);
        return calling==id||(sending>=0&&tx[sending].local==id)?Busy:Ok;
    }
    Result finish_close(PortId id) {
        Port *p=find(id);if(!p)return Closed;
        if(!p->closing)return Invalid;
        if(calling==id||(sending>=0&&tx[sending].local==id))return Busy;
        *p={};return Ok;
        // Native owner separately queues QRTR_DEL_CLIENT for this local id.
    }
};

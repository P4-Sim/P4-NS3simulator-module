/* -*- P4_16 -*- */

/*
* Copyright 2018-present Ralf Kundel, Nikolas Eller
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* 
* Author: Tobias Scheinert
* ref-src: srcP4/Evaluation/5_Router_TS_CoDel_Prio_ECN/codel_2.p4
* Modified by: Mingyu, used for test
*
* v1model.p4: https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4
* 
* Warning: there is modified to suit for ns3, see @ns3
*
*/

#include <core.p4>
#include <v1model.p4>

//Codel
#define SOJOURN_TARGET 5000
#define CONTROL_INTERVAL 48w10000
#define INTERFACE_MTU 1500
#define NO_QUEUE_ID 32w64

register<bit<32>>(NO_QUEUE_ID) r_drop_count;
register<bit<48>>(NO_QUEUE_ID) r_drop_time;
register<bit<32>>(NO_QUEUE_ID) r_last_drop_count;
register<bit<48>>(NO_QUEUE_ID) r_next_drop;
register<bit<1>>(NO_QUEUE_ID) r_state_dropping;

register<bit<1>>(NO_QUEUE_ID) r_slice_drop; //Prio Drop
register<bit<32>>(NO_QUEUE_ID) r_slice_time; //Timestamp
register<bit<19>>(NO_QUEUE_ID) r_slice_enq; //enq_qdepth
register<bit<19>>(NO_QUEUE_ID) r_slice_deq; //deq_qdepth

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

struct codel_t {
    bit<48> drop_time;
    bit<48> time_now;
    bit<1>  ok_to_drop;
    bit<1>  state_dropping;
    bit<32> delta;
    bit<48> time_since_last_dropping;
    bit<48> drop_next;
    bit<32> drop_cnt;
    bit<32> last_drop_cnt;
    bit<1>  reset_drop_time;
    bit<48> new_drop_time;
    bit<48> new_drop_time_helper;
    bit<9>  queue_id;
}

struct prio_t {
	bit<1>  prio_drop;
	bit<32> time;
	bit<19> enq;
	bit<19> deq;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> sourcePort;
    bit<16> destPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header arp_t {
    bit<16> hw_type;
    bit<16> protocol_type;
    bit<8>  hw_size;
    bit<8>  protocol_size;
    bit<16> opcode;
    macAddr_t srcMac;
    ip4Addr_t srcIp;
    macAddr_t dstMac;
    ip4Addr_t dstIp;
}

struct routing_metadata_t {
    bit<32> nhop_ipv4;
}

// info for connect with ns-3
struct ns3info {
    bit<1>      ns3_drop;           // the pkts will drop in bmv2 or not
    bit<64>     ns3_priority_id;    // The pkts ID in this prioirty, used for drop tracing. 
    bit<16>     protocol;           // the protocol in ns3::packet
    bit<16>     destination;        // the destination in ns3::packet
    bit<64>     pkts_id;            // the id of the ns3::packet (using for tracing etc)
}

struct metadata {
    routing_metadata_t      routing_metadata;
    codel_t                 codel;
    ns3info                 ns3i;
    prio_t		            prio;
}

struct headers {
    arp_t           arp;
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    udp_t           udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            TYPE_ARP  : parse_arp;
            default   : accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w17: parse_udp;
            8w6: parse_tcp;
            default: accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
	transition accept;

    }
    
    state parse_udp {
        packet.extract(hdr.udp);
	transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  
        verify_checksum(
            true, 
            { 
                hdr.ipv4.version, 
                hdr.ipv4.ihl, 
                hdr.ipv4.diffserv, 
                hdr.ipv4.totalLen, 
                hdr.ipv4.identification, 
                hdr.ipv4.flags, 
                hdr.ipv4.fragOffset, 
                hdr.ipv4.ttl, 
                hdr.ipv4.protocol, 
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr 
            }, 
            hdr.ipv4.hdrChecksum, 
            HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        // this drop will happen before "allocating the queue Nr". 
        // So NO need to record the queue Nr.
        meta.ns3i.ns3_drop = 1;      // add for connect ns-3 --> drop @ns3
        meta.ns3i.destination = 0;
        meta.ns3i.protocol = 0;
        meta.ns3i.pkts_id = 0;
        meta.ns3i.ns3_priority_id = 0;
        standard_metadata.egress_spec = 511;
        mark_to_drop(standard_metadata);
    }

    action set_port(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
        standard_metadata.egress_port = egress_spec;

    }

    action set_arp_nhop(bit<32> nhop_ipv4) {
        meta.routing_metadata.nhop_ipv4 = nhop_ipv4;
    }

    action set_ipv4_nhop(bit<32> nhop_ipv4) {
        meta.routing_metadata.nhop_ipv4 = nhop_ipv4;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }

    table arp_nhop {
        actions = {
            set_arp_nhop;
            drop;
        }
        key = {
            hdr.arp.dstIp: exact;
        }
        size = 1024;
    }

    table forward_table {
        actions = {
            set_port;
            drop;
        }
        key = {
            meta.routing_metadata.nhop_ipv4: exact;
        }
        size = 1024;
    }

    table ipv4_nhop {
        actions = {
            set_ipv4_nhop;
            drop;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = 1024;
    }
    
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0 || hdr.arp.isValid()) {
            if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
                ipv4_nhop.apply();
            } else {
                if (hdr.arp.isValid()) {
                    arp_nhop.apply();
                }
            }
            forward_table.apply();

            // if 𝑐𝑢𝑟𝑟𝑒𝑛𝑡 𝑞𝑢𝑒𝑢𝑒 𝑠𝑖𝑧𝑒 < 𝑞𝑢𝑒𝑢𝑒 𝑙𝑖𝑚𝑖𝑡 then
            //      𝐸𝑛𝑞𝑢𝑒𝑢𝑒 𝑡ℎ𝑒 𝑝𝑎𝑐𝑘𝑒𝑡
            r_slice_drop.read(meta.prio.prio_drop, (bit<32>)meta.codel.queue_id);
            if (meta.prio.prio_drop==1w1) {
                meta.ns3i.ns3_drop = 1;      // add for connect ns-3 --> drop @ns3 
                mark_to_drop(standard_metadata); // queue length --> drop
            }
        }
    }
}

/*************************************************************************
********************  C O N T R O L  D E S I G N   ***********************
*************************************************************************/

control c_codel(inout headers hdr, 
                inout metadata meta, 
                inout standard_metadata_t standard_metadata) {

    action a_codel_control_law(bit<48> value) {
        // 求出queue_id对应的drop_next时间。（自定义：drop数量 --> 下次drop的时间）
        meta.codel.drop_next = meta.codel.time_now + value;
        r_next_drop.write((bit<32>)meta.codel.queue_id, (bit<48>)meta.codel.drop_next); // 对应queue_id的drop_next保存至寄存器。
    }

    action a_codel_init() {
        // 初始化，从寄存器读取相关数据到变量中。
        meta.codel.ok_to_drop = 1w0; // 不准备 drop
        meta.codel.time_now = (bit<48>)standard_metadata.enq_timestamp + (bit<48>)standard_metadata.deq_timedelta;
        meta.codel.new_drop_time = meta.codel.time_now + CONTROL_INTERVAL;
        r_state_dropping.read(meta.codel.state_dropping, (bit<32>)meta.codel.queue_id);
        r_drop_count.read(meta.codel.drop_cnt, (bit<32>)meta.codel.queue_id);
        r_last_drop_count.read(meta.codel.last_drop_cnt, (bit<32>)meta.codel.queue_id);
        r_next_drop.read(meta.codel.drop_next, (bit<32>)meta.codel.queue_id);
        r_drop_time.read(meta.codel.drop_time, (bit<32>)meta.codel.queue_id);
    }

    action a_go_to_drop_state() {
        meta.ns3i.ns3_drop = 1;      // add for connect ns-3 --> drop @ns3 
	    mark_to_drop(standard_metadata);
        r_state_dropping.write((bit<32>)meta.codel.queue_id, (bit<1>)1); //给对应queue_id的队列进入drop阶段。// 1 就是在drop state, 0 表示未在drop阶段。
        meta.codel.delta = meta.codel.drop_cnt - meta.codel.last_drop_cnt; // 本次drop的数量 减去 上次统计的drop的数量
        meta.codel.time_since_last_dropping = meta.codel.time_now - meta.codel.drop_next; // 时间间隔（本次和上次drop包的间隔）
        meta.codel.drop_cnt = 32w1; // 归一
        r_drop_count.write((bit<32>)meta.codel.queue_id, (bit<32>)1); // 这里我认为应该是+1，而非覆盖写入1.
    }

    table t_codel_control_law {
        actions = {
            a_codel_control_law;
        }
        key = {
            meta.codel.drop_cnt: lpm; // drop的数量
        }
        size = 32;
    }

    apply {
        a_codel_init();
    
        // === 探测delay < 5ms 时间，以便后续处理。===
        if (standard_metadata.deq_timedelta < SOJOURN_TARGET ) { //|| standard_metadata.deq_qdepth < 19w1
            meta.codel.reset_drop_time = 1w1;   // @todo this will always be true!!!
        }

        if (meta.codel.reset_drop_time == 1w1) {
            // 延迟时间短，对应queue_id的droptime为 0，写入寄存器
            r_drop_time.write((bit<32>)meta.codel.queue_id, (bit<48>)0); // write 写入寄存器，read为从寄存器中读取
            meta.codel.drop_time = 48w0;
        }
        else {
            // 延迟时间长于标准值，不需要reset drop time
            if (meta.codel.drop_time == 48w0) {
                // 当次延迟时间长，然而drop time为0（之前延迟时间不长），不需要drop，设定新的drop time
                r_drop_time.write((bit<32>)meta.codel.queue_id, (bit<48>)meta.codel.new_drop_time);
                meta.codel.drop_time = meta.codel.new_drop_time;
            }
            else { //if (meta.codel.drop_time > 48w0)
                // 前几次延迟时间均长，drop time 不为0，需要drop
                if (meta.codel.time_now >= meta.codel.drop_time) {
                    meta.codel.ok_to_drop = 1w1; // 准备 drop
                }
            }
        }

        // state 状态处理 和 drop control
        if (meta.codel.state_dropping == 1w1) {
            // 在 drop state 状态里
            if (meta.codel.ok_to_drop == 1w0) {
                // 状态转化：发现未准备 drop 因为---> delay 比较小 ---> 离开 drop state
                r_state_dropping.write((bit<32>)meta.codel.queue_id, (bit<1>)0); //leave drop state
            }
            else {
                // 准备 drop (drop state & ok to drop)
                if (meta.codel.time_now >= meta.codel.drop_next) {
                    // 现在时间 大于 计算出的计划next drop 的时间
                    meta.ns3i.ns3_drop = 1;      // add for connect ns-3 --> drop @ns3 
                    mark_to_drop(standard_metadata);
                    meta.codel.drop_cnt = meta.codel.drop_cnt + 32w1; // drop的数量 ++
                    r_drop_count.write((bit<32>)meta.codel.queue_id, (bit<32>)meta.codel.drop_cnt);
                    t_codel_control_law.apply();

                }
            }
        }
        else {
            // 不在 drop state 状态里
            if (meta.codel.ok_to_drop == 1w1) {
                // 准备 drop 因为---> delay 比较大 --> 看优先级需不需要进入drop状态
                // 该最低优先级队列进入 drop state 状态 。最低优先级 0，最高优先级为 7
                a_go_to_drop_state(); // 最低优先级队列 0 drop

                if (meta.codel.delta > 32w1 && meta.codel.time_since_last_dropping < CONTROL_INTERVAL*16) {
                    // 
                    r_drop_count.write((bit<32>)meta.codel.queue_id, (bit<32>)meta.codel.delta);
                    meta.codel.drop_cnt = meta.codel.delta;
                }
                r_last_drop_count.write((bit<32>)meta.codel.queue_id, (bit<32>)meta.codel.drop_cnt);
                t_codel_control_law.apply();
            }
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    c_codel() c_codel_0;

    apply {

        r_slice_time.write((bit<32>)meta.codel.queue_id, (bit<32>)standard_metadata.deq_timedelta);
        r_slice_enq.write((bit<32>)meta.codel.queue_id, (bit<19>)standard_metadata.enq_qdepth);
        r_slice_deq.write((bit<32>)meta.codel.queue_id, (bit<19>)standard_metadata.deq_qdepth);
        
        if (standard_metadata.deq_qdepth > 19w500) {
            r_slice_drop.write((bit<32>)meta.codel.queue_id, (bit<1>)1);
        } else {
            r_slice_drop.write((bit<32>)meta.codel.queue_id, (bit<1>)0);	
        }

        c_codel_0.apply(hdr, meta, standard_metadata);
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
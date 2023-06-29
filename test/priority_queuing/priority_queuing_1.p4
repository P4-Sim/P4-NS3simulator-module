/* -*- P4_16 -*- */

/*
 * This is a simple switch with p4. No process in Ingress and Egress.
 * 
 * The only thing should pay attention is: the "ns3info", which is the
 * data struct for connect the ns3 and bmv2(p4-model). Without that info
 * the ns3 can not correctly handle the address, protocol, and other 
 * informations of the package, just add that struct to your original p4 
 * file and compile it.
 * The current method looks bad, but is safe and simple across multiple 
 * threads.
 *
 *    struct ns3info {
 *    bit<1>      ns3_drop;           // the pkts will drop in bmv2 or not
 *    bit<64>     ns3_priority_id;    // The pkts ID in this prioirty, used for drop tracing. 
 *    bit<16>     protocol;           // the protocol in ns3::packet
 *    bit<16>     destination;        // the destination in ns3::packet
 *    bit<64>     pkts_id;            // the id of the ns3::packet (using for tracing etc)
 *    }
 *
 * @mingyu myma979@gmail.com
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

// info for connect with ns-3
struct ns3info {
    bit<1>      ns3_drop;           // the pkts will drop in bmv2 or not
    bit<64>     ns3_priority_id;    // The pkts ID in this prioirty, used for drop tracing. 
    bit<16>     protocol;           // the protocol in ns3::packet
    bit<16>     destination;        // the destination in ns3::packet
    bit<64>     pkts_id;            // the id of the ns3::packet (using for tracing etc)
}

struct routing_metadata_t {
    bit<32> nhop_ipv4;
}

struct metadata {
    routing_metadata_t      routing_metadata;
    ns3info                 ns3i;
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

    // added actions below
    action set_priority(bit<7> value) {
        standard_metadata.priority = (bit<3>)value;
    }
    
    table slice_priority{
    	actions = {
            set_priority;
        }
        key = {
            hdr.ipv4.srcAddr: exact;            
        }
        size = 1024;
        const default_action = set_priority((bit<7>) 0);
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
            slice_priority.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
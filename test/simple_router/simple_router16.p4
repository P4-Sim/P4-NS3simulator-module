/* -*- P4_16 -*- */
#include <core.p4>
#define V1MODEL_VERSION 20200408
#include <v1model.p4>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

struct routing_metadata_t {
    bit<32> nhop_ipv4;
}

header arp_t {
    bit<16> hw_type;
    bit<16> protocol_type;
    bit<8>  hw_size;
    bit<8>  protocol_size;
    bit<16> opcode;
    bit<48> srcMac;
    bit<32> srcIp;
    bit<48> dstMac;
    bit<32> dstIp;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct metadata {
    @name(".routing_metadata") 
    routing_metadata_t routing_metadata;
}

struct headers {
    @name(".arp") 
    arp_t      arp;
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/


parser ParserImpl(packet_in packet, 
                    out headers hdr, 
                    inout metadata meta, 
                    inout standard_metadata_t standard_metadata) {

    @name(".start") state start {
        transition parse_ethernet;
    }

    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
    @name(".parse_arp") state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, 
                inout metadata meta, 
                inout standard_metadata_t standard_metadata) {

    @name(".set_arp_nhop") action set_arp_nhop(bit<32> nhop_ipv4) {
        meta.routing_metadata.nhop_ipv4 = nhop_ipv4;
    }
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".set_port") action set_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    @name(".set_ipv4_nhop") action set_ipv4_nhop(bit<32> nhop_ipv4) {
        meta.routing_metadata.nhop_ipv4 = nhop_ipv4;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    @name(".arp_nhop") table arp_nhop {
        actions = {
            set_arp_nhop;
            _drop;
        }
        key = {
            hdr.arp.dstIp: exact;
        }
        size = 8192;
    }
    @name(".forward_table") table forward_table {
        actions = {
            set_port;
            _drop;
        }
        key = {
            meta.routing_metadata.nhop_ipv4: exact;
        }
        size = 8192;
    }
    @name(".ipv4_nhop") table ipv4_nhop {
        actions = {
            set_ipv4_nhop;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = 8192;
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
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;


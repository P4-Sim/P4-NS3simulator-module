#include <core.p4>
#define V1MODEL_VERSION 20200408
#include <v1model.p4>

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
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
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_arp") state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x806: parse_arp;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: tcp_parser;
            8w17: udp_parser;
            default: accept;
        }
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
    @name(".tcp_parser") state tcp_parser {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".udp_parser") state udp_parser {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_arp_nhop") action set_arp_nhop(bit<32> dip) {
        hdr.arp.dstIp = dip;
        meta.routing_metadata.nhop_ipv4 = dip;
    }
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    @name(".set_port") action set_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    @name(".modify_arp_vip") action modify_arp_vip(bit<32> vip) {
        hdr.arp.srcIp = vip;
    }
    @name(".noop") action noop() {
        ;
    }
    @name(".modify_ipv4_vip") action modify_ipv4_vip(bit<32> vip) {
        hdr.ipv4.srcAddr = vip;
    }
    @name(".modify_dip") action modify_dip(bit<32> dip) {
        hdr.ipv4.dstAddr = dip;
        meta.routing_metadata.nhop_ipv4 = dip;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    @name(".arp_nhop") table arp_nhop {
        actions = {
            set_arp_nhop;
            _drop;
        }
        key = {
            hdr.arp.dstIp: exact;
        }
    }
    @name(".forward_table") table forward_table {
        actions = {
            set_port;
            _drop;
        }
        key = {
            meta.routing_metadata.nhop_ipv4: exact;
        }
    }
    @name(".set_arp_srcip") table set_arp_srcip {
        actions = {
            modify_arp_vip;
            noop;
        }
        key = {
            hdr.arp.srcIp: exact;
        }
    }
    @name(".set_ipv4_srcip") table set_ipv4_srcip {
        actions = {
            modify_ipv4_vip;
            noop;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
        }
    }
    @name(".vipt_with_tcp") table vipt_with_tcp {
        actions = {
            modify_dip;
            noop;
        }
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.tcp.dstPort  : exact;
        }
    }
    @name(".vipt_with_udp") table vipt_with_udp {
        actions = {
            modify_dip;
            noop;
        }
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.udp.dstPort  : exact;
        }
    }
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()) {
                vipt_with_tcp.apply();
            } else {
                if (hdr.udp.isValid()) {
                    vipt_with_udp.apply();
                }
            }
            set_ipv4_srcip.apply();
        } else {
            if (hdr.arp.isValid()) {
                arp_nhop.apply();
                set_arp_srcip.apply();
            }
        }
        forward_table.apply();
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
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;


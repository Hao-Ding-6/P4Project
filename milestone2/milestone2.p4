#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#define MAX_PORTS 6

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*************************** Header ***************************/

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

header ecmp_t {
    // if is_load_balance == 0, turn off load balancing;
    // if is_load_balance == 1, turn on load balancing.
    bit<16> is_load_balance; 

    // type of identifier
    bit<16> type;

    // if is_track == 0, turn off tracking;
    // if is_track == 1, turn on tracking.
    bit<16> is_track;

    // monitor of switch 1
    bit<32> port2_bytes;
    bit<32> port3_bytes;

    // seq number
    bit<32> seq;
}

// ecmp load balancing index
struct metadata {
    bit<14> ecmp_select;
}

struct headers {
    ethernet_t ethernet;
    ecmp_t     ecmp;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

/*************************** Parser ***************************/

parser myParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition parse_ecmp;
    }

    state parse_ecmp {
        packet.extract(hdr.ecmp);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_tcp;
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************** Checksum verification ***************************/

control myVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************** Ingress ***************************/

control myIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // register to store the number of packet
    register<bit<32>>(2) pkt_counter_reg;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        bit<32> cnt;
        pkt_counter_reg.read(cnt, 1);

        hash(meta.ecmp_select,
	    HashAlgorithm.crc16,
	    ecmp_base,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort,
              cnt },
	    ecmp_count);
    }

    action set_nhop(bit<48> nhop_dmac, bit<9> port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ecmp.is_load_balance = 0; // turn off the load balance flag after s1
    }

    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
    }

    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if (hdr.ecmp.is_load_balance == 1) {
                bit<32> cnt;
                pkt_counter_reg.read(cnt, 1);
                pkt_counter_reg.write(1, cnt + 1);

                hdr.ecmp.seq = cnt; // seq number for each pkt

                ecmp_group.apply();
                ecmp_nhop.apply();
            } else {
                ipv4_lpm.apply();
            }
            
        }
    }
}

/*************************** Egress ***************************/

control myEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // count the number of bytes seen since the last probe
    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    
    // set the mac address of source to smac
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table send_frame {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
        size = 256;
    }

    apply {
        if (hdr.ecmp.is_load_balance == 1) {
            send_frame.apply();
        }

        if (hdr.ecmp.is_track == 1) {
            if ((bit<32>)standard_metadata.egress_port == 2) {
                bit<32> p2_byte;
                byte_cnt_reg.read(p2_byte, 2);
                hdr.ecmp.port2_bytes = p2_byte + standard_metadata.packet_length;
                byte_cnt_reg.write(2, p2_byte + standard_metadata.packet_length);

                bit<32> p3_byte;
                byte_cnt_reg.read(p3_byte, 3);
                hdr.ecmp.port3_bytes = p3_byte;
            } else if ((bit<32>)standard_metadata.egress_port == 3) {
                bit<32> p2_byte;
                byte_cnt_reg.read(p2_byte, 2);
                hdr.ecmp.port2_bytes = p2_byte;

                bit<32> p3_byte;
                byte_cnt_reg.read(p3_byte, 3);
                hdr.ecmp.port3_bytes = p3_byte + standard_metadata.packet_length;
                byte_cnt_reg.write(3, p3_byte + standard_metadata.packet_length);
            }
            hdr.ecmp.is_track = 0;
        }
    }
}

/*************************** Checksum computation ***************************/

control myComputeChecksum(inout headers hdr, inout metadata meta) {
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


/*************************** Deparser ***************************/

control myDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ecmp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************** Switch ***************************/

V1Switch(
    myParser(),
    myVerifyChecksum(),
    myIngress(),
    myEgress(),
    myComputeChecksum(),
    myDeparser()
) main;

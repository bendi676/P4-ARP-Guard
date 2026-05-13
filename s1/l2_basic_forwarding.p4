/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
const bit<16> TYPE_ARP = 0x0806;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16>   htype;   
    bit<16>   ptype;   
    bit<8>    hlen;    
    bit<8>    plen;    
    bit<16>   opcode;  
    macAddr_t sha;     // Sender Hardware Address (MAC)
    bit<32>   spa;     // Sender Protocol Address (IP)
    macAddr_t tha;     
    bit<32>   tpa;     
}

struct metadata {
}

struct headers {
    ethernet_t ethernet;
    arp_t      arp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        // Only transition to parse_arp if it is an ARP packet
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N    *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    counter(256, CounterType.packets) arp_spoof_counter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action drop_spoofed_arp() {
        arp_spoof_counter.count((bit<32>) standard_metadata.ingress_port);
        mark_to_drop(standard_metadata);
    }

    action permit() { 
        // Successful ARP authentication match
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table arp_exact {
        key = {
            hdr.arp.spa: exact;
            hdr.arp.sha: exact;
        }
        actions = {
            permit;
            drop_spoofed_arp;
        }
        size = 1024;
        default_action = drop_spoofed_arp();
    }

    table mac_forward {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        // Only packets containing ARP header are processed
        if (hdr.arp.isValid()) {
            // Check if the IP-MAC binding exists
            if (arp_exact.apply().hit) {
                mac_forward.apply();
            }
        }
        // If it is not a valid ARP packet, it'll be dropped by the switch 
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N    **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {  }
}

/*************************************************************************
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //Reassemble the packet before it leaves
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
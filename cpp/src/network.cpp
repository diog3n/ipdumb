#include "network.h"
#include <cstdint>
#include <memory>
#include <sstream>
#include <linux/if_ether.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>

/* There probably is a better way to do this but haven't come up 
 * with something better yet */
IpAddress::IpAddress(uint32_t raw_address):
    oct1{static_cast<uint8_t>((raw_address & (255 << 24)) >> 24)},
    oct2{static_cast<uint8_t>((raw_address & (255 << 16)) >> 16)},
    oct3{static_cast<uint8_t>((raw_address & (255 << 8 )) >> 8 )},
    oct4{static_cast<uint8_t>( raw_address & 255)},
    raw_ip(raw_address) {}

std::string IpAddress::GetAddressString() const {
    std::ostringstream out;

    out << static_cast<unsigned int>(oct1) << "." 
        << static_cast<unsigned int>(oct2) << "." 
        << static_cast<unsigned int>(oct3) << "." 
        << static_cast<unsigned int>(oct4);

    return out.str();
}

uint32_t IpAddress::GetRawIPAddress() const {
    return raw_ip;
}

std::ostream& operator<<(std::ostream& out, const IpAddress& addr) {
    out << addr.GetAddressString();
    return out;
}


// ================ EthernetFrame ================ 

EthernetFrame::EthernetFrame(const pcap_pkthdr& packet_header, 
                             const u_char *bytes)
    : raw_header(*((ethhdr * ) bytes))
    , frame(bytes, bytes + packet_header.caplen) {
    
    /* Move pointer to the start of the packet */
    const u_char *packet_start = frame.data() + sizeof(ethhdr);

    if (ntohs(raw_header.h_proto) == ETHERTYPE_IP) {
        packet_ptr = std::make_unique<IPv4Packet>(packet_start);
    }
}

const ethhdr& EthernetFrame::GetRawHeader() const {
    return raw_header;
}

const Packet *EthernetFrame::GetPacket() const {
    return packet_ptr.get();
}

const IPv4Packet *EthernetFrame::GetIPv4Packet() const {
    return (IPv4Packet * ) packet_ptr.get();
}

const uint16_t EthernetFrame::GetNetworkProtocolType() const {
    return ntohs(raw_header.h_proto);
} 


// ================ IPv4Packet ================

IPv4Packet::IPv4Packet(const u_char *packet_start)
        : raw_header(*(iphdr * ) packet_start)
        , source_ip(ntohl(raw_header.saddr))
        , dest_ip(ntohl(raw_header.daddr)) {
            
    /* Move pointer to the start of the segment */            
    const u_char *segment_start = packet_start + raw_header.ihl * 4;
    
    switch (raw_header.protocol) {
        case IP_PROTOCOL_TCP:
            transport_segment_ptr = 
                            std::make_unique<TCPSegment>(segment_start);
            break;
        case IP_PROTOCOL_UDP:
            transport_segment_ptr = 
                            std::make_unique<UDPSegment>(segment_start);
            break;
        case IP_PROTOCOL_ICMP:
            transport_segment_ptr = 
                           std::make_unique<ICMPSegment>(segment_start);
            break;
    }
}

const iphdr& IPv4Packet::GetRawHeader() const {
    return raw_header;
}

const uint8_t IPv4Packet::GetTransportProtoType() const {
    return raw_header.protocol;
}

const Segment *IPv4Packet::GetSegment() const {
    return transport_segment_ptr.get();
}

const IpAddress& IPv4Packet::GetSourceIP() const {
    return source_ip;
}

const IpAddress& IPv4Packet::GetDestIP() const {
    return dest_ip;
}

// ================ TCPSegment ================

TCPSegment::TCPSegment(const u_char *segment_start)
    : raw_header(*((tcphdr * ) segment_start)) {}

const tcphdr& TCPSegment::GetRawHeader() const {
    return raw_header;
}

const uint16_t TCPSegment::GetSourcePort() const {
    return ntohs(raw_header.th_sport);
}

const uint16_t TCPSegment::GetDestPort() const {
    return ntohs(raw_header.th_dport);
}

// ================ UDPSegment ================

UDPSegment::UDPSegment(const u_char *segment_start)
    : raw_header(*((udphdr * ) segment_start)) {}

const udphdr& UDPSegment::GetRawHeader() const {
    return raw_header;
}

const uint16_t UDPSegment::GetSourcePort() const {
    return ntohs(raw_header.uh_sport);
}

const uint16_t UDPSegment::GetDestPort() const {
    return ntohs(raw_header.uh_dport);
}

// =============== ICMPSegment ================

ICMPSegment::ICMPSegment(const u_char *segment_start)
    : raw_header(*((icmphdr * ) segment_start)) {}

const icmphdr& ICMPSegment::GetRawHeader() const {
    return raw_header;
}
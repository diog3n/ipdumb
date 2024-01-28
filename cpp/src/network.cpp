#include "network.h"
#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <ios>
#include <linux/if_ether.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>

IpAddress::IpAddress(uint32_t bin_address):
    oct1{static_cast<uint8_t>((bin_address & (255 << 24)) >> 24)},
    oct2{static_cast<uint8_t>((bin_address & (255 << 16)) >> 16)},
    oct3{static_cast<uint8_t>((bin_address & (255 << 8 )) >> 8 )},
    oct4{static_cast<uint8_t>( bin_address & 255)} {}

std::string IpAddress::GetAddressString() const {
    std::ostringstream out;

    out << static_cast<unsigned int>(oct1) << "." 
        << static_cast<unsigned int>(oct2) << "." 
        << static_cast<unsigned int>(oct3) << "." 
        << static_cast<unsigned int>(oct4);

    return out.str();
}

// ================ EthernetFrame ================ 

EthernetFrame::EthernetFrame(const pcap_pkthdr& packet_header, 
                             u_char *bytes)
    : raw_header(*((ethhdr * ) bytes))
    , frame(bytes, bytes + packet_header.caplen) {
    
    u_char *packet_start = frame.data() + sizeof(ethhdr);
    
    if (raw_header.h_proto == ETHERTYPE_IP) {
        packet = IPv4Packet(packet_start);
    }
}

const ethhdr& EthernetFrame::GetRawHeader() const {
    return raw_header;
}

const Packet& EthernetFrame::GetPacket() const {
    return packet;
}

// ================ IPv4Packet ================

IPv4Packet::IPv4Packet(u_char *packet_start)
        : raw_header(*(iphdr * ) packet_start)
        , source_ip(ntohl(raw_header.saddr))
        , dest_ip(ntohl(raw_header.daddr)) {

    u_char *segment_start = packet_start + raw_header.ihl;
    
    switch (raw_header.protocol) {
        case IP_PROTOCOL_TCP:
            transport_segment = TCPSegment(segment_start);
            break;
        case IP_PROTOCOL_UDP:
            transport_segment = UDPSegment(segment_start);
            break;
        case IP_PROTOCOL_ICMP:
            transport_segment = ICMPSegment(segment_start);
            break;
    }
}

const iphdr& IPv4Packet::GetRawHeader() const {
    return raw_header;
}

const Segment& IPv4Packet::GetSegment() const {
    return transport_segment;
}

const IpAddress& IPv4Packet::GetSourceIP() const {
    return source_ip;
}

const IpAddress& IPv4Packet::GetDestIP() const {
    return dest_ip;
}

// ================ TCPSegment ================

TCPSegment::TCPSegment(u_char *segment_start)
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

UDPSegment::UDPSegment(u_char *segment_start)
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

ICMPSegment::ICMPSegment(u_char *segment_start)
    : raw_header(*((icmphdr * ) segment_start)) {}

const icmphdr& ICMPSegment::GetRawHeader() const {
    return raw_header;
}

// ============================================

void PacketHandler(u_char *args, 
                   const struct pcap_pkthdr *pkthdr,
                   const u_char *packet) {
    const ethhdr *eth_header = (ethhdr * ) packet;

    if (ntohs(eth_header->h_proto) != ETHERTYPE_IP) {
        return;
    }

    const iphdr *ip_header = (iphdr * ) (packet + sizeof(ethhdr));
    std::string transport_protocol_message;

    if (ip_header->protocol == IP_PROTOCOL_TCP) {
        transport_protocol_message = "TCP header";
    } else if (ip_header->protocol == IP_PROTOCOL_UDP) {
        transport_protocol_message = "UDP header";
    } else {
        transport_protocol_message = "Unknown header";
    }

    const tcphdr *transport_header = (tcphdr * ) (packet + sizeof(ethhdr) 
                                   + (ip_header->ihl) * 4);

    /* translate source and destination address into a readeable format */
    const IpAddress ip_source(ntohl(ip_header->saddr));
    const IpAddress ip_dest(ntohl(ip_header->daddr));

    std::cout << "[" << pkthdr->ts.tv_sec
              << "] IP packet, source address is "
              << ip_source.GetAddressString()
              // << " (hex netlong: " << std::hex << ip_header->saddr << ")" 
              << " and destitation address is "
              << ip_dest.GetAddressString() 
              // << " (hex netlong: " << std::hex << ip_header->daddr << ")"
              << std::endl;

    std::cout << transport_protocol_message 
              << " source port is " << std::dec
              << ntohs(transport_header->th_sport)
              << " and destination port is "
              << ntohs(transport_header->th_dport) 
              << std::endl;
}

void PrintHEX(const u_char *payload, int len) {
    int i;
    int gap;
    const u_char *ch;

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (i != 0 && i % 16 == 0) printf("\n");

        printf("%02x ", *ch);
        ch++;
    }

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    printf("\n");
}
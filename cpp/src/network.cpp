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
    
    u_char *packet_start = frame.data() + sizeof(ethhdr);

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

const uint16_t EthernetFrame::GetNetworkProtocolType() const {
    return ntohs(raw_header.h_proto);
} 


// ================ IPv4Packet ================

IPv4Packet::IPv4Packet(u_char *packet_start)
        : Packet(NetworkProto::IPV4)
        , raw_header(*(iphdr * ) packet_start)
        , source_ip(ntohl(raw_header.saddr))
        , dest_ip(ntohl(raw_header.daddr)) {

    u_char *segment_start = packet_start + raw_header.ihl * 4;
    
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

TCPSegment::TCPSegment(u_char *segment_start)
    : Segment(TransportProto::TCP)
    , raw_header(*((tcphdr * ) segment_start)) {}

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
    : Segment(TransportProto::UDP)
    , raw_header(*((udphdr * ) segment_start)) {}

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
    : Segment(TransportProto::ICMP)
    , raw_header(*((icmphdr * ) segment_start)) {}

const icmphdr& ICMPSegment::GetRawHeader() const {
    return raw_header;
}

// ============================================

void PacketHandler(u_char *args, 
                   const struct pcap_pkthdr *pkthdr, 
                   const u_char *packet) {
    const EthernetFrame eth_frame(*pkthdr, packet);

    if (eth_frame.GetNetworkProtocolType() != ETHERTYPE_IP) {
        return;
    }

    const IPv4Packet *ipv4_packet = (const IPv4Packet * ) 
                                    eth_frame.GetPacket();
    
    std::cout << "IPv4 packet, source address is " 
              << ipv4_packet->GetSourceIP().GetAddressString()
              << " and destination address is "
              << ipv4_packet->GetDestIP().GetAddressString()
              << std::endl; 

    switch (ipv4_packet->GetTransportProtoType()) { 
        case IP_PROTOCOL_TCP: {
            const TCPSegment *segment = (const TCPSegment * )
                                        ipv4_packet->GetSegment();

            std::cout << "TCP segment, source port is "
                      << segment->GetSourcePort()
                      << " and destination port is "
                      << segment->GetDestPort() 
                      << std::endl;
            break;
        }
        case IP_PROTOCOL_UDP: {
            const UDPSegment *segment = (const UDPSegment * )
                                        ipv4_packet->GetSegment();

            std::cout << "UDP segment, source port is "
                      << segment->GetSourcePort()
                      << " and destination port is "
                      << segment->GetDestPort() 
                      << std::endl;
            break;
        }
        case IP_PROTOCOL_ICMP: {
            std::cout << "ICMP segment" << std::endl;
        }
    }
}
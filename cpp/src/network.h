#pragma once
#include <cstddef>
#include <variant>
#include <memory>
#include <pcap/pcap.h>
#include <string>
#include <cstdint>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <vector>

#define IP_PROTOCOL_TCP  0x06
#define IP_PROTOCOL_UDP  0x11
#define IP_PROTOCOL_ICMP 0x01

class IPv4Packet;
class TCPSegment;
class UDPSegment;
class ICMPSegment;

class EthernetFrame;

/* these can be later expanded to include other protocols */
using Packet  = std::variant<std::monostate,
                             IPv4Packet>;

using Segment = std::variant<std::monostate,
                             TCPSegment, 
                             UDPSegment, 
                             ICMPSegment>;

struct IpAddress;

struct IpAddress { 
    uint8_t oct1;
    uint8_t oct2;
    uint8_t oct3;
    uint8_t oct4;

    IpAddress(uint32_t bin_address);
    std::string GetAddressString() const;
};

class TCPSegment {
public:
    TCPSegment(u_char *segment_start);

    const tcphdr& GetRawHeader() const;
    const uint16_t GetSourcePort() const;
    const uint16_t GetDestPort() const;
private:
    tcphdr raw_header;
};

class UDPSegment {
public:
    UDPSegment(u_char *segemnt_start);

    const udphdr& GetRawHeader() const;
    const uint16_t GetSourcePort() const;
    const uint16_t GetDestPort() const;
private:
    udphdr raw_header;
};

class ICMPSegment {
public:
    ICMPSegment(u_char *segment_start);

    const icmphdr& GetRawHeader() const;
private:
    icmphdr raw_header;
};

class IPv4Packet {
public:
    IPv4Packet(u_char *packet_start);

    const iphdr& GetRawHeader() const;
    const Segment& GetSegment() const;
    const IpAddress& GetSourceIP() const;
    const IpAddress& GetDestIP() const;
private:
    iphdr raw_header;
    IpAddress source_ip;
    IpAddress dest_ip;

    Segment transport_segment;
};

class EthernetFrame {
public:
    EthernetFrame(const pcap_pkthdr& packet_header, u_char *bytes);

    const ethhdr& GetRawHeader() const;
    const Packet& GetPacket() const;
private:
    ethhdr raw_header;
    Packet packet;
    std::vector<u_char> frame;
};

void PacketHandler(u_char *args, 
                   const struct pcap_pkthdr *pkthdr,
                   const u_char *packet);

void PrintHEX(const u_char *payload, int len);
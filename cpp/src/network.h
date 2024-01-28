#pragma once
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

enum class TransportProto {NONE, TCP, UDP, ICMP};

/* this can be expanded in the future to include IPv6 and other
 * network-layer protocols */
enum class NetworkProto {NONE, IPV4};

class Packet;
class Segment;

class IPv4Packet;
class TCPSegment;
class UDPSegment;
class EthernetFrame;
class ICMPSegment;

struct IpAddress;

struct IpAddress { 
    uint8_t oct1;
    uint8_t oct2;
    uint8_t oct3;
    uint8_t oct4;

    IpAddress(uint32_t bin_address);
    std::string GetAddressString() const;
};

class Segment {
public:
    Segment(): type(TransportProto::NONE) {}

    Segment(TransportProto proto): type(proto) {}

    const TransportProto type;
};

class Packet {
public:
    Packet(): type(NetworkProto::NONE) {}

    Packet(NetworkProto proto): type(proto) {}

    const NetworkProto type;
};

class EthernetFrame {
public:
    EthernetFrame(const pcap_pkthdr& packet_header, const u_char *bytes);

    const ethhdr& GetRawHeader() const;
    const Packet *GetPacket() const;
    const uint16_t GetNetworkProtocolType() const; 
private:
    ethhdr raw_header;
    std::vector<u_char> frame;

    std::unique_ptr<Packet> packet_ptr;
};

class IPv4Packet: public Packet {
public:
    IPv4Packet(u_char *packet_start);

    const iphdr& GetRawHeader() const;
    const uint8_t GetTransportProtoType() const;
    const Segment *GetSegment() const;
    const IpAddress& GetSourceIP() const;
    const IpAddress& GetDestIP() const;
private:
    iphdr raw_header;
    IpAddress source_ip;
    IpAddress dest_ip;

    std::unique_ptr<Segment> transport_segment_ptr;
};

class TCPSegment: public Segment {
public:
    TCPSegment(u_char *segment_start);

    const tcphdr& GetRawHeader() const;
    const uint16_t GetSourcePort() const;
    const uint16_t GetDestPort() const;
private:
    tcphdr raw_header;
};

class UDPSegment: public Segment {
public:
    UDPSegment(u_char *segment_start);

    const udphdr& GetRawHeader() const;
    const uint16_t GetSourcePort() const;
    const uint16_t GetDestPort() const;
private:
    udphdr raw_header;
};

class ICMPSegment: public Segment {
public:
    ICMPSegment(u_char *segment_start);

    const icmphdr& GetRawHeader() const;
private:
    icmphdr raw_header;
};

void PacketHandler(u_char *args, 
                   const struct pcap_pkthdr *pkthdr,
                   const u_char *packet);

void PrintHEX(const u_char *payload, int len);
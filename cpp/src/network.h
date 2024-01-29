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

#define UDP_HEADER_SIZE  8

/* A generic Packet class. Every network-layer protocol class 
 * should inherit from this for the sake of readability. */
class Packet;

/* Generic Transport Segment class. Evely transport-layer protocol
 * shoult inherit from this for the sake of readability. */
class Segment;

/* Specific classes for data-link, network, transport layers. */
class IPv4Packet;
class TCPSegment;
class UDPSegment;
class EthernetFrame;
class ICMPSegment;

/* A simple struct that allows to store and print IP address in a more
 * familiar fashion. */
struct IpAddress;

class IpAddress { 
public:
    IpAddress(uint32_t bin_address);
    std::string GetAddressString() const;
    uint32_t GetRawIPAddress() const;

private:
    uint8_t oct1;
    uint8_t oct2;
    uint8_t oct3;
    uint8_t oct4;

    uint32_t raw_ip;
};

std::ostream& operator<<(std::ostream& out, const IpAddress& addr);

/* These do not have anything inside (yet?) */
class Segment {};
class Packet {};

/* This class is not just a ethhdr wrapper, it actually encapsulates 
 * data inside. */
class EthernetFrame {
public:
    EthernetFrame(const pcap_pkthdr& packet_header, const u_char *bytes);

    const ethhdr& GetRawHeader() const;
    const Packet *GetPacket() const;
    const IPv4Packet *GetIPv4Packet() const;
    const uint16_t GetNetworkProtocolType() const; 
private:
    /* raw_header is still used to get some specific details */
    ethhdr raw_header;

    /* This class stores packet bytes inside to protect them from
     * invalidation. */
    const std::vector<u_char> frame;

    /* A generic pointer to the packet that can be casted to a 
     * specific packet later. */
    std::unique_ptr<Packet> packet_ptr;
};

/* This class encapsulates transport segment inside via pointer. Since
 * IPv4Packet class is usually created when constructing an EthernetFrame
 * instance, storing data bytes inside is unnecessary. */
class IPv4Packet: public Packet {
public:
    IPv4Packet(const u_char *packet_start);

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

/* Following classes are pretty simple in structure due to a given
 * functionality: only thing we really need is raw_header where src/dst
 * ports are stored. */

class TCPSegment: public Segment {
public:
    TCPSegment(const u_char *segment_start);

    const tcphdr& GetRawHeader() const;
    const uint16_t GetSourcePort() const;
    const uint16_t GetDestPort() const;
private:
    tcphdr raw_header;
};

class UDPSegment: public Segment {
public:
    UDPSegment(const u_char *segment_start);

    const udphdr& GetRawHeader() const;
    const uint16_t GetSourcePort() const;
    const uint16_t GetDestPort() const;
private:
    udphdr raw_header;
};

/* This was created just for fun and experimentation. */
class ICMPSegment: public Segment {
public:
    ICMPSegment(const u_char *segment_start);

    const icmphdr& GetRawHeader() const;
private:
    icmphdr raw_header;
};
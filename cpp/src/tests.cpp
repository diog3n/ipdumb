#include "tests.h"
#include "network.h"
#include <cassert>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

void TestIpAddress() {
    using namespace std::literals;

    // 192.168.0.1 = 11000000.10101000.00000000.00000001 
    IpAddress ip1(0b11000000101010000000000000000001);
    assert(ip1.GetAddressString() == "192.168.0.1"s);

    // 172.16.64.101 = 10101100.00010000.01000000.01100101
    IpAddress ip2(0b10101100000100000100000001100101);
    assert(ip2.GetAddressString() == "172.16.64.101"s);

    // 255.255.255.255 = 11111111.11111111.11111111.11111111
    IpAddress ip3(0b11111111111111111111111111111111);
    assert(ip3.GetAddressString() == "255.255.255.255"s);

    // 0.0.0.0 = 00000000.00000000.00000000.00000000
    IpAddress ip4(0b00000000000000000000000000000000);
    assert(ip4.GetAddressString() == "0.0.0.0"s);

    TEST_STREAM << "TestIpAddress OK!" << std::endl;
}

void TestHeaders() {
    using namespace std::literals;

    /* A test packet */
    u_char packet[] = {
        0x50, 0xd2, 0xf5, 0x9a, 0xfd, 0xea, 0xbc, 0x54, 
        0x2f, 0xd0, 0xe9, 0x45, 0x08, 0x00, 0x45, 0x00, 
        0x00, 0x34, 0xa1, 0x5d, 0x40, 0x00, 0x40, 0x06, 
        0xa3, 0x91, 0xc0, 0xa8, 0x1f, 0x64, 0x22, 0x6b, 
        0xf3, 0x5d, 0x8c, 0x02, 0x01, 0xbb, 0xc0, 0x5b, 
        0xda, 0x67, 0xee, 0x4f, 0xb6, 0x0e, 0x80, 0x10, 
        0x00, 0xf4, 0xf5, 0xfb, 0x00, 0x00, 0x01, 0x01, 
        0x08, 0x0a, 0x1a, 0x94, 0x24, 0x97, 0x27, 0x58, 
        0x94, 0x8c
    };

    pcap_pkthdr p_pkthdr = {{}, 66, 66};

    EthernetFrame eth_frame(p_pkthdr, packet);

    for (int i = 0; i < 66; i++) {
        packet[i] = 0;
    }

    assert(ntohs(eth_frame.GetRawHeader().h_proto) == ETHERTYPE_IP);

    const IPv4Packet *ipv4_pack = (const IPv4Packet * ) 
                                  (eth_frame.GetPacket());
    assert(ipv4_pack != nullptr);

    assert(ipv4_pack->GetSourceIP()
                    .GetAddressString() == "192.168.31.100");
    assert(ipv4_pack->GetDestIP()
                    .GetAddressString() == "34.107.243.93");
    assert(ipv4_pack->GetSegment()->type == TransportProto::TCP);

    const TCPSegment *tcp_segment = (const TCPSegment * ) 
                                    (ipv4_pack->GetSegment());
    
    assert(tcp_segment->GetSourcePort() == 0x8c02);
    assert(tcp_segment->GetDestPort() == 0x01bb);

    TEST_STREAM << "TestHeaders OK!" << std::endl;
}

/*
    one before last captured packet in the "capture" file

    ETHER HEADER

    50 d2 f5 9a fd ea MAC DEST

    bc 54 2f d0 e9 45 MAC SRC

    08 00             PROTO

    IP HEADER

    45                VERSION (4), IHL (5) 
    
    00                DIFF. SERVICES FIELD 

    00 34             TOTAL SIZE 

    a1 5d             IDENTIFICATION 

    40 00             FLAGS (010 - Do not fragment), OFFSET (0)

    40                TTL 

    06                PROTOCOL (TCP)
    
    a3 91             HEADER CHECKSUM

    c0 a8 1f 64       SOURCE IP ADDRESS      (192.168.31.100)
  
    22 6b f3 5d       DESTINATION IP ADDRESS (34.107.243.93)

    TCP HEADER

    8c 02             SOURCE PORT 

    01 bb             DESTINATION PORT

    ...

    WHOLE FRAME

    50 d2 f5 9a fd ea bc 54 2f d0 e9 45 08 00 45 00
    00 34 a1 5d 40 00 40 06 a3 91 c0 a8 1f 64 22 6b
    f3 5d 8c 02 01 bb c0 5b da 67 ee 4f b6 0e 80 10
    00 f4 f5 fb 00 00 01 01 08 0a 1a 94 24 97 27 58
    94 8c




*/


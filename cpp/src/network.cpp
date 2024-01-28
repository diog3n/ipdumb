#include "network.h"
#include <cstdint>
#include <sstream>
#include <ios>
#include <linux/if_ether.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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

void PacketHandler(u_char *args, 
                    const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
    const ethhdr *eth_header = (ethhdr * ) packet;

    if (ntohs(eth_header->h_proto) != ETHERTYPE_IP) {
        return;
    }

    const iphdr *ip_header = (iphdr * ) (packet + sizeof(ethhdr));

    const tcphdr *tcp_header = (tcphdr * ) (packet + sizeof(ethhdr) 
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

    std::cout << "TCP header, source port is " << std::dec
              << ntohs(tcp_header->th_sport)
              << " and destination port is "
              << ntohs(tcp_header->th_dport) 
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
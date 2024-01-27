#include "network.h"
#include "tests.h"

#include <ios>
#include <linux/if_ether.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>

void print_packet_info(const u_char *packet, 
                       struct pcap_pkthdr packet_header);

void packet_handler(u_char *args, 
                    const struct pcap_pkthdr *pkthdr,
                    const u_char *packet);



int main(int argc, char *argv[]) {
    TestIpAddress();
    TestHeaders();

    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    pcap_if_t *devs;
    int findall_result = pcap_findalldevs(&devs, error_buffer);
    if (findall_result == PCAP_ERROR) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    if (devs == NULL) {
        printf("Error: No devices found!\n");
        return 1;
    }

    pcap_if_t *current_dev = devs;

    while (current_dev != NULL) {
        printf("Found device: %s\n", current_dev->name);
        current_dev = current_dev->next;
    }

    device = devs->name;

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

    if (handle == NULL) {
        printf("Error: failed to get a handle. %s\n", error_buffer);
        return 1;
    }

    /* We use 0 as cnt, this means unlimited or until file ends. */
    int loop_status = pcap_dispatch(handle, 0, packet_handler, NULL); 

    pcap_close(handle);

    return 0;
}

void print_packet_info(const u_char *packet, 
                       struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void packet_handler(u_char *args, 
                    const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
    ethhdr *eth_header;
    
    /* get the ethernet frame header */
    eth_header = (struct ethhdr * ) packet;

    std::cerr << "(DEBUG) Bytes of the packet: ";
    for (int pos = 0; pos < 64; pos++) {
        std::cerr << std::hex << static_cast<int>(*(packet + pos)) << " ";
    }
    std::cerr << std::endl;

    /* if frame does not carry an IP address - ignore it */
    if (ntohs(eth_header->h_proto) == ETHERTYPE_IP) return;


    /* calculate the start of ip header */
    iphdr *ip_header = (struct iphdr * ) (packet + sizeof(ethhdr));

    std::cerr << "(DEBUG) iphdr version = " << (ip_header->version) << std::endl;
    std::cerr << "(DEBUG) iphdr ihl = " << (ip_header->ihl & 0xf) << std::endl;

    /* calculate the start of tcp header */
    tcphdr *tcp_header = (struct tcphdr * ) 
                         (packet + sizeof(ethhdr) 
                                 + (ip_header->ihl & 0xf) * 4);

    /* translate source and destination address into a readeable format */
    const IpAddress ip_source(ntohl(ip_header->saddr));
    const IpAddress ip_dest(ntohl(ip_header->daddr));

    std::cout << "IP packet, source address is "
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

/*int main() {
    std::cout << "Hello world" << std::endl;

    return 0;
}*/
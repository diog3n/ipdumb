#include "network.h"
#include "tests.h"

#include <linux/if_ether.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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
    /*handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );*/
    
    handle = pcap_open_offline("../capture.pcap", error_buffer);

    if (handle == NULL) {
        printf("Error: failed to get a handle. %s\n", error_buffer);
        return 1;
    }

    /* We use 0 as cnt, this means unlimited or until file ends. */
    int loop_status = pcap_loop(handle, 0, PacketHandler, NULL); 

    pcap_close(handle);

    return 0;
}
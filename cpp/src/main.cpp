#include "command_line.h"
#include "network.h"
#include "sequence.h"

#include <cstdlib>
#include <fstream>
#include <thread>
#include <cstring>
#include <pcap.h>
#include <pcap/pcap.h>

#define EXIT_KEY 'q'

int main(int argc, char *argv[]) {
    /* If user didn't supply enough arguments, print usage. */
    if (argc < 4) {
        PrintUsage();
        return 1;
    }

    /* Boolean variable that is used to exit out of the main loop
     * when capturing from device. */
    bool exiting = false;
    bool finished_reading = false;

    /* PCAP will write error messages here. */
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    /* A triplet of pointers used for reading a packet from 
     * device/file. */
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr *packet_header;

    /* Sequence of IP packets */
    Sequence sequence;

    if (strcmp(argv[1], "dev") == 0) {

        /* Parameters of live reading from device.
         * please, note, that you may need root privileges for live
         * capture directly from device */
        int packet_count_limit = 1;
        int timeout_limit = 10000; /* In milliseconds */
        
        /* Device name as it is in the system. For example: eth0 */
        char *device = argv[2]; 

        /* Opening a device for live capture */
        handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

    } else if (strcmp(argv[1], "file") == 0) {
        /* Name of the .pcap file. */
        char *filename = argv[2];

        /* There's no need for root privileges when reading from
         * file. */
        handle = pcap_open_offline(filename, error_buffer);
    }

    /* If pcap failed to obtain handle, abort */
    if (handle == NULL) {
        printf("%s\n", error_buffer);
        return 1;
    }

    /* This is a lambda-expression that is used for checking
     * if a EXIT_KEY was pressed. It's pretty basic and barebones. */
    auto key_reader = [&exiting, &finished_reading]() {
        while(!exiting && !finished_reading) {
            char c;
            c = getchar(); 
            if(c == EXIT_KEY) {
                std::cout << "Finishing up..." << std::endl;
                exiting = true;
            }  
        }
    };

    std::cout << "Type " << EXIT_KEY 
              << " in to stop cature and dump info into a file." 
              << std::endl;

    /* Running a thread alongside main thread to read keypresses. */
    std::thread key_thread(key_reader);

    while (!exiting && !finished_reading) {
        
        /* Read next packet from capture file or device. */
        int read_status = pcap_next_ex(handle, &packet_header, &packet);
        EthernetFrame frame(*packet_header, packet);

        if (read_status == PCAP_ERROR_BREAK) {
            std::cout << "Finished reading." << std::endl;
            finished_reading = true;
            break;
        }

        if (read_status == 0) {
            std::cout << "Packet timeout reached. Finished." << std::endl;
            break;
        }

        /* This piece of software only works with IPv4 packets for now. */
        if (frame.GetNetworkProtocolType() != ETHERTYPE_IP) continue;
        
        /* If IP packet does not carry TCP or UDP - skip it*/
        if (frame.GetIPv4Packet()
                ->GetTransportProtoType() != IP_PROTOCOL_TCP && 
            frame.GetIPv4Packet()
                ->GetTransportProtoType() != IP_PROTOCOL_UDP) continue;

        SequenceEntry entry{frame};

        std::cout << "IPv4 packet: " << entry << std::endl; 

        /* Add an entry to the sequence. */
        sequence.AddSequenceEntry(entry, GetPacketSize(frame));

    }
    
    if (!exiting) std::cout << "Press any key to exit..." << std::endl;
        
    /* Wait for key_reader function to finish. */
    key_thread.join();

    /* Dump sequence into the given file. */
    std::ofstream file_out(argv[3], std::ios::out);
    sequence.PrintSequence(file_out);

    pcap_close(handle);

    return 0;
}
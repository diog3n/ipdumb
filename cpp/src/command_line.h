#pragma once
#include <iostream>

inline void PrintUsage() {
    std::cout << "Usage:\n" 
              << "    ipdump [dev|file] [device_name|capture_file.pcap] "
              << "<output_file_name.csv>\n" 
              << "    to dump info into a file\n"
              << "Or\n"
              << "    ipdump [dev|file] [device_name|capture_file.pcap]\n" 
              << "    to dump info into a terminal\n"
              << "Note: you may need root privileges to read from device."
              << std::endl;
}
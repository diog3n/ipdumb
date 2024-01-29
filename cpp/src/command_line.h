#pragma once
#include <iostream>

inline void PrintUsage() {
    std::cout << "Usage:\n" 
              << "    ipdump [dev|file] [device_name|capture_file_name.pcap] "
              << "<output_file_name.csv>" << std::endl;
}
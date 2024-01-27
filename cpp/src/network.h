#pragma once
#include <cstdint>
#include <string>

struct IpAddress { 
    uint8_t oct1;
    uint8_t oct2;
    uint8_t oct3;
    uint8_t oct4;

    IpAddress(uint32_t bin_address);
    std::string GetAddressString() const;
};
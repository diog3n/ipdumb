#include "network.h"
#include <cstdint>
#include <sstream>

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
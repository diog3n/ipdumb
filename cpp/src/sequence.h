#pragma once
#include "network.h"

#include <cstdint>
#include <netinet/ether.h>
#include <ostream>
#include <unordered_map>

/* SequenceEntry is a line that contains src/dst ip, transport type, 
 * and src/dst ports */
class SequenceEntry {
public:
    SequenceEntry(const EthernetFrame& frame);

    const IpAddress& GetSourceIP() const;

    const IpAddress& GetDestIP() const;

    const uint8_t GetTransportType() const;

    const uint16_t GetTransportSourcePort() const;
    
    const uint16_t GetTransportDestPort() const;

    bool operator==(const SequenceEntry& other) const;

    /* Hasher turns SequenceEntry into a unique number. This will allow 
     * us to quickly unite multiple entries under one sequence. */
    struct SequenceEntryHasher {
        size_t operator()(const SequenceEntry& entry) const {
            std::hash<uint32_t> int32_hasher;
            std::hash<uint16_t> int16_hasher;
            std::hash<uint8_t> type_hasher;

            return int32_hasher(entry.ip_source.GetRawIPAddress())
                 + int32_hasher(entry.ip_source.GetRawIPAddress()) * 37
                 + int16_hasher(entry.tr_source) * 37 * 37
                 + int16_hasher(entry.tr_dest) * 37 * 37 * 37;
        }
    };
private:
    IpAddress ip_source;
    IpAddress ip_dest;

    uint8_t tr_type;

    uint16_t tr_source;
    uint16_t tr_dest;
};

std::ostream& operator<<(std::ostream& out, const SequenceEntry& entry);

/* Sequence is a set of packets with the same source and destination 
 * IP addresses and same source and destination TCP/UDP ports */
class Sequence {
public:
    void AddSequenceEntry(const SequenceEntry& entry, 
                          const uint16_t bytes);

    void PrintSequence(std::ostream& out) const;
private:
    struct PacketStats {
        uint32_t bytes = 0;
        uint32_t packet_count = 0;
    };

    /* Maps SequenceEntry to a pair of <bytes, packet count> */
    std::unordered_map<SequenceEntry, PacketStats,
                       SequenceEntry::SequenceEntryHasher> entries;
};

/* This function returns data payload size, not the size of the whole 
 * frame. That's the reason why some packets may have size == 0 or why
 * some sequences will have surprisingly low amounts of transferred data.
 *
 * Note: Everything past tranport layer is considered data payload */
uint16_t GetPacketSize(const EthernetFrame& frame);
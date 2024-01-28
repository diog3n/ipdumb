#pragma once
#include "network.h"

#include <cstdint>
#include <netinet/ether.h>
#include <ostream>
#include <unordered_map>

class SequenceEntry {
public:
    SequenceEntry(const EthernetFrame& frame);

    const IpAddress& GetSourceIP() const;

    const IpAddress& GetDestIP() const;

    const TransportProto GetTransportType() const;

    const uint16_t GetTransportSourcePort() const;
    
    const uint16_t GetTransportDestPort() const;

    bool operator==(const SequenceEntry& other) const;

    struct SequenceEntryHasher {
        size_t operator()(const SequenceEntry& entry) const {
            std::hash<uint32_t> int32_hasher;
            std::hash<uint16_t> int16_hasher;
            std::hash<TransportProto> type_hasher;

            return int32_hasher(entry.ip_source.GetRawIPAddress())
                 + int32_hasher(entry.ip_source.GetRawIPAddress()) * 37
                 + int16_hasher(entry.tr_source) * 37 * 37
                 + int16_hasher(entry.tr_dest) * 37 * 37 * 37;
        }
    };
private:
    IpAddress ip_source;
    IpAddress ip_dest;

    TransportProto tr_type;

    uint16_t tr_source;
    uint16_t tr_dest;
};

/* Sequence is a set of packets with the same source and destination 
 * IP addresses and same source and destination TCP/UDP ports */
class Sequence {
public:
    void AddSequenceEntry(const SequenceEntry& entry, 
                          const uint16_t bytes);

    void PrintSequence(std::ostream& out) const;
private:
    std::unordered_map<SequenceEntry, uint32_t,
                       SequenceEntry::SequenceEntryHasher> entries;
};

uint16_t GetPacketSize(const EthernetFrame& frame);
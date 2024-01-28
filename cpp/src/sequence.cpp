#include "sequence.h"
#include "network.h"
#include <netinet/tcp.h>

SequenceEntry::SequenceEntry(const EthernetFrame& frame)
    : ip_source(((IPv4Packet * ) frame.GetPacket())->GetSourceIP())
    , ip_dest(((IPv4Packet * ) frame.GetPacket())->GetDestIP()) {

    const IPv4Packet *packet = (const IPv4Packet * ) frame.GetPacket();

    /* Since both udp and tcp headers have their source and destination
     * ports right in the beginning of the header, we don't care to which
     * exactly transport protocol is lying underneath, so we cast it to a
     * struct tcphdr type arbitrarily. */
    const tcphdr *tcp_segment = (const tcphdr * ) packet->GetSegment();

    tr_source = tcp_segment->th_sport;
    tr_dest = tcp_segment->th_dport;

    tr_type = packet->GetSegment()->type;
}

const IpAddress& SequenceEntry::GetSourceIP() const {
    return ip_source;
}

const IpAddress& SequenceEntry::GetDestIP() const {
    return ip_dest;
}

const TransportProto SequenceEntry::GetTransportType() const {
    return tr_type;
}

const uint16_t SequenceEntry::GetTransportSourcePort() const {
    return tr_source;
}

const uint16_t SequenceEntry::GetTransportDestPort() const {
    return tr_dest;
}

bool SequenceEntry::operator==(const SequenceEntry& other) const {
    return ip_source.GetRawIPAddress() == other.ip_source.GetRawIPAddress()
        && ip_dest.GetRawIPAddress()   == other.ip_dest.GetRawIPAddress()
        && tr_type   == other.tr_type
        && tr_source == other.tr_source
        && tr_dest   == other.tr_dest;
}

void Sequence::AddSequenceEntry(const SequenceEntry& entry, 
                                const uint16_t bytes) {
    entries[entry] += bytes;   
}

void Sequence::PrintSequence(std::ostream& out) const {
    for (auto iter = entries.begin(); iter != entries.end(); iter++) {
        const auto& entry = iter->first;
        const auto& bytes = iter->second;

        out << entry.GetSourceIP()            << "," 
            << entry.GetDestIP()              << ","
            << entry.GetTransportSourcePort() << ","
            << entry.GetTransportDestPort()   << ","
            << bytes << std::endl;
    }
}

uint16_t GetPacketSize(const EthernetFrame& frame) {
    const IPv4Packet *packet = (IPv4Packet * ) frame.GetPacket();

    const iphdr raw_iphdr = packet->GetRawHeader();

    const uint16_t ip_payload_size = ntohs(raw_iphdr.tot_len) 
                                   - raw_iphdr.ihl * 4;
    
    if (ip_payload_size == 0) return 0;

    if (packet->GetTransportProtoType() == IP_PROTOCOL_TCP) {
        const TCPSegment *segment = (TCPSegment * ) packet;

        return ip_payload_size - segment->GetRawHeader().th_off * 4;
    } else if (packet->GetTransportProtoType() == IP_PROTOCOL_UDP) {
        const UDPSegment *segment = (UDPSegment * ) packet;

        return ip_payload_size - UDP_HEADER_SIZE;
    }

    return ip_payload_size;
}
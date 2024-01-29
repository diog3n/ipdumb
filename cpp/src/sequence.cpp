#include "sequence.h"
#include "network.h"
#include <iostream>
#include <netinet/tcp.h>

SequenceEntry::SequenceEntry(const EthernetFrame& frame)
    : ip_source(frame.GetIPv4Packet()->GetSourceIP())
    , ip_dest(frame.GetIPv4Packet()->GetDestIP()) {

    const IPv4Packet *packet = frame.GetIPv4Packet();

    /* Since both udp and tcp headers have their source and destination
     * ports right in the beginning of the header, we don't care to which
     * exactly transport protocol is lying underneath, so we cast it to a
     * TCPSegment type arbitrarily. */
    const TCPSegment *tcp_segment = (const TCPSegment * ) 
                                     packet->GetSegment();

    tr_source = tcp_segment->GetSourcePort();
    tr_dest = tcp_segment->GetDestPort();
    tr_type = packet->GetTransportProtoType();
}

const IpAddress& SequenceEntry::GetSourceIP() const {
    return ip_source;
}

const IpAddress& SequenceEntry::GetDestIP() const {
    return ip_dest;
}

const uint8_t SequenceEntry::GetTransportType() const {
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

std::ostream& operator<<(std::ostream& out, const SequenceEntry& entry) {
    out << entry.GetSourceIP()            << ", " 
        << entry.GetDestIP()              << ", "
        << (entry.GetTransportType() == IP_PROTOCOL_TCP 
                 ? "TCP"
                 : entry.GetTransportType() == IP_PROTOCOL_UDP 
                        ? "UDP"
                        : "UKNOWN")       << ", "
        << entry.GetTransportSourcePort() << ", "
        << entry.GetTransportDestPort();

    return out;
}

void Sequence::AddSequenceEntry(const SequenceEntry& entry, 
                                const uint16_t bytes) {
    if (entry.GetTransportType() != IP_PROTOCOL_TCP
     && entry.GetTransportType() != IP_PROTOCOL_UDP) return;

    entries[entry].bytes += bytes;
    entries[entry].packet_count++;   
}

void Sequence::PrintHeader(std::ostream& out) const {
    out << "source_ip," "dest_ip," "source_port,"
           "dest_port," "packet_count," "bytes\n"; 
}

void Sequence::PrintSequence(std::ostream& out) const {
    bool is_first = true;

    PrintHeader(out);

    for (auto iter = entries.begin(); iter != entries.end(); iter++) {
        const auto& entry = iter->first;
        const auto& packet_stats = iter->second;

        if (!is_first) {
            out << std::endl;
        }

        is_first = false;
        out << entry.GetSourceIP()            << "," 
            << entry.GetDestIP()              << ","
            << entry.GetTransportSourcePort() << ","
            << entry.GetTransportDestPort()   << ","
            << packet_stats.packet_count      << ","
            << packet_stats.bytes;
    }
}

uint16_t GetPacketSize(const EthernetFrame& frame) {
    const IPv4Packet *packet = frame.GetIPv4Packet();

    const iphdr raw_iphdr = packet->GetRawHeader();

    uint16_t ip_payload_size = ntohs(raw_iphdr.tot_len) 
                                   - raw_iphdr.ihl * 4;

    if (ip_payload_size == 0) return 0;

    if (packet->GetTransportProtoType() == IP_PROTOCOL_TCP) {
        const TCPSegment *segment = (TCPSegment * ) packet->GetSegment();

        ip_payload_size -= segment->GetRawHeader().th_off * 4;
    } else if (packet->GetTransportProtoType() == IP_PROTOCOL_UDP) {
        const UDPSegment *segment = (UDPSegment * ) packet->GetSegment();

        ip_payload_size -= UDP_HEADER_SIZE;
    }

    return ip_payload_size;
}
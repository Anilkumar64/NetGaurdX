#include "core/models/PacketModel.h"
#include "core/models/FlowModel.h"

std::string protocolToString(Protocol p)
{
    switch (p)
    {
    case Protocol::ARP:
        return "ARP";
    case Protocol::ICMP:
        return "ICMP";
    case Protocol::TCP:
        return "TCP";
    case Protocol::UDP:
        return "UDP";
    case Protocol::DNS:
        return "DNS";
    case Protocol::HTTP:
        return "HTTP";
    case Protocol::HTTPS:
        return "HTTPS";
    case Protocol::TLS:
        return "TLS";
    case Protocol::QUIC:
        return "QUIC";
    default:
        return "UNKNOWN";
    }
}

std::string tcpFlagsToString(uint8_t flags)
{
    std::string result;
    if (flags & 0x02)
        result += "SYN|";
    if (flags & 0x10)
        result += "ACK|";
    if (flags & 0x01)
        result += "FIN|";
    if (flags & 0x04)
        result += "RST|";
    if (flags & 0x08)
        result += "PSH|";
    if (flags & 0x20)
        result += "URG|";
    if (!result.empty())
        result.pop_back(); // strip trailing '|'
    if (result.empty())
        result = "NONE";
    return result;
}

std::string tcpStateToString(TCPState s)
{
    switch (s)
    {
    case TCPState::CLOSED:
        return "CLOSED";
    case TCPState::LISTEN:
        return "LISTEN";
    case TCPState::SYN_SENT:
        return "SYN_SENT";
    case TCPState::SYN_RECEIVED:
        return "SYN_RECEIVED";
    case TCPState::ESTABLISHED:
        return "ESTABLISHED";
    case TCPState::FIN_WAIT_1:
        return "FIN_WAIT_1";
    case TCPState::FIN_WAIT_2:
        return "FIN_WAIT_2";
    case TCPState::CLOSE_WAIT:
        return "CLOSE_WAIT";
    case TCPState::CLOSING:
        return "CLOSING";
    case TCPState::LAST_ACK:
        return "LAST_ACK";
    case TCPState::TIME_WAIT:
        return "TIME_WAIT";
    default:
        return "UNKNOWN";
    }
}

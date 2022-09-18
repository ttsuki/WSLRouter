// pcappp.h - WinPcap C++ wrapper
// MIT License: (c) 2022 ttsuki

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <iphlpapi.h>

#define HAVE_REMOTE
#include <pcap/pcap.h>

#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <memory>
#include <optional>
#include <functional>
#include <string>
#include <vector>

namespace pcappp
{
    using pcap_if_t = ::pcap_if_t;
    using pcap_rmtauth = ::pcap_rmtauth;
    using pcap_t = ::pcap_t;

    struct pcap_exception : public std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    // pcap
    static inline std::shared_ptr<pcap_if_t> findalldevs_ex(const char* source, const pcap_rmtauth* auth = nullptr)
    {
        std::string src = source;
        pcap_rmtauth a = auth ? *auth : pcap_rmtauth{};
        char error[PCAP_ERRBUF_SIZE]{};
        pcap_if_t* devices{};
        int r = pcap_findalldevs_ex(src.data(), auth ? &a : nullptr, &devices, error);
        if (r != 0) throw pcap_exception(error);
        if (!devices) throw pcap_exception(error);
        return {devices, pcap_freealldevs};
    }

    // win32
    static inline std::shared_ptr<IP_ADAPTER_INFO> get_all_ip_adapter_info()
    {
        ULONG sz = 0;
        ULONG r = ::GetAdaptersInfo(nullptr, &sz);
        if (r != ERROR_BUFFER_OVERFLOW) throw pcap_exception("fail");
        auto buf = std::make_unique<std::byte[]>(static_cast<size_t>(sz));
        auto head = reinterpret_cast<IP_ADAPTER_INFO*>(buf.get());
        r = GetAdaptersInfo(head, &sz);
        if (r != NO_ERROR) throw pcap_exception("fail");
        return {head, [b = std::move(buf)](IP_ADAPTER_INFO*) {}};
    }

    struct adapter_info
    {
        std::shared_ptr<pcap_if_t> pcap_if;
        std::shared_ptr<IP_ADAPTER_INFO> ip_adapter_info;
    };

    static inline std::vector<adapter_info> get_all_adapters()
    {
        std::vector<adapter_info> ret;
        auto src = pcappp::findalldevs_ex(PCAP_SRC_IF_STRING);
        auto ais = pcappp::get_all_ip_adapter_info();

        for (auto p = src.get(); p; p = p->next)
        {
            std::shared_ptr<IP_ADAPTER_INFO> i = nullptr;
            for (auto ai = ais.get(); ai; ai = ai->Next)
                if (::strstr(p->name, ai->AdapterName))
                    i = std::shared_ptr<IP_ADAPTER_INFO>(ais, ai);
            ret.emplace_back(adapter_info{std::shared_ptr<pcap_if_t>(src, p), std::move(i)});
        }

        return ret;
    }

    static inline std::optional<adapter_info> find_adapter_from_ip(std::string_view ip)
    {
        for (auto& [pc, ai] : pcappp::get_all_adapters())
            if (ai)
                for (auto a = &ai->IpAddressList; a; a = a->Next)
                    if (a->IpAddress.String == ip)
                        return adapter_info{pc, ai};

        return std::nullopt;
    }

    enum struct pcap_open_flag : int
    {
        none = 0,
        promiscuous = PCAP_OPENFLAG_PROMISCUOUS,
        datatx_udp = PCAP_OPENFLAG_DATATX_UDP,
        nocapture_rpcap = PCAP_OPENFLAG_NOCAPTURE_RPCAP,
        nocapture_local = PCAP_OPENFLAG_NOCAPTURE_LOCAL,
        max_responsiveness = PCAP_OPENFLAG_MAX_RESPONSIVENESS,
    };

    static inline constexpr pcap_open_flag operator ~(pcap_open_flag a) noexcept { return static_cast<pcap_open_flag>(~static_cast<std::underlying_type_t<pcap_open_flag>>(a)); }
    static inline constexpr pcap_open_flag operator &(pcap_open_flag a, pcap_open_flag b) noexcept { return static_cast<pcap_open_flag>(static_cast<std::underlying_type_t<pcap_open_flag>>(a) & static_cast<std::underlying_type_t<pcap_open_flag>>(b)); }
    static inline constexpr pcap_open_flag operator |(pcap_open_flag a, pcap_open_flag b) noexcept { return static_cast<pcap_open_flag>(static_cast<std::underlying_type_t<pcap_open_flag>>(a) | static_cast<std::underlying_type_t<pcap_open_flag>>(b)); }
    static inline constexpr pcap_open_flag operator ^(pcap_open_flag a, pcap_open_flag b) noexcept { return static_cast<pcap_open_flag>(static_cast<std::underlying_type_t<pcap_open_flag>>(a) ^ static_cast<std::underlying_type_t<pcap_open_flag>>(b)); }
    static inline constexpr pcap_open_flag& operator &=(pcap_open_flag& a, pcap_open_flag b) noexcept { return a = a & b; }
    static inline constexpr pcap_open_flag& operator |=(pcap_open_flag& a, pcap_open_flag b) noexcept { return a = a | b; }
    static inline constexpr pcap_open_flag& operator ^=(pcap_open_flag& a, pcap_open_flag b) noexcept { return a = a ^ b; }

    // pcap
    static inline std::shared_ptr<::pcap_t> open(const char* source, int snaplen, pcap_open_flag flags, int read_timeout, const pcap_rmtauth* auth = nullptr)
    {
        std::string src = source;
        ::pcap_rmtauth a = auth ? *auth : ::pcap_rmtauth{};
        char error[PCAP_ERRBUF_SIZE]{};
        ::pcap_t* p = ::pcap_open(src.data(), snaplen, static_cast<int>(flags), read_timeout, auth ? &a : nullptr, error);
        if (!p) throw pcap_exception(error);
        return {p, &::pcap_close};
    }

    // pcap
    static inline void setfilter(const std::shared_ptr<::pcap_t>& cap, const char* filter_expression, bpf_u_int32 mask = 0, bool optimization = true)
    {
        ::bpf_program program{};

        if (::pcap_compile(cap.get(), &program, filter_expression, optimization ? 1 : 0, mask) < 0)
            throw pcap_exception(pcap_geterr(cap.get()));

        if (::pcap_setfilter(cap.get(), &program) < 0)
            throw pcap_exception(pcap_geterr(cap.get()));
    }

    // pcap
    template <class F = std::function<void(const pcap_pkthdr* header, const u_char* pkt_data)>>
    static inline void loop(const std::shared_ptr<::pcap_t>& cap, F&& callback)
    {
        ::pcap_loop(
            cap.get(), -1,
            [](u_char* kb, const pcap_pkthdr* header, const u_char* pkt_data)
            {
                reinterpret_cast<F*>(kb)->operator()(header, pkt_data);
            }, reinterpret_cast<u_char*>(&callback));
    }

    // pcap
    static inline void sendpacket(const std::shared_ptr<::pcap_t>& cap, const void* pkt_data, size_t length)
    {
        if (::pcap_sendpacket(cap.get(), static_cast<const u_char*>(pkt_data), static_cast<int>(length)) != 0)
            throw std::runtime_error(pcap_geterr(cap.get()));
    }

#pragma pack(push,1)

    struct ethernet_header
    {
        u_char daddr[6];     // Destination MAC Address
        u_char saddr[6];     // Source MAC Address
        u_char ethertype[2]; // Ether Type
    };

    struct ipv4_header
    {
        u_char ver_ihl;         // Version (4 bits) + Internet header length (4 bits)
        u_char tos;             // Type of service 
        u_short tlen;           // Total length 
        u_short identification; // Identification
        u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
        u_char ttl;             // Time to live
        u_char proto;           // Protocol
        u_short crc;            // Header checksum
        u_char saddr[4];        // Source address
        u_char daddr[4];        // Destination address
    };

    struct ipv6_header
    {
        u_int ver_tc_fl;      // Version (4 bits) + Traffic Class  (6+2 bits) + Flow Label (20 bits)
        u_short pay_load_len; // Payload length
        u_char next_header;   // Next header
        u_char hop_limit;     // Hop Limit
        u_char saddr[16];     // Source address
        u_char daddr[16];     // Destination address
    };

    struct tcp_header
    {
        u_short sport;    // Source port
        u_short dport;    // Destination port
        u_int seq;        // Sequence number
        u_int ack;        // Acknowledgment number 
        u_short flags;    // Flags (16 bits) + Data offset (4 bits)
        u_short wsize;    // Window size
        u_short checksum; // Checksum 
        u_short urgptr;   // Urgent pointer
    };

    struct udp_header
    {
        u_short sport; // Source port
        u_short dport; // Destination port
        u_short len;   // Datagram length
        u_short crc;   // Checksum
    };
#pragma pack(pop)

    static_assert(sizeof(ethernet_header) == 14);
    static_assert(sizeof(ipv4_header) == 20);
    static_assert(sizeof(ipv6_header) == 40);
    static_assert(sizeof(tcp_header) == 20);
    static_assert(sizeof(udp_header) == 8);
}

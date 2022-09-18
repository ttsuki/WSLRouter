// WSLRouter.cpp
// MIT License: (c) 2022 ttsuki

#include <cstddef>
#include <ctime>
#include <cstring>

#include <type_traits>
#include <memory>

#include <array>
#include <vector>
#include <string>
#include <iomanip>
#include <iostream>

#include "pcappp.h"
#include "fmt.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace app
{
    int show_adapters();
    int packet_monitor();
    int packet_router();
}

// entry point
int main()
{
    //return app::show_adapters();
    //return app::packet_monitor();
    return app::packet_router();
}

namespace app
{
    inline namespace ark
    {
        /// Loads T from unaligned memory pointer
        template <class T>
        static inline constexpr auto load_u(const void* src) noexcept
        -> std::enable_if_t<std::is_trivially_copyable_v<T>, T>
        {
            T t;
            memcpy(&t, src, sizeof(T));
            return t;
        }

        /// Stores T to unaligned memory pointer
        template <class T>
        static inline constexpr auto store_u(void* d, const std::decay_t<T>& s) noexcept
        -> std::enable_if_t<std::is_trivially_copyable_v<T>, void>
        {
            memcpy(d, &s, sizeof(T));
        }
    }

    static void dump_packet_header(std::ostream& cout, const void* pkt_data, size_t length, timeval timestamp);
    static void show_adapters(std::ostream& cout, const std::vector<pcappp::adapter_info>& adapters);

    int show_adapters()
    {
        auto all_devices = pcappp::get_all_adapters();
        show_adapters(std::cout, all_devices);
        return 0;
    }

    int packet_monitor()
    {
        std::string source = [&]
        {
            auto all_devices = pcappp::get_all_adapters();
            show_adapters(std::cout, all_devices);

            if (all_devices.empty())
            {
                std::cerr << "no device." << std::endl;
                throw 1;
            }

            size_t i{};
            std::cout << "Enter the i/f index to monitor [" << 0 << "-" << (all_devices.size() - 1) << "]: ";
            std::cin >> i;

            if (i >= all_devices.size())
            {
                std::cerr << "index out of range." << std::endl;
                throw 1;
            }

            return all_devices[i].pcap_if->name;
        }();

        std::cout << "Opening device... " << source << "\n";
        auto pcap = pcappp::open(source.c_str(), 65536, pcappp::pcap_open_flag::none, 20);

        std::cout << "Ready" << "\n";
        pcappp::loop(pcap, [](const pcap_pkthdr* header, const u_char* pkt_data)
        {
            dump_packet_header(std::cout, pkt_data, header->len, header->ts);
        });
        return 0;
    }

    int packet_router()
    {
        // config
        const auto wan_adapter = pcappp::find_adapter_from_ip("10.1.1.223");
        const auto lan_adapter = pcappp::find_adapter_from_ip("172.17.240.1");
        const auto inbound_filter = R"(ip dst host 10.1.1.223 and udp dst port 7777)";
        const auto smac = std::array<u_char, 6>{0x00, 0x15, 0x5D, 0xF2, 0xCF, 0x6E}; // Windows WSL 
        const auto dmac = std::array<u_char, 6>{0x00, 0x15, 0x5D, 0xE9, 0xA8, 0xCE}; // WSL eth0
        const auto dst = std::array<u_char, 4>{192, 168, 49, 2};                     // target ip (minikube) address via WSL eth0
        //
        //               [Client] <( send to 10.1.1.223:7777/udp )
        //                   |
        //  Physical |---+---+-----------| 10.1.1.0/24
        //               |
        //               | 10.1.1.223
        //             [Windows] (with `route add 192.168.49.0/24 172.17.255.64`)
        //                   | 172.17.240.1 (00:15:5D:F2:CF:6E) vEthernet
        //                   |
        //  Hyper-V  |---+---+-----------| 172.17.240.0/20
        //               |
        //               | 172.17.255.64 (00:15:5D:E0:A8:CE) eth0
        //           [WSL2 Ubuntu] (with ip forwarding)
        //                   | 192.168.49.1 br-xxxxxx
        //                   |
        //  minikube |---+---+-----------| 192.168.49.0/24
        //               |
        //               | 192.168.49.2:7777/udp <- Desired service.
        //           [Server Node]
        //                  |||
        //                  [[[Containers]]] (Cluster-IPs)
        //

        std::cout << "Opening device... " << "\n";
        std::cout << "  wan: " << wan_adapter->pcap_if->name << "\n";
        std::cout << "  lan: " << lan_adapter->pcap_if->name << "\n";
        auto wan = pcappp::open(wan_adapter->pcap_if->name, 65536, pcappp::pcap_open_flag::none, 20);
        auto lan = pcappp::open(lan_adapter->pcap_if->name, 65536, pcappp::pcap_open_flag::datatx_udp, 20);

        std::cout << "Setting inbound_filter... " << inbound_filter << "\n";
        pcappp::setfilter(wan, inbound_filter, 0);

        std::cout << "Ready" << "\n";
        pcappp::loop(wan, [&](const pcap_pkthdr* header, const u_char* pkt_data)
        {
            // incoming
            dump_packet_header(std::cout, pkt_data, header->len, header->ts);

            // new packet buffer
            std::array<u_char, 65536> buffer{};
            memcpy(buffer.data(), pkt_data, header->len);

            auto eh = reinterpret_cast<pcappp::ethernet_header*>(buffer.data() + 0);
            auto ih = reinterpret_cast<pcappp::ipv4_header*>(buffer.data() + sizeof(pcappp::ethernet_header));
            auto uh = reinterpret_cast<pcappp::udp_header*>(buffer.data() + sizeof(pcappp::ethernet_header) + (ih->ver_ihl & 0x0F) * 4);
            const auto ether_type = static_cast<u_int16_t>(static_cast<u_int16_t>(eh->ethertype[0]) << 8 | static_cast<u_int16_t>(eh->ethertype[1]));
            if (ether_type != 0x0800) return; // return if not IPv4?
            if (ih->proto != 0x11) return;    // return if not UDP?

            const int udp_payload_size = ntohs(uh->len);

            // Rewrite src/dst MAC, dst ip
            store_u<decltype(dmac)>(eh->daddr, dmac);
            store_u<decltype(smac)>(eh->saddr, smac);
            store_u<decltype(dst)>(ih->daddr, dst);

            // Recalculate ip checksum
            {
                ih->crc = 0;
                u_int ip_sum = 0;

                for (int i = 0; i < 10; i++) ip_sum += *(reinterpret_cast<const u_short*>(ih) + i);

                while (ip_sum >> 16) ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
                ih->crc = static_cast<u_short>(~ip_sum);
            }

            // Recalculate udp checksum
            {
                uh->crc = 0;

                u_int udp_sum = 0;
                udp_sum += load_u<u_short>(ih->saddr + 0);
                udp_sum += load_u<u_short>(ih->saddr + 2);
                udp_sum += load_u<u_short>(ih->daddr + 0);
                udp_sum += load_u<u_short>(ih->daddr + 2);
                udp_sum += htons(ih->proto);
                udp_sum += uh->len;

                int size = udp_payload_size + 8;
                for (int i = 0; i < size / 2; i++) udp_sum += *(reinterpret_cast<const u_short*>(uh) + i);
                if (size % 2 != 0) udp_sum += htons(*(reinterpret_cast<const u_char*>(uh) + size - 1));

                while (udp_sum >> 16) udp_sum = (udp_sum & 0xFFFF) + (udp_sum >> 16);
                uh->crc = static_cast<u_short>(~udp_sum);
            }

            // outgoing
            dump_packet_header(std::cout, buffer.data(), header->len, header->ts);
            pcappp::sendpacket(lan, buffer.data(), header->len);
        });

        return 0;
    }

    static void show_adapters(std::ostream& cout, const std::vector<pcappp::adapter_info>& adapters)
    {
        int i = 0;
        for (auto [pc, ai] : adapters)
        {
            cout << "[" << i << "] ";
            cout << pc->name;
            if (ai)
            {
                for (auto ip = &ai->IpAddressList; ip; ip = ip->Next)
                    cout << " " << ip->IpAddress.String;
                cout << " " << ai->Description;
            }
            cout << "\n";
            i++;
        }
    }

    static void dump_packet_header(std::ostream& cout, const void* pkt_data, size_t length, timeval timestamp)
    {
        using namespace fmt;

        // timestamp
        {
            const time_t sec = timestamp.tv_sec;
            const long usec = timestamp.tv_usec;

            tm ltime{};
            localtime_s(&ltime, &sec);

            char timestr[16]{};
            strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
            cout << timestr << "." << std::dec << std::setw(6) << std::setfill('0') << usec << " ";
        }

        // ethernet
        auto eh = static_cast<const pcappp::ethernet_header*>(pkt_data);
        auto dst_mac = load_u<mac_address>(eh->daddr);
        auto src_mac = load_u<mac_address>(eh->saddr);
        auto ether_type = static_cast<u_int16_t>(static_cast<u_int16_t>(eh->ethertype[0]) << 8 | static_cast<u_int16_t>(eh->ethertype[1]));
        cout << src_mac << " >> " << dst_mac;

        const void* ether_payload = static_cast<const std::byte*>(pkt_data) + 14; // ethernet header length = 14

        if (ether_type == 0x0800) // ipv4
        {
            cout << " IPv4";

            auto ih = static_cast<const pcappp::ipv4_header*>(ether_payload);
            const void* ip_proto_header = static_cast<const std::byte*>(ether_payload) + (ih->ver_ihl & 0x0F) * 4;
            auto saddr = load_u<ipv4_address>(ih->saddr);
            auto daddr = load_u<ipv4_address>(ih->daddr);
            auto proto = ih->proto;

            if (proto == 0x06)
            {
                cout << " TCP ";
                auto th = static_cast<const pcappp::tcp_header*>(ip_proto_header);
                auto sport = load_u<port_number>(&th->sport);
                auto dport = load_u<port_number>(&th->dport);
                cout << saddr << ':' << sport << " >> " << daddr << ':' << dport;
            }
            else if (proto == 0x11)
            {
                cout << " UDP ";
                auto uh = static_cast<const pcappp::udp_header*>(ip_proto_header);
                auto sport = load_u<port_number>(&uh->sport);
                auto dport = load_u<port_number>(&uh->dport);
                cout << saddr << ':' << sport << " >> " << daddr << ':' << dport;
            }
            else
            {
                cout << "Unknown Proto[0x" << hex_byte{proto} << "] ";
                cout << saddr << " >> " << daddr;
            }
        }

        else if (ether_type == 0x86DD) // IPv6 
        {
            cout << " IPv6";

            auto ih = static_cast<const pcappp::ipv6_header*>(ether_payload);
            const void* ip_proto_header = static_cast<const std::byte*>(ether_payload) + 40;
            auto saddr = load_u<ipv6_address>(ih->saddr);
            auto daddr = load_u<ipv6_address>(ih->saddr);
            auto next = ih->next_header;

            if (next == 0x06)
            {
                cout << " TCP ";
                auto th = static_cast<const pcappp::tcp_header*>(ip_proto_header);
                auto sport = load_u<port_number>(&th->sport);
                auto dport = load_u<port_number>(&th->dport);
                cout << saddr << ':' << sport << " >> " << daddr << ':' << dport;
            }
            else if (next == 0x11)
            {
                cout << " UDP ";
                auto uh = static_cast<const pcappp::udp_header*>(ip_proto_header);
                auto sport = load_u<port_number>(&uh->sport);
                auto dport = load_u<port_number>(&uh->dport);
                cout << saddr << ':' << sport << " >> " << daddr << ':' << dport;
            }
            else
            {
                cout << "Unknown NextHeader[0x" << hex_byte{next} << "] ";
                cout << saddr << " >> " << daddr;
            }
        }
        else if (ether_type == 0x0806) // ARP 
        {
            cout << " ARP";
        }
        else
        {
            cout << " Unknown EtherType[" << hex_short{ether_type} << "]";
        }

        cout << " length:" << std::dec << length << "\n";
    }
}

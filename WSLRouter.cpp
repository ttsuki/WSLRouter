// WSLRouter.cpp
// MIT License: (c) 2022 ttsuki

#include <cstddef>
#include <ctime>
#include <cstring>

#include <type_traits>
#include <memory>

#include <thread>
#include <mutex>

#include <array>
#include <vector>
#include <string>
#include <iomanip>
#include <iostream>
#include <sstream>

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

    using fmt::mac_address;
    using fmt::ipv4_address;
    static_assert(sizeof mac_address == 6);
    static_assert(sizeof ipv4_address == 4);

    static inline ipv4_address parse_ipv4(const char* address)
    {
        int tmp[4]{};
        if (::sscanf_s(address, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3]) == 4 &&
            ((tmp[0] | tmp[1] | tmp[2] | tmp[3]) & ~0xFF) == 0)
            return ipv4_address{
                static_cast<decltype(ipv4_address::address)::value_type>(tmp[0]),
                static_cast<decltype(ipv4_address::address)::value_type>(tmp[1]),
                static_cast<decltype(ipv4_address::address)::value_type>(tmp[2]),
                static_cast<decltype(ipv4_address::address)::value_type>(tmp[3]),
            };
        throw std::invalid_argument("failed to parse ipv4_address");
    }

    static inline mac_address parse_mac(const char* address)
    {
        int tmp[6]{};
        if (::sscanf_s(address, "%02x:%02x:%02x:%02x:%02x:%02x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) == 6 &&
            ((tmp[0] | tmp[1] | tmp[2] | tmp[3] | tmp[4] | tmp[5]) & ~0xFF) == 0)
        {
            return mac_address{
                static_cast<decltype(mac_address::address)::value_type>(tmp[0]),
                static_cast<decltype(mac_address::address)::value_type>(tmp[1]),
                static_cast<decltype(mac_address::address)::value_type>(tmp[2]),
                static_cast<decltype(mac_address::address)::value_type>(tmp[3]),
                static_cast<decltype(mac_address::address)::value_type>(tmp[4]),
                static_cast<decltype(mac_address::address)::value_type>(tmp[5]),
            };
        }
        throw std::invalid_argument("failed to parse mac_address");
    }

    struct arp_table_t
    {
        mutable std::mutex mutex_;
        mutable std::unordered_map<uint32_t, std::optional<mac_address>> table_;

        std::optional<mac_address> get(ipv4_address a) const
        {
            std::lock_guard lock(mutex_);
            return table_[load_u<uint32_t>(&a)];
        }

        void update(ipv4_address a, mac_address m)
        {
            std::lock_guard lock(mutex_);
            table_[load_u<uint32_t>(&a)] = m;
        }
    };

    static void show_adapters(std::ostream& cout, const std::vector<pcappp::adapter_info>& adapters);
    static void dump_packet_header(std::ostream& cout, std::string_view label, const void* pkt_data, size_t length, timeval timestamp);

    static bool rewrite_ethernet_frame_ipv4(
        u_char* frame, [[maybe_unused]] size_t length,
        mac_address src_mac, mac_address dst_mac,
        ipv4_address src_ipv4, ipv4_address dst_ipv4);

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
            dump_packet_header(std::cout, "", pkt_data, header->len, header->ts);
        });
        return 0;
    }

    int packet_router()
    {
        // NAT Config
        const auto frontend_ip = parse_ipv4("10.1.1.223");             // Windows Physical (front-end)
        const auto frontend_adapter = parse_mac("00:00:5E:00:53:AF");  // Windows Physical (front-end)
        const auto internal_adapter = parse_mac("00:15:5D:F2:CF:6E");  // Windows vEthernet (WSL)
        const auto internal_next_hop = parse_mac("00:15:5D:E9:A8:CE"); // Next hop for Target server (WSL eth0)
        const auto internal_server_ip = parse_ipv4("192.168.49.2");    // Target server ip address
        const auto inbound_filter = "ip dst host 10.1.1.223 and udp dst port 7777";
        const auto outbound_filter = "ip src host 192.168.49.2 and udp src port 7777";

        //
        //                   [Client] <( send to 10.1.1.223:7777/udp )
        //                       |
        //                       |
        //      Physical |---+---+-----------| 10.1.1.0/24
        //                   |
        //                   | Physical (frontend)
        //                   | 10.1.1.223         <- frontend_ip
        //                   | 00:00:5E:00:53:AF  <- frontend_adapter
        // +-------------- [Windows] --------------------------------------------+
        // |                     | Internal (vEthernet (WSL))
        // |                     | 192.168.0.1/24
        // |                     | 00:15:5D:F2:CF:6E  <- internal_adapter
        // |                     |
        // |    Hyper-V  |---+---+-----------| 172.17.240.0/20
        // |                 |
        // |                 | eth0
        // |                 | 192.168.0.101/24
        // |                 | 00:15:5D:E0:A8:CE  <- internal_next_hop
        // | +-------- [WSL2 Ubuntu] (with ip forwarding) ----------------------+
        // | |                   | br-xxxxxxxxxxxx
        // | |                   | 192.168.49.1
        // | |                   | xx:xx:xx:xx:xx:xx
        // | |                   |
        // | |  minikube |---+---+-----------| 192.168.49.0/24
        // | |               |
        // | |               | 192.168.49.2          <- internal_server_ip
        // | |               |             :7777/udp <- Desired service.
        // | |          [Server Node]
        // | |                  |||
        // | |                  [[[Containers]]] (Cluster-IPs)
        // | |
        // | |

        const auto frontend_adapter_interface = pcappp::find_adapter_from_mac(reinterpret_cast<const std::byte*>(&frontend_adapter));
        const auto internal_adapter_interface = pcappp::find_adapter_from_mac(reinterpret_cast<const std::byte*>(&internal_adapter));

        std::cout << "Opening device... " << "\n";
        if (!frontend_adapter_interface) throw std::invalid_argument("frontend adapter not found.");
        if (!internal_adapter_interface) throw std::invalid_argument("internal adapter not found.");
        std::cout << "  wan: " << frontend_adapter_interface->pcap_if->name << " [" << frontend_adapter << "]" << "\n";
        std::cout << "  lan: " << internal_adapter_interface->pcap_if->name << " [" << internal_adapter << "]" << "\n";

        auto wan = pcappp::open(frontend_adapter_interface->pcap_if->name, 65536, pcappp::pcap_open_flag::datatx_udp, 20);
        auto lan = pcappp::open(internal_adapter_interface->pcap_if->name, 65536, pcappp::pcap_open_flag::datatx_udp, 20);

        std::cout << "Setting inbound_filter... " << inbound_filter << "\n";
        pcappp::setfilter(wan, inbound_filter, 0);

        std::cout << "Setting outbound_filter... " << outbound_filter << "\n";
        pcappp::setfilter(lan, outbound_filter, 0);

        // arp_table
        arp_table_t arp_table;

        // write_console
        auto dump_packet_header = [console_access = std::mutex()](std::string_view label, const void* pkt_data, size_t length, timeval timestamp) mutable
        {
            std::ostringstream ss;
            app::dump_packet_header(ss, label, pkt_data, length, timestamp);
            std::lock_guard lock(console_access);
            std::cout << ss.str();
        };

        // inbound thread
        auto wan_to_lan_thread = std::thread([&]
        {
            std::vector<u_char> buffer{};
            buffer.reserve(65536);

            pcappp::loop(wan, [&](const pcap_pkthdr* header, const u_char* pkt_data)
            {
                // incoming
                dump_packet_header(" R<", pkt_data, header->len, header->ts);

                auto eh = reinterpret_cast<const pcappp::ethernet_header*>(pkt_data + 0);
                const auto ether_type = get_ether_type(*eh);

                if (ether_type == 0x0800) // Ipv4
                {
                    auto ih = reinterpret_cast<const pcappp::ipv4_header*>(pkt_data + sizeof(pcappp::ethernet_header));
                    const auto source_ip = load_u<ipv4_address>(ih->saddr);
                    const auto source_mac = load_u<mac_address>(eh->saddr);

                    // new packet buffer
                    buffer.assign(pkt_data, pkt_data + header->len);

                    if (rewrite_ethernet_frame_ipv4(
                        buffer.data(), header->len,
                        internal_adapter, internal_next_hop, // rewrite src/dst mac
                        source_ip, internal_server_ip))      // rewrite dst ip
                    {
                        // update arp table
                        arp_table.update(source_ip, source_mac);

                        // dispatch inbound packet
                        pcappp::sendpacket(lan, buffer.data(), header->len);

                        // log
                        dump_packet_header("<i ", buffer.data(), header->len, header->ts);
                    }
                }
            });
        });

        // outbound thread
        auto lan_to_wan_thread = std::thread([&]
        {
            std::vector<u_char> buffer{};
            buffer.reserve(65536);

            std::unordered_map<uint32_t, std::optional<mac_address>> arp_table_cache; // thread local cache
            pcappp::loop(lan, [&](const pcap_pkthdr* header, const u_char* pkt_data)
            {
                // outgoing
                dump_packet_header(">o ", pkt_data, header->len, header->ts);

                auto eh = reinterpret_cast<const pcappp::ethernet_header*>(pkt_data + 0);
                const auto ether_type = get_ether_type(*eh);

                if (ether_type == 0x0800) // Ipv4
                {
                    auto ih = reinterpret_cast<const pcappp::ipv4_header*>(pkt_data + sizeof(pcappp::ethernet_header));

                    const auto destination_ip = load_u<ipv4_address>(ih->daddr);
                    auto destination_mac = arp_table_cache[load_u<uint32_t>(&destination_ip)];
                    if (!destination_mac) { destination_mac = arp_table_cache[load_u<uint32_t>(&destination_ip)] = arp_table.get(destination_ip); }
                    if (destination_mac)
                    {
                        // new packet buffer
                        buffer.assign(pkt_data, pkt_data + header->len);

                        if (rewrite_ethernet_frame_ipv4(
                            buffer.data(), header->len,
                            frontend_adapter, *destination_mac,
                            frontend_ip, destination_ip))
                        {
                            // send outbound packet
                            pcappp::sendpacket(wan, buffer.data(), header->len);

                            // log
                            dump_packet_header(" S>", buffer.data(), header->len, header->ts);
                        }
                    }
                }
            });
        });

        lan_to_wan_thread.join();
        wan_to_lan_thread.join();

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

    static void dump_packet_header(std::ostream& cout, std::string_view label, const void* pkt_data, size_t length, timeval timestamp)
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

        // label
        cout << label << " ";

        // ethernet
        auto eh = static_cast<const pcappp::ethernet_header*>(pkt_data);
        auto dst_mac = load_u<mac_address>(eh->daddr);
        auto src_mac = load_u<mac_address>(eh->saddr);
        auto ether_type = pcappp::get_ether_type(*eh);
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
                cout << '[' << saddr << ']' << ':' << sport << " >> " << '[' << daddr << ']' << ':' << dport;
            }
            else if (proto == 0x11)
            {
                cout << " UDP ";
                auto uh = static_cast<const pcappp::udp_header*>(ip_proto_header);
                auto sport = load_u<port_number>(&uh->sport);
                auto dport = load_u<port_number>(&uh->dport);
                cout << '[' << saddr << ']' << ':' << sport << " >> " << '[' << daddr << ']' << ':' << dport;
            }
            else
            {
                cout << "Unknown Proto[0x" << hex_byte{proto} << "] ";
                cout << '[' << saddr << ']' << " >> " << '[' << daddr << ']';
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
                cout << '[' << saddr << ']' << ':' << sport << " >> " << '[' << daddr << ']' << ':' << dport;
            }
            else if (next == 0x11)
            {
                cout << " UDP ";
                auto uh = static_cast<const pcappp::udp_header*>(ip_proto_header);
                auto sport = load_u<port_number>(&uh->sport);
                auto dport = load_u<port_number>(&uh->dport);
                cout << '[' << saddr << ']' << ':' << sport << " >> " << '[' << daddr << ']' << ':' << dport;
            }
            else
            {
                cout << "Unknown NextHeader[0x" << hex_byte{next} << "] ";
                cout << '[' << saddr << ']' << " >> " << '[' << daddr << ']';
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


    static bool rewrite_ethernet_frame_ipv4(
        u_char* frame, [[maybe_unused]] size_t length,
        mac_address src_mac, mac_address dst_mac,
        ipv4_address src_ipv4, ipv4_address dst_ipv4)
    {
        bool done = true;

        auto eh = reinterpret_cast<pcappp::ethernet_header*>(frame);
        const auto ether_type = pcappp::get_ether_type(*eh);
        if (ether_type != 0x0800) return false; // only IPv4 packets are supported. 

        auto ih = reinterpret_cast<pcappp::ipv4_header*>(frame + sizeof(pcappp::ethernet_header));

        // Rewrite src/dst MAC, IP
        store_u<mac_address>(eh->daddr, dst_mac);   // destination mac address
        store_u<mac_address>(eh->saddr, src_mac);   // source mac address
        store_u<ipv4_address>(ih->saddr, src_ipv4); // source ip address
        store_u<ipv4_address>(ih->daddr, dst_ipv4); // destination ip address

        // Recalculate ip checksum
        {
            ih->crc = 0;
            u_int ip_sum = 0;
            for (int i = 0; i < 10; i++) ip_sum += *(reinterpret_cast<const u_short*>(ih) + i);
            while (ip_sum >> 16) ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
            ih->crc = static_cast<u_short>(~ip_sum);
        }

        if (ih->proto == 0x11) // if packet is UDP
        {
            // Recalculate udp checksum
            auto uh = reinterpret_cast<pcappp::udp_header*>(frame + sizeof(pcappp::ethernet_header) + (ih->ver_ihl & 0x0F) * 4);
            uh->crc = 0;

            u_int udp_sum = 0;
            // IPv4 UDP header
            udp_sum += load_u<u_short>(ih->saddr + 0);
            udp_sum += load_u<u_short>(ih->saddr + 2);
            udp_sum += load_u<u_short>(ih->daddr + 0);
            udp_sum += load_u<u_short>(ih->daddr + 2);
            udp_sum += htons(ih->proto);
            udp_sum += uh->len;

            int size = ntohs(uh->len);
            for (int i = 0; i < size / 2; i++) udp_sum += *(reinterpret_cast<const u_short*>(uh) + i);
            if (size % 2 != 0) udp_sum += *(reinterpret_cast<const u_char*>(uh) + size - 1);

            while (udp_sum >> 16) udp_sum = (udp_sum & 0xFFFF) + (udp_sum >> 16);
            uh->crc = static_cast<u_short>(~udp_sum);
        }
        else
        {
            // not supported. drop
            return false;
        }

        return done;
    }
}

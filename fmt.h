// fmt.h - formatted output helper
// MIT License: (c) 2022 ttsuki

#pragma once

#include <cstdint>
#include <array>
#include <ostream>
#include <iomanip>

#pragma pack(push,1)

namespace fmt
{
    enum struct dec_byte : uint8_t { };

    enum struct hex_byte : uint8_t { };

    enum struct dec_short : uint16_t { };

    enum struct hex_short : uint16_t { };

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, hex_byte val)
    {
        return ostream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(val);
    }

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, hex_short val)
    {
        return ostream << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(val);
    }

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, dec_byte val)
    {
        return ostream << std::dec << std::setw(0) << static_cast<int>(val);
    }

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, dec_short val)
    {
        return ostream << std::dec << std::setw(0) << static_cast<int>(val);
    }

    struct mac_address
    {
        std::array<hex_byte, 6> address;
    };

    static_assert(sizeof(mac_address) == 6);

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, mac_address addr)
    {
        return ostream
            << addr.address[0] << ':'
            << addr.address[1] << ':'
            << addr.address[2] << ':'
            << addr.address[3] << ':'
            << addr.address[4] << ':'
            << addr.address[5];
    }

    struct ipv4_address
    {
        std::array<dec_byte, 4> address;
    };

    static_assert(sizeof(ipv4_address) == 4);

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, ipv4_address v4)
    {
        return ostream << '['
            << v4.address[0] << '.'
            << v4.address[1] << '.'
            << v4.address[2] << '.'
            << v4.address[3] << ']';
    }

    struct ipv6_address
    {
        std::array<hex_byte, 16> address;
    };

    static_assert(sizeof(ipv6_address) == 16);

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, ipv6_address v6)
    {
        return ostream << '['
            << v6.address[0] << v6.address[1] << ':'
            << v6.address[2] << v6.address[3] << ':'
            << v6.address[4] << v6.address[5] << ':'
            << v6.address[6] << v6.address[7] << ':'
            << v6.address[8] << v6.address[9] << ':'
            << v6.address[10] << v6.address[11] << ':'
            << v6.address[12] << v6.address[13] << ':'
            << v6.address[14] << v6.address[15] << ']';
    }

    struct port_number
    {
        std::array<dec_byte, 2> number;
    };

    static_assert(sizeof(port_number) == 2);

    template <class char_t, class traits_t>
    static inline std::basic_ostream<char_t, traits_t>& operator <<(std::basic_ostream<char_t, traits_t>& ostream, port_number p)
    {
        return ostream << static_cast<dec_short>(static_cast<uint16_t>(p.number[0]) << 8 | static_cast<uint16_t>(p.number[1]));
    }
}

#pragma pack(pop)

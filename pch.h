// pch.h - precompiled header

#ifndef PCH_H
#define PCH_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <iphlpapi.h>
#include <winsock2.h>

#define HAVE_REMOTE
#include <pcap/pcap.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>

#include <stdexcept>
#include <memory>
#include <optional>
#include <functional>
#include <array>
#include <string>
#include <vector>
#include <iomanip>
#include <iostream>

#endif //PCH_H

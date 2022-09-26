# WSL UDP Router📡

This is experimental project.

This program captures UDP packets arriving to specified adapter/port on Windows, and redirects them to internal service port on WSL2.

This allows external clients of the Windows host to access UDP services (e.g. agones on minikube) on WSL2.

## Limitations

### Need to disable WinNAT

By default, WinNAT NATs packets from WSL2 to external hosts.

This causes external clients to receive duplicate packets. One is sent by this router and the other is sent by WinNAT from the Windows's ephemeral port.

To work around this, you need to
  - stop the WinNAT service ("net stop winnat" in command prompt)
  - or manually reassign IP addresses outside the WinNAT range to the vEthernet(WSL) adapter and the eth0 adapter.


### Sample configuration:

```cpp
// std::map<std::string, const char*>
auto command_line_options = std::get<0>(parse_command_line_args(
    argc, argv, {
        {"--frontend-ip", nullptr},        // Windows Physical (front-end)            e.g. "10.1.1.123"
        {"--frontend-adapter", nullptr},   // Windows Physical MAC address(front-end) e.g. "00:00:5E:00:53:AF"
        {"--internal-adapter", nullptr},   // Windows vEthernet MAC address(WSL)      e.g. "00:15:5D:F2:CF:6E"
        {"--internal-next-hop", nullptr},  // Next hop MAC address (WSL eth0)         e.g. "00:15:5D:E0:A8:CE"
        {"--internal-server-ip", nullptr}, // Target server ip address                e.g. "192.168.49.2"
        {"--inbound-filter", nullptr},     // Packet filter expression                e.g. "ip dst host 10.1.1.123 and udp dst port 7777"
        {"--outbound-filter", nullptr},    // Packet filter expression                e.g. "ip src host 192.168.49.2 and udp src port 7777"
    }));

//
//                   [Client] <( send to 10.1.1.223:7777/udp )
//                       |
//                       |
//      Physical |---+---+-----------| 10.1.1.0/24
//                   |
//                   | Physical (frontend)
//                   | 10.1.1.123         <- --frontend-ip
//                   | 00:00:5E:00:53:AF  <- --frontend-adapter
// +-------------- [Windows] --------------------------------------------+
// |                     | Internal (vEthernet (WSL))
// |                     | 192.168.252.1/24
// |                     | 00:15:5D:F2:CF:6E  <- --internal-adapter
// |                     |
// |    Hyper-V  |---+---+-----------| 192.168.252.0/24
// |                 |
// |                 | eth0
// |                 | 192.168.252.101/24
// |                 | 00:15:5D:E0:A8:CE  <- --internal-next-hop
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
```

## Requirements

WinPcap library required. 

Original WinPcap seems unable to enumerate WSL i/f, so you need either
- Npcap
- Win10Pcap
- or else.

## Configure

1. Rewite `WSLRouter.cpp` `int packet_router()` config section for your environment.
2. Build and run.

## License
MIT License (c) 2022 ttsuki


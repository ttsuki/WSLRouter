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

// NAT Config
const auto frontend_ip = parse_ipv4("10.1.1.223");             // Windows Physical (front-end)
const auto frontend_adapter = parse_mac("00:00:5E:00:53:AF");  // Windows Physical (front-end)
const auto internal_adapter = parse_mac("00:15:5D:F2:CF:6E");  // Windows vEthernet (WSL)
const auto internal_next_hop = parse_mac("00:15:5D:E9:A8:CE"); // Next hop for Target server (WSL eth0)
const auto internal_server_ip = parse_ipv4("192.168.49.2");    // Target server ip address
const auto inbound_filter = R"(ip dst host 10.1.1.223 and udp dst port 7777)";
const auto outbound_filter = R"(ip src host 192.168.49.2 and udp src port 7777)";

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


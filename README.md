# WSL UDP Router📡

This is experimental project.

This program redirects UDP packets arriving on a Windows host to internal service port on WSL2.

This allows external clients of the Windows host to access services (e.g. agones on minikube) on WSL2.

## Limitations

This program will capture a packet, rewirte destination of packet, and resend it to WSL host via vEthernet interface.

That packets will be delivered to WSL2 host (or more inner host via ip forwarding).  However, returning packets from WSL2 host are returned to client via WinNAT on Windows host, so services that depends on udp's `connect` context may not work.

### My network (sample):

```cpp
// config
const auto wan_adapter = pcappp::find_adapter_from_ip("10.1.1.223");
const auto lan_adapter = pcappp::find_adapter_from_ip("172.17.240.1");
const auto inbound_filter = R"(ip dst host 10.1.1.223 and udp dst port 7777)";
const auto smac = std::array<u_char, 6>{0x00, 0x15, 0x5D, 0xF2, 0xCF, 0x6E}; // Windows WSL 
const auto dmac = std::array<u_char, 6>{0x00, 0x15, 0x5D, 0xE9, 0xA8, 0xCE}; // WSL eth0
const auto dst = std::array<u_char, 4>{192, 168, 49, 2};                     // target ip (minikube) address via WSL eth0

//
//               [Client] <( send to 10.1.1.223:7777/udp )
//                   | 10.1.1.1
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
//                   | 192.168.49.1 br-xxxxxxxxxxxx
//                   |
//  minikube |---+---+-----------| 192.168.49.0/24
//               |
//               | 192.168.49.2:7777/udp <- Desired service.
//           [Server Node]
//                  |||
//                  [[[Containers]]] (Cluster-IPs)
//
```

1. Clients (`10.1.1.1:59999/udp`) packet send to `10.1.1.223:7777/udp`.
2. This program capture that packet, and rewrite destintion header of packet to `192.168.24.2:7777`, then send it to `eth0`(`00:15:5D:E9:A8:CE`) from the `vEthernet (WSL)` interface.
3. WSL2 forwards the packet arriving on `eth0` to the service port on minikube network.
    - `sudo iptables -A FORWARD -j ACCEPT`
    - `sudo sysctl -w net.ipv4.ip_forward=1`
4. The service provides some service and send a repliyng packet to `10.1.1.3:59999/udp`
5. Windows host doesn't know the packet is replying, does NAPT the packet as from `10.1.1.223:ehphemel/udp`, send to `10.1.1.1:59999/udp`.
6. `10.1.1.1:59999/udp` receive packet from `10.1.1.223:ehphemel/udp` rather than `10.1.1.223:7777/udp`.
    - This returning packet may cause distination unreachable. UDP's connection context expects packet returning from `7777/udp` and does not allow to receive returning packets from other ports.  
    - If the client is behind another NAPT router, the returning packet may be blocked by the NAPT router.  This is the same situation where UDP hole punching is required.

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


### Simple router with a static routing table.
The router will receive raw Ethernet frames.It will process the packets, then forward them to the correct outgoing interface.
The router will route packets from an emulated host (client) to two (2) emulated application servers (HTTP Server 1 and 2) sitting behind the router.
The application servers are each running an HTTP server. You can access these servers using regular client software.

Based on Stanford CS144 Starter Code
All personal work is in sr_router.c, sr_arpcache.c and their respective header files.

### All of the following operations work:
Pinging from the client to any of the router's interfaces (192.168.2.1, 172.64.3.1, 10.0.1.11).
Tracerouting from the client to any of the router's interfaces.
Pinging from the client to any of the app servers (192.168.2.2, 172.64.3.10).
Tracerouting from the client to any of the app servers.
Downloading a file using HTTP from one of the app servers.

### Setup
This router runs on top of Mininet. https://github.com/mininet/mininet/releases/

Configure the environment by running the config.sh file and start Mininet emulation by using the following command:
```
> cd ~/cs144_lab3/
> ./config.sh
> ./run_mininet.sh
```
Run the controller:
```
> cd ~/cs144_lab3/ > ./run_pox.sh
```
Make:
```
> cd ~/cs144_lab3/router/
> make
> ./sr
```
To test out the connectivity of the environment setup, run the binary file of the solution:
```
> cd ~/cs144_lab3/ > ./sr_solution
```
### Additional Functionality

The router routes packets between the Internet and the application servers.
The router handles ARP requests and replies.
The router handles traceroutes through it (where it is not the end host) and to it (where it is the end host).
The router responds to ICMP echo requests.
The router responds to TCP/UDP packets sent to one of its interfaces with an ICMP port unreachable.
The router maintains an ARP cache whose entries are invalidated after a timeout period (15 seconds).
The router queues all packets waiting for outstanding ARP replies.
If a host does not respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message is sent back to the source of the queued packet.
The router enforces guarantees on timeouts--that is, if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router.


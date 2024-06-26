# adblock load balancer 2000
Tool to forward raw DNS requests to the PiHole/Adguard with the least load (2+ required). Built for home LAN usage, my agents run on gen 1 Raspberry Pi units which I wanted to make use of as a summer project for 2023. Components here include: 
1. Agents script (pushes server usage stats where PiHole/Adguard is installed)
![agent](https://raw.githubusercontent.com/antoinesylvia/adblock_load_balancer/main/z_pics/agent.PNG)
2. Metrics script (collects real-time server usage information from agents)
![metrics](https://raw.githubusercontent.com/antoinesylvia/adblock_load_balancer/main/z_pics/metrics.PNG)
3. Load Balancer main script (uses data pulled from metrics to make a decision).
![load_balancer](https://raw.githubusercontent.com/antoinesylvia/adblock_load_balancer/main/z_pics/load_balancer.PNG)
-------------------
Flow options for devices - Backend:
1. Device on LAN<-->Load Balancer<-->PiHole/AdguardHome<-->Unbound(recursive DNS - local install)
2. Device on LAN<-->Load Balancer<-->PiHole/AdguardHome<-->Unbound(recursive DNS - local install)<-->3rd party (CloudFlare/Google etc.)
3. Device on LAN<-->Load Balancer<-->PiHole/AdguardHome<-->3rd party (CloudFlare/Google etc.)
-------------------
Flow for componments:
Agents-->Metrics script<--->Load Balancer main--->PiHole/AdguardHome

1. Agents script - Running on servers with PiHole/AdguardHome installed, pushes server usage data (psutil).
2. Metrics script - Running on server without PiHole/Adguard, collects usage data via UDP and allows metrics pulls via HTTP (short term data only).
3. Load Balancer main - Pulls metrics data, makes server decision for DNS request based on least load.
4. PiHole/AdguardHome - Receives DNS request.
-------------------
Fallback Mode:
- Provides a backup mechanism when the metrics server isn't unavailable or not responding correctly. In the fallback mode, the DNS server continues to handle DNS requests by randomly selecting a Pi-hole server, ensuring that the DNS resolution service remains operational even if the metrics-based server selection is not possible.
   
-------------------
Router config in DNS settings:
1. WAN DNS - Add the IP of the server(s) where you are running the Load Balancer main script.
2. LAN DNS - Add the IP of the server(s) where you are running the Load Balancer main script (for advanced router software running under Unifi or PfSense etc., LAN DNS will ensure devices with DNS set as automatic will use the IP(s) for the Load Balancer).

- I recommend running the Load Balancer main script on two devices for redundancy. The IP address info data should show primarily IPs for devices (non-router) in metrics if you have LAN DNS setup appropiately. 
- If you have a Wireguard server running on a seperate VLAN than the Load Balancer server running the script, you can add a firewall rule so devices can send DNS requests directly or you can route them through the gateway (metrics logs will show gateway IP for these requests).
-------------------
Host config in DNS settings:
1. For the server(s) running the Load Balancer main script, ensure UDP port 53 is open on the host firewall (receive DNS traffic from devices)
2. For the server(s) running the Metrics script, ensure the 2 ports you select for UDP (need to accept inbound metrics data for server usage from agents) and TCP (used by load balancer main script to pull metrics data for server usage)
-------------------
Setup config file (samples attached in repo):
1. Agents - See comments in sample stored in this repo, adjust IPs and ports based on your setup.
2. Metrics -  See comments in sample stored in this repo, adjust IPs and ports based on your setup.
3. Load Balancer -  See comments in sample stored in this repo, adjust IPs and ports based on your setup.
-------------------
To-do:
1. Assymetric - Add RSA keys (public/private) for initial handshake between components.
2. Symmetric - Use to transfer data (pre-shared).
3. Dockerized version.
4. Discord Notifications

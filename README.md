# adblock load balancer 2000
Tool to forward raw DNS requests to the PiHole/Adguard with the least load (2+ required). Built for home LAN usage. Components here include: 
1. Agents script (pushes server usage stats where PiHole/Adguard is installed)
2. Metrics script (collects real-time server usage information from agents)
3. Load Balancer main script (uses data pulled from metrics to make a decision).
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
Router config in DNS settings:
1. WAN DNS - Add the IP of the server(s) where you are running the Load Balancer main script.
2. LAN DNS - Add the IP of the server(s) where you are running the Load Balancer main script (for advanced router software running under Unifi or PfSense etc., LAN DNS will ensure devices with DNS set as automatic will use the IP(s) for the Load Balancer).

- note 1: I recommend running the Load Balancer main script on two devices for redundancy. The IP address info data should show primarily IPs for devices (non-router) in metrics if you have LAN DNS setup appropiately. 
- note 2: If you have a Wireguard server running on a seperate VLAN than the Load Balancer server running the script, you can add a firewall rule so devices can send DNS requests directly or you can route them through the gateway (metrics logs will show gateway IP for these requests).
-------------------
Host config in DNS settings:
1. For the server(s) running the Load Balancer main script, ensure UDP port 53 is open on the host firewall (receive DNS traffic from devices)
2. For the server(s) running the Metrics script, ensure the 2 ports you select for UDP (need to accept inbound metrics data for server usage from agents) and TCP (used by load balancer main script to pull metrics data for server usage)
-------------------
Setup config file (coming soon, sampe is attached in repo):
1. Agents - 
2. Metrics -
3. Load Balancer - 
-------------------
To-do:
1. Assymetric - Add RSA keys (public/private) for initial handshake between components.
2. Symmetric - Use to transfer data (pre-shared).
3. Dockerized version.
4. Discord Notifications

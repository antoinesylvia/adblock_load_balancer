# adblock_load_balancer
Tool to forward raw DNS requests to the PiHole/Adguard with the least load (2+ required). Built for home LAN usage. Components here include: 
1. Agents script (pushes server usage stats where PiHole/Adguard is installed)
2. Metrics script (collects real-time server usage information from agents)
3. Load Balancer main script (uses data pulled from metrics to make a decision).

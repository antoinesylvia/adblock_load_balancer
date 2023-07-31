# adblock_load_balancer
Tool to forward raw DNS requests to the PiHole/Adguard with the least load (2+ required). Components here include: Agents script (pushes server usage stats where PiHole/Adguard is installed), Metrics script (collects real-time server usage information from agents), and Load Balancer main script (uses data pulled from metrics to make a decision).

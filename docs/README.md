# 🛡️ Network Monitoring Tool  
A Python-based real-time network monitoring tool with threat detection, geolocation, and live alerts.  

---

## 🚀 **Features**  
✅ Real-time packet monitoring (TCP, UDP, ICMP)  
✅ IP-based filtering  
✅ Risk severity assessment (Low, Medium, High)  
✅ Threat detection (DDoS, SYN flood, Port Scanning)  
✅ Geolocation (Country + City)  
✅ Dark mode + Live alerts  

---

## 🌐 **Setup**  
1. Download the GeoLite2 database from [https://www.maxmind.com](https://www.maxmind.com)  
2. Place `GeoLite2-City.mmdb` in the project folder  
3. Install the required dependencies:
   
 install the required python packages and libraries

Run the tool:
python src/network_monitor.py

Output Example:
[+] Starting packet capture...
TCP Packet: 192.168.1.2:443 --> 192.168.1.3:65432 (United States, New York) [Severity: LOW]
UDP Packet: 192.168.1.2:53 --> 192.168.1.3:12345 (Germany, Berlin) [Severity: MEDIUM]
[ALERT] DDoS attack detected from 192.168.1.10!

📊 Real-Time Stats
Metric	       Value
Packets/sec	   34.5
Error Rate	   2.5%
TCP Traffic	   65%
UDP Traffic	   30%
ICMP Traffic	 5%

🌍 Geolocation
The tool retrieves the country and city of the source IP using the GeoLite2 database.
Example:
192.168.1.2 → United States, New York

⚠️ Threat Detection
Threat Type	     Description	                                            Severity
DDoS Attack	     High volume of traffic from the same source	            High
Port Scanning	   Multiple connection attempts from the same source	      Medium
SYN Flood	       High number of SYN packets without completing handshake	High

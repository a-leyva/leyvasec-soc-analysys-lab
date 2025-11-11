cat > Wireshark_Traffic_Investigation.md <<'MD'
# Wireshark — Network Traffic Investigation
**Date:** 2025-11-10  
**Objective:** Identify suspicious traffic and possible data exfiltration in a controlled lab environment (OWASP Juice Shop running locally).

**Environment:** Kali Linux (host) running OWASP Juice Shop Docker container (target) — lab only.

**Tools:** tcpdump, Wireshark

**Capture command:**  
`sudo tcpdump -i eth0 -w ~/20251110_wireshark_capture.pcap`

**Filters used:**  
- `http`  
- `http.request.method == "POST"`  
- `dns`  
- `ip.addr == 127.0.0.1` *(localhost:3000)*

**Steps performed:**  
1. Captured ~90 seconds of traffic while interacting with the web lab.  
2. Loaded PCAP in Wireshark and analysed Conversations and Endpoints to find heavy talkers.  
3. Filtered HTTP POSTs and followed TCP/HTTP streams to inspect form data and responses.  
4. Examined DNS queries for long/encoded subdomains (possible tunnelling).  
5. Exported a subset of suspicious packets to `20251110_suspicious_traffic.pcap`.

**Findings:**  
- Multiple POST requests to `/rest/auth/login` demonstrating form submissions (lab PoC).  
- No real user data (lab environment); clear example of how credentials or session tokens may be observed in insecure transports.  
- Example suspicious DNS queries contained long encoded labels (lab demonstrates DNS payload patterns).

**Remediation & notes:**  
- Use HTTPS for all forms (TLS) and enforce secure cookies and HSTS.  
- Monitor DNS patterns for unusually long subdomains; implement egress filtering.  
- In production, restrict which services can make outbound DNS requests and inspect DNS logs.

**Artifacts included:**  
- `20251110_wireshark_capture.pcap` (original)  
- `20251110_suspicious_traffic.pcap` (subset)  
- `20251110_wireshark_tcpstream_post.png`  
- `20251110_wireshark_conversations.png`  
- `20251110_wireshark_dns_query.png`  
- `20251110_wireshark_notes.txt`
MD

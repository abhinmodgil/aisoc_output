### Dimension: IOC in Threat Intel
- [MISP] Is the IP address `47.250.57.32` present in MISP? What are its associated tags, events, and reputation?

### Dimension: Network Behavior
- [Wazuh] Show all web traffic from Source IP `47.250.57.32` to Agent IP `10.50.1.10` in the last hour. Were there other suspicious requests?
- [Velociraptor] Search web server logs on `ALU-WEB-PROD-01` for any requests from `47.250.57.32` that resulted in a 404 Not Found status.

### Dimension: Process Behavior
- [Velociraptor] On host `ALU-WEB-PROD-01`, what processes were active at the time of the alert (`2024-05-21T10:20:50.912+0000`)?
- [Velociraptor] Was there any unusual network activity involving ports 80/443 around the timestamp of the alert?

### Dimension: Host Vulnerability
- [Organization Database] What web server software and version is running on `ALU-WEB-PROD-01`? Is it known to be vulnerable to directory traversal attacks?
- [Wazuh] Does the host `ALU-WEB-PROD-01` have any web-related vulnerabilities reported in the last vulnerability scan?
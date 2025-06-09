### Dimension: Network Behavior
- [Wazuh] Show all POST requests to `/cart/add` on `ALU-WEB-PROD-01` in the last 24 hours. Are there any unusual patterns?
- [Wazuh] Search for any other alerts related to `ALU-WEB-PROD-01` in the last week. Are they related to DDoS attempts?

### Dimension: IOC in Threat Intel
- [MISP] Is the IP address `198.51.100.25` present in MISP? What are its associated tags, events, and reputation?

### Dimension: Process Behavior
- [Velociraptor] On host `ALU-WEB-PROD-01`, check the parent process of the web server (`w3wp.exe`) at the time of the alert. Was anything else happening around that time?
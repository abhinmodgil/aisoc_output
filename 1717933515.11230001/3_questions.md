### Dimension: Network Behavior
- [Wazuh] Show all network traffic between Source IP `10.50.3.20` and Destination IP `104.207.51.245` in the last 24 hours. Are there other suspicious flows?
- [Velociraptor] Search firewall logs on `ALU-FW-EDGE-01` for any connections involving `10.50.3.20`. Are there unusual patterns?

### Dimension: IOC in Threat Intel
- [MISP] Is the Destination IP `104.207.51.245` present in MISP? What are its associated tags, events, and reputation?
- [MISP] Is the Source IP `10.50.3.20` present in MISP? What are its associated tags, events, and reputation?

### Dimension: Contextual Guidance
- [Organization Database] What role does `ALU-FW-EDGE-01` play in the network architecture? Is it a perimeter firewall or internal gateway?
- [Organization Database] What services does `ALU-FW-EDGE-01` typically allow through? Are there any unexpected ports open?
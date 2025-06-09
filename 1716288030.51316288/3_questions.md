### Dimension: Network Behavior
- [Wazuh] Show all web traffic from Source IP `192.168.10.50` to Agent IP `10.50.2.5` in the last hour. Were there other suspicious requests?
- [Velociraptor] Search web server logs on `ALU-AUTH-PROD-01` for any POST requests from `192.168.10.50` that resulted in a 401 Unauthorized response.

### Dimension: IOC in Threat Intel
- [MISP] Is the IP address `192.168.10.50` present in MISP? What are its associated tags, events, and reputation?

### Dimension: User Attribution
- [Organization Database] Who is the owner of the agent `ALU-011`? Are they authorized to access `/oauth2/token`?
- [Wazuh] Search for authentication failures involving `ALU-011` in the last week. Did any occur around the time of the alert?

### Dimension: Contextual Guidance
- [Organization Database] What is the purpose of the service running on `ALU-AUTH-PROD-01`? Is it expected to receive POST requests to `/oauth2/token`?
- [Wazuh] Check the latest configuration changes made to `ALU-AUTH-PROD-01`. Have any recent updates been applied that might affect security posture?
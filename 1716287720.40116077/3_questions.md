### Dimension: Network Behavior
- [Wazuh] Show all network traffic from IP `203.0.113.75` to `ALU-WEB-PROD-01` in the last 24 hours. Are there any unusual patterns?
- [Velociraptor] Check firewall logs on `ALU-WEB-PROD-01` for any blocked connections from `203.0.113.75`.

### Dimension: IOC in Threat Intel
- [MISP] Is the IP address `203.0.113.75` present in MISP? What are its associated tags, events, and reputation?

### Dimension: User Attribution
- [Organization Database] Who is the user `diana.gomez`? What role does she play within the organization?
- [Wazuh] Has `diana.gomez` ever logged in remotely before? When did they last access the system?

### Dimension: Contextual Guidance
- [Organization Database] What operating system and software versions are running on `ALU-WEB-PROD-01`?
- [Organization Database] Are there any recent changes to the environment that could explain the alert?
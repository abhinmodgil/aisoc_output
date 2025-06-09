### Dimension: Network Behavior
- [Wazuh] Show all failed logons from IP `203.0.113.75` to `ALU-WEB-PROD-01` in the last 24 hours. Are there other failed attempts?
- [Velociraptor] Search event logs on `ALU-WEB-PROD-01` for any failed logons from `203.0.113.75`. Are they related to `diana.gomez`?

### Dimension: IOC in Threat Intel
- [MISP] Is the IP address `203.0.113.75` present in MISP? What are its associated tags, events, and reputation?

### Dimension: User Attribution
- [Organization Database] Who is the owner of the account `diana.gomez`? What is their role within the organization?
- [Wazuh] Check for recent changes to the `diana.gomez` account in Active Directory. Has her password been reset recently?

### Dimension: Contextual Guidance
- [Organization Database] What are the typical login patterns for users on `ALU-WEB-PROD-01`? How many failed logins per day are normal?
- [Wazuh] Compare the number of failed logins from `203.0.113.75` against the total number of failed logins on `ALU-WEB-PROD-01` over the past week.
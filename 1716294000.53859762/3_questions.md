### Dimension: Network Behavior
- [Wazuh] Show all failed logons from IP `10.50.1.30` to `ALU-WEB-PROD-01` in the last 24 hours. Are there any patterns?
- [Velociraptor] Search event logs on `ALU-WEB-PROD-01` for repeated failed logons from `10.50.1.30`.

### Dimension: IOC in Threat Intel
- [MISP] Is the IP address `10.50.1.30` present in MISP? What are its associated tags, events, and reputation?

### Dimension: User Attribution
- [Organization Database] Who is the owner of the account `alu-backupsvc$`? Is this a service account or a human user?
- [Wazuh] Check for any recent changes to the permissions or attributes of the `alu-backupsvc$` account.

### Dimension: Contextual Guidance
- [Organization Database] What is the purpose of the `ALU-BCK-PROD-01` workstation? Is it used for backups or something else?
- [Wazuh] Search for any unusual activities involving the `ALU-BCK-PROD-01` workstation around the time of the alert.
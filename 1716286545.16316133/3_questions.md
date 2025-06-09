### Dimension: Process Behavior
- [Velociraptor] On host 'ALU-SUPPORT-PROD-01', what is the full path of the executable that created `/tmp/.X11-unix/Xrootkit`?
- [Velociraptor] What other files were created or modified around the time `/tmp/.X11-unix/Xrootkit` appeared?

### Dimension: Host Vulnerability
- [Wazuh] Has the host 'ALU-SUPPORT-PROD-01' ever had a rootkit detection before? Check the last 30 days of alerts.
- [Wazuh] Are there any open ports on this host that could indicate compromise? Run a port scan.

### Dimension: User Attribution
- [Organization Database] Who has access to the 'ALU-SUPPORT-PROD-01' machine? Are there any recent changes to user permissions?
- [Wazuh] Did any unusual logins occur around the time of the alert? Look for failed login attempts or unexpected remote sessions.

### Dimension: Contextual Guidance
- [Organization Database] What is the purpose of the 'ALU-SUPPORT-PROD-01' machine? Is it a critical asset?
- [Organization Database] When was the last security audit performed on this host? Was anything noted as potentially vulnerable?
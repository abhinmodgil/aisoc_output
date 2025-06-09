### Dimension: User Attribution
- [Organization Database] Who is the user 'anika.sharma'? What role does she typically play within the organization?
- [Wazuh] Has 'anika.sharma' ever been flagged for unusual behavior before? Check for previous alerts involving her account.

### Dimension: Process Behavior
- [Velociraptor] On host 'ALU-WEB-PROD-01', what was the parent process of the 'net.exe' command that added 'temp_admin_svc' to the 'Administrators' group?
- [Velociraptor] What child processes, network connections, or file modifications were initiated by this 'net.exe' process?

### Dimension: Host Vulnerability
- [Wazuh] Does the host 'ALU-WEB-PROD-01' have any known, unpatched vulnerabilities related to local privilege escalation (LPE) or group manipulation?
- [Wazuh] Are there any recent changes to the host configuration that could explain this event?

### Dimension: Contextual Guidance
- [Organization Database] When did 'anika.sharma' join the company? Was she recently promoted or assigned new responsibilities?
- [Organization Database] Have there been any recent organizational changes, such as restructuring or policy updates, that might justify this action?
### Dimension: Process Behavior
- [Velociraptor] On host 'ALU-BCK-PROD-01', what processes were active when the removable media was detected?
- [Velociraptor] Did any processes attempt to read or copy files from the inserted drive?

### Dimension: Host Vulnerability
- [Wazuh] Has this host ever had a similar USB-based attack before? Check for previous alerts involving removable devices.
- [Wazuh] Are there any known vulnerabilities in the operating system or installed software that could allow unauthorized access via removable media?

### Dimension: User Attribution
- [Organization Database] Who has physical access to the backup server 'ALU-BCK-PROD-01'? Are they authorized to insert removable drives?
- [Wazuh] Was the user 'ALU-BCK-PROD-01$' involved in any unusual activities around the time of the alert?

### Dimension: Contextual Guidance
- [Organization Database] What is the purpose of the 'ALU-BCK-PROD-01' server? Is it supposed to accept removable media at all?
- [Organization Database] Have we seen similar alerts in other environments? How did those investigations proceed?
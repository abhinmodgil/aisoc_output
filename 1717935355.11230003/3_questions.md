### Dimension: Process Behavior
- [Velociraptor] On host 'ALU-ENDUSR-01', what was the parent process of the 'powershell.exe' process that ran the malicious command?
- [Velociraptor] What child processes, network connections, or file modifications did the 'powershell.exe' process initiate?

### Dimension: Host Vulnerability
- [Wazuh] Has the host 'ALU-ENDUSR-01' been flagged for any recent security incidents or vulnerabilities?
- [Wazuh] Are there any open ports or services on 'ALU-ENDUSR-01' that could indicate compromise?

### Dimension: IOC in Threat Intel
- [MISP] Is the hash of the encoded PowerShell command (`cmd.exe /c powershell -enc...`) present in MISP? What are its associated tags, events, and reputation?
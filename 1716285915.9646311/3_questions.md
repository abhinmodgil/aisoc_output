### Dimension: Process Behavior
- [Velociraptor] Inspect process `2508` on host `ALU-ORDPROC-PROD-01`. What is its full command line? Who started it?
- [Velociraptor] List all open files and network sockets associated with process `2508`. Are they legitimate?

### Dimension: Host Vulnerability
- [Wazuh] Check the agent's vulnerability database for any recent updates related to Linux kernel exploits.
- [Wazuh] Run a quick scan using the Wazuh rootkit detection module against the host.

### Dimension: Contextual Guidance
- [Organization Database] What is the purpose of the `ALU-ORDPROC-PROD-01` host? Is it a production server?
- [Organization Database] Who has access to this host? Can we confirm whether the user who triggered the alert (`root`) is authorized to run such a process?
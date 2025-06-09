### Dimension: Process Behavior
- [Velociraptor] On host 'ALU-SUPPORT-PROD-01', what is the full path of the `/tmp/.X11-unix/Xrootkit` file?
- [Velociraptor] What is the current state of the Xrootkit process (`/usr/bin/xr`) on this host? Is it still running?
- [Velociraptor] List all files created or modified within the past 24 hours in `/tmp/.X11-unix`. Are there any unusual files?

### Dimension: Host Vulnerability
- [Wazuh] Has the host 'ALU-SUPPORT-PROD-01' been scanned recently for vulnerabilities? If so, were any related to rootkits or kernel exploits detected?
- [Wazuh] Check the agent's log for any recent alerts related to rootkits or kernel-level threats.

### Dimension: Contextual Guidance
- [Organization Database] What is the purpose of the 'ALU-SUPPORT-PROD-01' host? Who manages it? Is it a critical production server?
- [Organization Database] When was the last time this host underwent a security audit or penetration test? Was anything similar found then?
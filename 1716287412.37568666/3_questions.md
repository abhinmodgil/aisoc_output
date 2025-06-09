### Dimension: Process Behavior
- [Velociraptor] On host 'ALU-WEB-PROD-01', what processes were active when the removable media was detected?
- [Velociraptor] Was there any unusual network activity originating from this host around the time of detection?

### Dimension: Host Vulnerability
- [Wazuh] Has this host ever been flagged for unauthorized USB usage before?
- [Wazuh] Are there any recent alerts related to this host involving unexpected device recognition?

### Dimension: User Attribution
- [Organization Database] Who has administrative access to 'ALU-WEB-PROD-01'? Could they have authorized the insertion of a USB drive?
- [Organization Database] What software versions are installed on this host? Are there any known vulnerabilities in those versions?

### Dimension: Contextual Guidance
- [Organization Database] When was the last time this host underwent a security audit? Did it pass?
- [Organization Database] What is the expected behavior of this host within the organization? Should it recognize unknown devices?
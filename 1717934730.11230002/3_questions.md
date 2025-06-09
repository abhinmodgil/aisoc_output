### Dimension: Process Behavior
- [Velociraptor] On host 'ALU-WIN-LAP-DEV01', what was the parent process of the 'invoice.exe' process?
- [Velociraptor] What child processes, network connections, or file modifications did 'invoice.exe' make?

### Dimension: Host Vulnerability
- [Wazuh] Has 'ALU-WIN-LAP-DEV01' ever had a similar executable downloaded before? Check recent downloads and execution history.
- [Wazuh] Are there any known vulnerabilities in Windows related to the download or execution of files from unknown sources?

### Dimension: User Attribution
- [Organization Database] Who is the owner of the 'John' account on 'ALU-WIN-LAP-DEV01'? Is this a standard user or an admin?
- [Wazuh] Did the user 'John' execute any unusual programs recently?

### Dimension: Contextual Guidance
- [Organization Database] What is the expected behavior of the 'John' user on 'ALU-WIN-LAP-DEV01'? Should they be downloading and executing executables regularly?
### Dimension: Network Behavior
- [Wazuh] Show all POST requests from Source IP `198.51.100.25` to Agent IP `10.50.1.10` in the last hour. Were there other suspicious requests?
- [Velociraptor] Search web server logs on `ALU-WEB-PROD-01` for any POST requests from `198.51.100.25` that resulted in a 200 OK status.

### Dimension: IOC in Threat Intel
- [MISP] Is the IP address `198.51.100.25` present in MISP? What are its associated tags, events, and reputation?

### Dimension: Process Behavior
- [Velociraptor] On host `ALU-WEB-PROD-01`, what was the parent process of the web server process handling the `/cart/add` endpoint?
- [Velociraptor] What child processes, network connections, or file modifications did this process initiate after receiving the POST request?
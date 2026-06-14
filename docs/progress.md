## Universal Forwarder Configuration
Status: Complete

### What was built
Created inputs.conf on the Windows endpoint to forward Security, System, and Application Windows Event Logs to the Splunk indexer.

### Key decisions
Switched both VMs to a NAT Network so they could communicate directly with each other while still reaching the internet.

Connected the Universal Forwarder to the Splunk receiving port 9997.

inputs.conf was required separately from the forward-server connection. Connecting to the indexer and configuring what to send are two different steps.

### Problems solved
Initial connection attempts failed because Splunk needed to be restarted after lowering the disk space threshold.

The add forward-server command required local forwarder credentials created during MSI install, not the Splunk Enterprise admin account.

inputs.conf did not exist by default and had to be created manually to begin forwarding Windows Event Logs.

### Network+ and security concepts this covers
TCP port 9997 is the standard Splunk forwarder to indexer communication port.

Windows Event Log categories: Security (logins, privilege use), System (OS level events), Application (software events).

NAT Network vs NAT in VirtualBox and how virtual machines communicate with each other.

### Result
Windows Security, System, and Application logs are now flowing into Splunk in real time and searchable with index=main.
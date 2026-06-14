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

## Failed Login Detection
Status: Complete

### What was built
A scheduled Splunk alert called Multiple Failed Logins Detected. It searches for Event ID 4625 (failed logon) grouped by host, and triggers when 3 or more occur within a 15 minute window.

### Search query
index=main EventCode=4625
| stats count by host, ComputerName
| where count >= 3

### Schedule
Runs every 5 minutes using cron schedule */5 * * * *

### Severity reasoning
Set to Medium. A few failed logins are normal user error. Three or more in a short window could indicate a brute force attempt or a user locked out, both worth investigating but not an automatic critical incident.

### Network+ and security concepts this covers
Windows Event ID 4625 is the standard failed logon event.

Cron syntax for scheduling recurring tasks, a concept used across Linux and many monitoring tools.

Detection thresholds and severity tiers, a core SOC analyst concept. Not every event needs the same level of urgency.

### Real test
Generated failed logins manually by entering the wrong password 3 times at the Windows lock screen. The alert correctly grouped and counted these events.
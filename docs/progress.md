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

## Successful Login After Failed Attempts Detection
Status: Complete

### What was built
A scheduled Splunk alert called Successful Login After Failed Attempts. It checks for a successful login (Event ID 4624) occurring within 15 minutes of a failed login (Event ID 4625) on the same host.

### Search query
index=main (EventCode=4625 OR EventCode=4624) host=windows-endpoin
| stats earliest(eval(if(EventCode=4625, _time, null()))) as first_fail, latest(eval(if(EventCode=4624, _time, null()))) as success_time by host
| where isnotnull(first_fail) AND isnotnull(success_time) AND success_time > first_fail AND (success_time - first_fail) <= 900

### Schedule
Runs every 5 minutes using cron schedule */5 * * * *, looking back over the last 30 minutes.

### Severity reasoning
Set to High. A failed login followed by a successful one on the same host is a stronger signal than failed logins alone. It could mean a user fumbled their password and recovered, or it could mean someone guessed or cracked credentials and got in. Either way it warrants a closer look.

### Real test
Locked the Windows endpoint, failed the password 3 times, then logged in successfully. The detection correctly identified the failed attempts at 8:20:53 PM through 8:20:58 PM and the successful login 6 seconds later at 8:21:04 PM, well within the 15 minute threshold.

### Network+ and security concepts this covers
Event ID 4624 is the standard successful logon event, complementing 4625 for failed logons.

Correlating two different event types over time using stats and eval is a core technique for building behavioral detections, not just single event alerts.

The transaction command was tested first but did not produce results, so a stats based approach with earliest and latest was used instead. This is also a more performant pattern in real world Splunk environments.

## New User Account Creation Detection
Status: Complete

### What was built
A scheduled Splunk alert called New User Account Created. It watches for Event ID 4720, which fires whenever a new local user account is created on Windows.

### Search query
index=main EventCode=4720
| table _time, host, ComputerName, Account_Name, Caller_User_Name

### Schedule
Runs every 5 minutes, looking back over the last 15 minutes.

### Severity reasoning
Set to Medium-Low. New account creation is not always malicious, IT does this routinely. But it is a well known persistence technique for attackers, who create a new account after compromising a system so they have a backup way back in. The point of this alert is visibility and review, not an automatic red flag.

### Real test
Created a local account called testuser123 using net user testuser123 Password123! /add from an administrator command prompt. The event correctly logged Caller_User_Name as vboxuser (the account that created it) and Account_Name as testuser123 (the account that was created).

### Network+ and security concepts this covers
Event ID 4720 is the standard Windows event for local user account creation.

Persistence is a stage of the attack lifecycle where an attacker ensures continued access after initial compromise, often by creating new accounts or scheduled tasks.

Not every security relevant event needs to be inherently suspicious to be worth alerting on. Some alerts exist purely for visibility and audit trail purposes.
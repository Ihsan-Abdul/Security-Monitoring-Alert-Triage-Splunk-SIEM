# Alert Triage Playbook

## Overview

This playbook covers the first response steps for each of the six detections built in this project. It is written the way it would actually be used: an analyst gets an alert, and needs to know what query to run, what the result should look like if the alert is a true positive, and what to do next. The specific systems, accounts, and timing referenced below come directly from the campaign documented in [Investigations](../Investigations), rather than being generic placeholders.

Every alert in this environment triggers a "Log Event" action, so in practice an analyst would see this appear as an entry to review rather than a ticket. The steps below assume that starting point.

## Alert Triage Procedures

### Firewall Brute Force Success (High)

**What triggered it:** five or more denied connections to SSH (port 22) or RDP (port 3389) from the same source, followed by an allowed connection, within a 10-minute window.

**Triage steps:**
1. Run the investigation query: [firewall-bruteforce-investigation.spl](../Investigations/firewall-analysis/spl-queries/firewall-bruteforce-investigation.spl).
2. Confirm which system was reached. In this environment that was either the Linux server at 192.168.1.100 over SSH or the Windows server at 192.168.1.21 over RDP.
3. Check whether the timing matches a known pattern rather than a one-off. In this campaign, SSH attempts clustered around 10:00 AM and RDP attempts around 3:00 PM daily.
4. Block the source IP at the firewall.
5. Reset credentials on the affected server, since a successful connection following the failures means the attacker got in, not just attempted to.

### Windows RDP Brute Force (Medium)

**What triggered it:** five or more failed logins (Event ID 4625) for a single account within a 10-minute window.

**Triage steps:**
1. Run the investigation query: [windows-brute-force-investigation.spl](../Investigations/windows-analysis/spl-queries/windows-brute-force-investigation.spl).
2. Check whether a successful login (Event ID 4624) followed the failures for the same account and source IP. If it did, this stops being a Medium-severity failed-attempt alert and becomes an active compromise.
3. Verify whether an account lockout policy is in place. Its absence is part of why this campaign succeeded every time it was attempted.
4. Notify the account owner and confirm whether the login activity was authorized.

### Windows Admin Login from External IP (Critical)

**What triggered it:** a successful login (Event ID 4624) to an account containing "admin" from a source IP outside the internal network range.

**Triage steps:**
1. Run the investigation query: [windows-privileged-account-investigation.spl](../Investigations/windows-analysis/spl-queries/windows-privileged-account-investigation.spl).
2. Treat this as an active incident rather than something to monitor. There are very few legitimate reasons for an administrative account to authenticate from outside the network.
3. Check the timing against any recent standard-account compromise. In this campaign, the admin login followed a standard user's compromised credentials by seven minutes, which is what confirmed credential reuse rather than a coincidental external login.
4. Look for activity immediately following the login, since this is typically the point where an attacker begins doing something with the access they just gained.

### Malicious PowerShell or PsExec Execution (High)

**What triggered it:** Event ID 4688 showing `powershell.exe` with an encoded command, or `psexec.exe` execution.

**Triage steps:**
1. Run the investigation query: [windows-process-monitoring-investigation.spl](../Investigations/windows-analysis/spl-queries/windows-process-monitoring-investigation.spl).
2. Decode the PowerShell command if one is present, rather than treating the flag alone as sufficient information.
3. Review the full command line for PsExec activity, including the target host and any credentials passed on the command line. In this campaign, the account password was visible in plaintext in the command line, which is its own finding independent of the lateral movement itself.
4. Determine which host was targeted and whether the account used has access beyond what was already compromised. Lateral movement toward a domain controller, as seen here, should be escalated immediately.

### Linux SSH Brute Force (Medium)

**What triggered it:** five or more failed SSH login attempts from a single source within a 10-minute window.

**Triage steps:**
1. Run the investigation query: [linux-brute-force-investigation.spl](../Investigations/linux-analysis/spl-queries/linux-brute-force-investigation.spl).
2. Identify the targeted account and check whether any of the failed attempts were followed by a success.
3. Check the port the attempts landed on. This campaign used port 4444 rather than the standard port 22, so a triage step that assumes SSH activity only happens on port 22 would miss it.

### Linux SSH Root Attack (Critical)

**What triggered it:** a successful login to the root account following a cluster of failed attempts.

**Triage steps:**
1. Run the investigation query: [root-attacks-investigation.spl](../Investigations/linux-analysis/spl-queries/root-attacks-investigation.spl).
2. Treat a positive result as full system compromise, not a brute force attempt in progress. Root access means the attacker has complete control of the host.
3. Check for activity on other non-standard ports following the root login. In this campaign, several additional accounts were accessed on other ports shortly after root was compromised, which pointed to further movement rather than a single isolated login.
4. Begin incident response rather than standard triage. The response actions taken once this alert was confirmed are documented in the companion [Incident Response Report](https://github.com/Ihsan-Abdul/Incident-Response-Triage-Documentation).

## Correlation Steps

When any one of these alerts fires, check the following before treating it as isolated:

1. Search for the same source IP across firewall, Windows, and Linux logs. In this campaign, all three source IPs appeared across all three systems, which is what confirmed a single coordinated attack rather than three unrelated events.
2. Build a timeline around the alert rather than looking at it in isolation. The firewall breach, Windows credential compromise, and Linux root compromise in this campaign were separated by hours, not minutes, and would look unrelated without a timeline connecting them.
3. Check for outbound connections following any confirmed compromise, as a possible sign of data leaving the network.

## Escalation Criteria

- **Critical:** admin or root access confirmed. Escalate immediately and begin incident response rather than continuing standard triage.
- **High:** a brute force attempt succeeded, or an encoded PowerShell command was found. Escalate for further investigation.
- **Medium:** failed attempts only, with no confirmed success. Document the activity and continue monitoring for escalation.

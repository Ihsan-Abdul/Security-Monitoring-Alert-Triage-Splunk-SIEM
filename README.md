# Security Monitoring & Alert Triage with Splunk SIEM

## Overview

This project documents a full detection workflow built in Splunk against a simulated five-day attack campaign spanning a network firewall, a Windows server, and a Linux server. It covers writing the correlation searches that would catch the campaign, investigating the sample logs to understand what actually happened, and documenting how an analyst should respond once an alert fires. The goal was to work through the same process a Tier 1 SOC analyst goes through day to day: build a detection, confirm it catches something real, and hand off clear guidance for what to do next.

## Key Skills Demonstrated

- **SIEM operations:** writing and scheduling Splunk correlation searches (SPL), configuring alerts with cron scheduling and trigger conditions, and reading search results to confirm a detection works as intended.
- **Detection engineering:** building rules to catch brute force attacks, privileged account misuse, and post-exploitation activity, and tuning thresholds against real sample data rather than guessing at reasonable values.
- **Incident investigation:** correlating firewall, Windows, and Linux logs to reconstruct a single attack timeline, rather than treating each log source as a separate, unrelated event.
- **Threat framework application:** mapping every detection and every investigation finding to specific MITRE ATT&CK techniques.
- **Security documentation:** writing a detection catalog, investigation reports, and a triage playbook that could be handed to another analyst and actually followed.

## Quick Start

- **Detection logic:** the query catalog and the reasoning behind each detection are in [Detections](Detection).
- **Investigation detail:** the full attack narrative, broken into firewall, Windows, and Linux findings, is in [Investigations](Investigations).
- **Triage procedures:** step-by-step response guidance for each alert is in [Playbooks/Alert-Triage-Playbook.md](Playbooks/Alert-Triage-Playbook.md).
- **Sample data:** the simulated logs used throughout this project are in [Sample-Logs](Sample-Logs).

## Project Structure

```
Security-Monitoring-Alert-Triage-Splunk-SIEM/
├── README.md
├── Detections/      Detection queries, alert configuration, and screenshots for each of the four scheduled alerts
├── Investigations/  The attack narrative across firewall, Windows, and Linux logs, with supporting queries and screenshots
├── Playbooks/       Triage steps for each detection, written against the specific findings from this campaign
└── Sample-Logs/     The simulated log data used to build and test every query in this project
```

## Tools and Data Sources

- **SIEM platform:** Splunk Enterprise (free license).
- **Log sources:**
  - Network firewall — allow and deny events, including activity on ports 22, 3389, 4444, and 4445.
  - Windows servers — Event IDs 4624 (successful logon), 4625 (failed logon), 4688 (process creation), and 4672 (special privileges assigned to a new logon).
  - Linux servers — SSH authentication logs (`sshd`).

### Sample Data

The simulated logs used throughout this project are in [Sample-Logs](Sample-Logs):

- `windows-logs.csv` — Windows Event Logs, including timestamps, event IDs, account names, source IPs, and command lines.
- `linux_ssh_logs.csv` — Linux SSH authentication logs, including source IP, username, port, and whether the attempt was accepted or failed.
- `firewall_logs.csv` — Firewall allow and deny events, including source, destination, protocol, and byte count.

## What Was Built

1. **Correlation searches** to detect patterns like repeated failed logins followed by a success, the signature of a brute force attempt that worked.
2. **Scheduled alerts** with threshold-based triggering, each configured with a cron schedule and a logged action, documented with screenshots of the actual Splunk configuration.
3. **Investigation queries** written to answer specific questions that came up while tracing the attack, such as whether a privileged account was used from outside the network, or whether the attacker was using non-standard ports.
4. **A triage playbook** covering all six detections, written against the actual accounts, IPs, and timing observed in this campaign rather than as a generic checklist.

## Key Learnings and Insights

- **Timing and infrastructure patterns matter as much as the attack itself.** The campaign repeated at the same two times every day and rotated across three source IPs. That consistency was a stronger indicator of automated, scripted activity than any single failed login could have been on its own.
- **No single log source told the full story.** The firewall logs showed that something got in, but only correlating them with Windows and Linux authentication events showed what the attacker did once they were inside, including the credential reuse between a standard account and an admin account, and the eventual root compromise on Linux.
- **Detection logic built around a specific port would have missed this campaign.** The attacker used ports 4444 and 4445 for SSH instead of port 22, which is why the detections and investigation queries in this project were written to key off behavior, a burst of failures followed by a success, rather than assuming attacks only show up on the standard port for a service.
- **Structured query output speeds up triage.** Using `eval` to assign a severity label and a plain-language alert name directly in the search results meant the difference between a brute force attempt and a confirmed compromise was visible at a glance, instead of requiring a second pass to interpret raw event counts.

## How to Reproduce This Project

1. Install Splunk Enterprise (free license) or start a Splunk Cloud trial.
2. Load the three CSV files from [Sample-Logs](Sample-Logs) into Splunk as file inputs, assigning them to the `firewall_logs`, `windows_logs`, and `linux_logs` indexes referenced in the queries.
3. Run the queries from [Detections](Detection) as searches to confirm they return results against the sample data, then save each one as a scheduled alert using the settings shown in the accompanying screenshots.
4. Run the investigation queries from [Investigations](Investigations) to reconstruct the attack timeline, following the three write-ups in order: firewall, then Linux, then Windows.
5. Use [Playbooks/Alert-Triage-Playbook.md](Playbooks/Alert-Triage-Playbook.md) to walk through the response steps for each alert as if it had just fired.

## Related Project: Incident Response Report

This project covers detection and investigation. The response side, including the forensic timeline, containment actions, and an executive summary of the same campaign, is documented in a companion repository: [Incident Response Report: Analysis of a 5-Day Brute Force Campaign](https://github.com/Ihsan-Abdul/Incident-Response-Triage-Documentation).

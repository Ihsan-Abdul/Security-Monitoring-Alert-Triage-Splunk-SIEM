# Investigations

This folder documents the process of tracing a single attack campaign across three data sources: the network firewall, a Windows server, and a Linux server. The three write-ups below are meant to be read in order, since each one picks up where the last left off.

1. [Firewall Analysis](firewall-analysis/firewall-attacks.md) — the initial brute force campaign against SSH and RDP, and the three attacker IPs that appear throughout the rest of the investigation.
2. [Linux Analysis](linux-analysis/linux-attacks.md) — root account compromise on the Linux server and the discovery that the attacker was using non-standard ports to avoid detection.
3. [Windows Analysis](windows-analysis/windows-attacks.md) — credential compromise, privileged account misuse, and an attempted move onto the domain controller.

Each write-up includes the SPL query used to uncover the finding and a screenshot of that query run against the sample data, so the investigation can be followed and reproduced rather than taken on faith.

For the detections that were built to catch this campaign automatically rather than found through manual investigation, see [Detections](../Detections). For the response actions taken once the campaign was confirmed, see the [Alert Triage Playbook](../Playbooks/Alert-Triage-Playbook.md) and the companion [Incident Response Report](https://github.com/Ihsan-Abdul/Incident-Response-Triage-Documentation).

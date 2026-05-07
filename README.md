# Cowboy Bebop Threat Hunting Lab

A four-episode SIEM threat detection lab built with Splunk, Sysmon, and three VirtualBox VMs — each named after a ship from Cowboy Bebop.

## Lab Architecture

| VM | OS | IP | Role |
|---|---|---|---|
| Bebop | Ubuntu 24.04 | 10.0.2.6 | Splunk Enterprise 10.2.3 (SIEM) |
| Swordfish II | Windows 11 | 10.0.2.5 | Victim — Sysmon + Universal Forwarder |
| Red Dragon | Kali Linux | 10.0.2.3 | Attacker |

## Episodes

| Episode | Technique | MITRE ATT&CK | Sysmon Event |
|---|---|---|---|
| Tank! | PowerShell download cradle | T1059.001 | Event ID 1 |
| Stray Dog Strut | Registry run key persistence | T1547.001 | Event ID 13 |
| Honky Tonk Women | LSASS memory dump attempt | T1003.001 | Event ID 1 |
| Gateway Shuffle | Rogue Windows service creation | T1543.003 | Event ID 1 |

## Detection Queries

**Episode 1 — Initial Access**

```spl
index=sysmon "powershell.exe" earliest=-30m
```

**Episode 2 — Persistence**

```spl
index=sysmon "Cowboy"
```

**Episode 3 — Credential Access**

```spl
index=sysmon "lsass"
```

**Episode 4 — Lateral Movement**

```spl
index=sysmon "GatewayShuttle"
```

## Tools Used

- Splunk Enterprise 10.2.3
- Sysmon (SwiftOnSecurity ruleset)
- Kali Linux
- VirtualBox NatNetwork

## Full Writeup

Published on Medium: [See You Space Cowboy: Bounty Hunting Threats with Splunk](https://medium.com/@jwilliams.cyber/see-you-space-cowboy-bounty-hunting-threats-with-splunk-911ffbed051a)

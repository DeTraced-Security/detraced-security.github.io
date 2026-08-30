---
title: CurseJar - A MythJS Variant
description: When Minecraft Modpacks Go Rogue
date: 2026-08-27
categories:
  - cybersecurity
  - Research
tags:
  - analysis
  - RAT
  - Malware
  - Phishing
authors: 
- tr4ceang3l
researchers: 
- slavetomints
- tr4ceang3l
- izzyboop
comments: false
published: true
---
> **Disclosure**:
>This report documents analysis of a malware incident involving malicious software, victim interviews, static and dynamic analysis, and threat-actor OSINT. Personal Identifiable Information has been omitted.
{: .prompt-warning }

# Summary
On 12 July 2026, a security incident was opened following a report from a victim on a public Discord server, who had been infected by a malicious CurseForge (Minecraft) modpack. The victim experienced a full administrator account lockout and extracted the malware sample in Safe Mode. The investigation, designated DT-TA-00003, was assigned the working name CURSEJAR and the malware was subsequently formally classified as part of the MythStealer family – an off-the-shelf, commercially available Rust-based infostealer with JavaScript bindings, sold or operated by a threat actor using the aliases `kurdishmyth`/`mythprivate`, suspected to be of Indonesian origin.

Analysis of the sample determined the strain was capable of targeting a broad range of sensitive information, including:
- Browser Credentials and Session Cookies
- Discord Authentication Tokens
- Clipboard Contents
- Cryptocurrency Wallet Data
The malware also contained functionality associated to keylogging and screen captures but was determined unused within this specific strain of the MythStealer.

Further investigation subsequently identified a secondary victim and linked both compromises to the same apparent operator. The threat-actor communications indicated that the operator used multiple delivery and social-engineering approaches, including:
- A trusted friend/impersonation - Modpack installation
- A Transactional “recovery” service - Ransoming of stolen data

Following the compromise, both victims had experienced account access issues across various platform, including Discord, and were subjected to manual extortion. The threat-actor demonstrated knowledge of account information, by sharing stolen credentials as a leverage against the victims to force a ransom.

> Note:
>The malware substantially exceeded the necessary requirements to perform an account takeover, and it is advised to be aware that the operator’s goal was solely financial.
{: .prompt-info }

#  Incident Overview

| Field                     | Detail                                                                      |
| ------------------------- | --------------------------------------------------------------------------- |
| Case                      | DT-TA-000003                                                                |
| Working Name              | CURSEJAR                                                                    |
| Malware Family            | MythJS - MythStealer derivative                                             |
| Primary Delivery Vector   | Social Engineering - Malicious Minecraft Modpack                            |
| Initial Victim Count      | 2 Confirmed, Approximately 20+ Unconfirmed                                  |
| Primary Platform          | Windows                                                                     |
| Primary Target Population | Gaming, Piracy-Adjacent Users                                               |
| Observed Victim Impact    | Discord Account Compromise, Extortion                                       |
| C2 - Exfiltration         | Discord Webhook, Potential Telegram Backup                                  |
| Analysis Methods          | Static Analysis, Dynamic Analysis, MiTM Inspection, Victim Interviews, OSINT |

# Initial Infection
The malware’s infection method is quite trivial, it relies on an obvious social engineering method orienting around utilising hijacked accounts to deliver a ZIP file containing a malicious binary – generally masking as a Mod or a Game – and trying to convince the receiver that it’s safe. In the case for this specific strain, the threat actor had went as far as to trying to show that the ZIP file was safe by going through the files with the user and even “running” the malware on their own device, with the mod they’re pretending to be.

## Delivery Method
The initial victim reported downloading a ZIP file, from someone that they assumed were a friend, presenting as a Minecraft CurseForge modpack. The archive ultimately contained a malicious JAR file. Upon decompilation of the jar, it revealed an external download stage point to a hosted by Dropbox as a means of hiding from antivirus and EDR technology.

Upon resolution, the JAR would download the executable, defining the modpack as stager in the operator’s supply chain. Once downloaded, the file was saved as `ModPack13.exe` and then called by the encapsulating stager.

### Kill Chain

![](/assets/img/mythjs/killchain.png)

# Malware Architecture
Analysis of the downloaded `ModPack13.exe` identified it as a `vercel/pkg` packaged Node.JS Single Executable Application (Node SEA), which allowed us to quickly unpack with `pkg-unpacker` to expose the filesystem snapshot and iterate it’s potential files, supply chain, and any hard-coded tokens.

The primary target file for the sample resolved down to `\snapshot\embed\main.js` which upon further analysis revealed to be a Rust WAT loader and contained the following Node.JS modules and native interfaces:
- `node-telegram-bot-api` - Unused
- `ffi-napi`
- `ref-napi`
- `sodium-native`
- `axios`
- `tough-cookie`
These components provided various functionalities for native Windows interaction, cryptographic operations, HTTP communication, browser data access, and various other collection and post-exploitation activities.

# Information Stealing Capabilities
During analysis of the malware, quite a few different data targets were identified for exfiltration, a lot of which oriented around giving the attacker more leverage to broaden their range of victims and perform an extortion on a third party platform.
## Browser Data
The malware targeted browser credential stores and associated browser data, including Chromium- and Firefox-derived storage.

Observed targets included:
- Chrome
- Firefox
- Brave

The malware also targeted browser session cookies, this is significant because session cookies can provide an attacker with access to authenticated services without necessarily requiring the victim's plaintext password, essentially allowing them access to sensitive information like bank accounts, government profiles, etc.
## Discord Credentials
The malware targeted Discord authentication material stored within the victim's local application data.

This capability is particularly relevant to the observed victim impact: both the malware analysis and subsequent victim interactions indicate that Discord access was central to the operation.

## Cryptocurrency Wallets
The malware contained targeting for browser-based cryptocurrency wallets, including extensions associated with:
- MetaMask
- Phantom
- Exodus

This expands the potential impact beyond social-media/account compromise

## Clipboard Collection
The malware also contained functionality to access clipboard contents through native Windows APIs.

Clipboard collection can expose:
- passwords
- authentication codes
- cryptocurrency addresses
- copied session information
- other sensitive material

# Anti-Analysis Capability
The sample incorporated multiple unused mechanisms intended to complicate analysis, that included the following:

The SAE incorporated some pretty typical anti-debugging, which was solely just a matter of checking if the thread was in debugging mode or being injected into, although the exact origin of the exported function could not be identified, we were able to attribute it to the design style of MythStealer.

![](/assets/img/mythjs/anti-debugging.png)

Like all SAE binaries produced for production, the typical debugging route of appending `NODE_OPTIONS`, `--require`, or `--inspect` hooking had been stripped completely from the binary. This isn’t something we would conclude to being malicious as it’s standard procedure for production built SAE binaries as a baseline defence and not inherently designed for anti-analysis as it doesn’t prevent unpacking or debugging on it’s own.

Now unlike most information stealers, MythJS includes a WASM-based loader at its core which is derived from MythStealer’s Rust core that adds an additional layer of reverse-engineering stage to obfuscate the malware’s functionality. At the time of writing, the underlying MythStealer Rust code has not been reviewed as majority of the stealer’s functionality laid bare outside of it’s predecessor’s functionality.

# Command and Control / Exfiltration
Like most off-the-shelf information stealers, or stealers attempting to blend in with the user’s general traffic, this one also leveraged Discord’s API as a way to exfiltrate the stolen information into a place where an analyst wouldn’t be able to perform an analysis against the C2 – or in some cases, the red teamer is then prevented from dumping and deleting the threat actors infrastructure. Despite the lack of attack surface, the threat actor still relied on reportable artefacts, in this case it was a Discord API Webhook, so now there is a way to report and potentially have the threat actor’s operation brought to a temporary halt.

![](/assets/img/mythjs/cookie-theft.png)

Another potential exfiltration route, that could double down as a C2, was an identified Telegram packaged that allowed for communications with threat actors over a bot. Fortunately, or unfortunately, this section of the malware’s code was remained untouched with no indicators – in the network or callstack – that indicated to the Telegram dependency being used.

# Detection Opportunities
Organizations and users should consider monitoring for:
### Network
- Unexpected connections to newly registered or suspicious hosting infrastructure
- Discord webhook communication originating from unexpected processes
- Unusual outbound HTTP requests from Minecraft/Java/Node.js processes
### Endpoint
- Unexpected executable downloads initiated by Minecraft modpacks
- node.exe-like behaviour originating from packaged applications
- Access to browser credential databases by unrelated applications
- Access to Discord Local Storage by unknown processes
- Unexpected access to cryptocurrency-wallet browser-extension data
- Suspicious clipboard access
### User behaviour
- Minecraft mods distributed outside trusted repositories
- Executables embedded inside ZIP/JAR distributions
- "Cracked" software requiring execution of unrelated Windows binaries
- Discord contacts requesting users to install modified software

# Indicators of Compromise (IOCs)
Due to the length of this report, we’ve placed all IOCs and YARA onto AlienVault’s OTX, which can be found here:
[otx.alienvault.com/pulse/6a5389a31ba8a98a8bb9e1a6](https://otx.alienvault.com/pulse/6a5389a31ba8a98a8bb9e1a6)

# Defensive Recommendations
### For Minecraft Users
- Do not execute `.exe` files supplied as part of unofficial modpacks.
- Treat a Minecraft JAR as suspicious if it unexpectedly downloads or launches external Windows executables.
- Prefer established distribution channels.
- Verify unexpected software requests through a separate communication channel.
### For Incident Responders
Where MythJS-like activity is suspected:
1. Isolate the affected endpoint.
2. Preserve volatile and filesystem evidence where possible.
3. Invalidate active sessions.
4. Reset credentials from a known-clean device.
5. Rotate tokens and API credentials.
6. Review browser-stored credentials.
7. Review cryptocurrency-wallet exposure.
8. Examine Discord account sessions and authentication activity.
9. Preserve malicious files and network telemetry for analysis.

# Conclusion
As usual, DeTraced Security heavily encourages the usage of Anti-Virus/Anti-Malware services and tools such as [VirusTotal](https://virustotal.com), [Hybrid Analysis](https://hybrid-analysis.com), and [AnyRun](https://any.run). If such tools are unavailable within your region, we heavily recommend to avoid installing any software that someone sends you online and instead attempt to find the original source via Google or your preferred search engine.



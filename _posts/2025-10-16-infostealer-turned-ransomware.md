---
title: InfoStealer Turned Ransomware
categories:
 - Research
tags:
 - blog
 - Windows
 - Ransomware
 - research
 - RAT
date: 2025-10-16
description: Just when you thought a TA wouldn’t shift TTPs…
authors: 
- tr4ceang3l
- slavetomints
researchers: 
- slavetomints
- tr4ceang3l
- likerofjazz
- akithecatearedmerc
image:
  path: /assets/img/infostealer-turned-ransomware/odisrotz-github.png
  alt: GitHub profile of the TAs
  post: false
---

## Introduction
On the 19th of August 2025, an individual –here-by referred to as “V”– requested help on an unnamed Cybersecurity-oriented Discord server, seeking assistance regarding the recovery of a ransomware-infected system. V had claimed to be searching for a supposed “fixer” for a cheat related to Fortnite’s Retrac. Upon further investigation and triaging of V’s system, we discovered the initial social engineering domain `hxxps[://]retracfix[.]vercel[.]app` and a corresponding YouTube video that directed victims to the aforementioned domain. The domain intends to serve malware under the guise of a “system fixer” and a patch for Project Retrac.

## Initial Evaluations
During the initial investigation of the campaign, researchers at DeTraced identified the campaign as being led by a group of threat actors previously associated with the WebRAT malware. We are currently tracking this group as “Betray.” Upon identifying the potential threat actors, the investigation focused on the initial malware dropper, which was extracted from the domain linked to the infection.

The dropper was heavily obfuscated using various techniques, with a primary reliance on Base64 encoding and GZip compression to conceal its contents from the victim's antivirus software. The dropper’s first action upon execution is to perform hardware checks to detect the presence of common indicators for Virtual Machine (VM) environments. If these checks are successful, the malware will terminate its execution to avoid detection in a researcher’s environment.

If the sandbox evasion is successful and the dropper determines it is running on a legitimate victim’s system, it proceeds to execute a series of system commands via PowerShell. The dropper directs itself to the directory `C:\ProgramData` and checks if the folder `IntelDriver` exists. If the folder is not present, the dropper creates it. Once this directory is in place, the dropper creates a new file called `windows.cmd` and writes its own contents into it.

Next, the dropper reads the Base64-encoded content from any line in the `windows.cmd` file that begins with `::`, and decodes this content. The decoded data is saved to a file named `boot64x.w`. After completing this step, the dropper proceeds to establish persistence on the system by writing a VBScript to a file called `%computername%_windows64x_APZOacoasfjc.vbs`. This script is configured to run the dropper’s payload every minute by creating a Scheduled Task at the path `%AppData%\IntelDriverTask.xml`.

With persistence established, the dropper continues by setting up the main payload. It again reads from `windows.cmd`, specifically extracting data from the section prefixed with `rem`. This data is copied to a file named `netstat.c`. Once `netstat.c` is successfully written, the dropper decodes the Base64-encoded content, decompresses it using Gunzip, and stores the decompressed data into a `byte[]` object. Finally, this decoded content is saved as a valid binary to the file `AarSvcw.dll`.


Now that the main payload has been created, we can take a look at how the malware really operates. For the most part, the payload can be dissected with static analysis. The primary interests of the payload are its use of XOR to encrypt the strings with the single-byte key `0x5A`; using this key, we can decrypt most of the strings in the payload. As a fallback, the payload will recreate the Scheduled Task if, at some point, the file was deleted or moved to ensure persistence, the next stage is to consistently check if a debugger has been attached to the payload to which it will attempt to scramble the memory it’s in and immediately terminate itself to deter dynamic analysis, we can neutralise this check by simply patching the related function calls with `00`s. Once the persistence check has passed, the payload will proceed to extract another set of encrypted data stored within `boot64x.w` and loads it into memory, preparing itself to then inject the secondary payload into `explorer.exe`.

The contents of the secondary payload are currently unknown to us as we continue to investigate the malware and the affiliated campaign’s supply chain.

## Supply-chain Analysis
Betray uses YouTube videos that advertise cheats and "fixer" scripts for video games, aiming to get kids and teens who are looking for cheats for video games. The videos show the user running a script in Windows Command Prompt, and then it cuts to them playing the game with the supposed benefits of the cheat. During the video, the attacker will go over the installation process and will claim that the user's antivirus software will detect it, but it is a false positive. 

![the youtube videos](/assets/img/infostealer-turned-ransomware/videos.png)

This little bit of social engineering will be good enough to work on most users and trick the victim into interacting with the video description and following the website link, which brings them to an application hosted on Vercel. Betray has two different styles of websites. One type will have a download button for users to click on, and others will include a `irm [TINYURL LINK] | iex` command for the users to run on their systems.

![](/assets/img/infostealer-turned-ransomware/download-page.png)
![](/assets/img/infostealer-turned-ransomware/retrac-irm-iex.png)

In both cases, the goal is to get the user to download and run the batch or PowerShell scripts that Betray uses as a dropper for their malware.

Betray also includes directions on their websites for users to follow, which include having users ignore warnings from their antivirus software.

![](/assets/img/infostealer-turned-ransomware/download-instructions.png)

Once the victim follows these steps, the malware is now on the user's system and will execute. But where does the malware come from?

Inspecting the network connections when the file was downloaded revealed that it came from a release from a GitHub repository, so we went and checked it out.

![](/assets/img/infostealer-turned-ransomware/odisrotz-github.png)

This is one of multiple GitHub accounts found throughout this campaign. Inspection of the repositories either turned up an empty repository with 1-2 releases or a repository full of malware. Looking into the releases answered as to where the malware came from.

![](/assets/img/infostealer-turned-ransomware/odisrotz-releases.png)

Betray typically hides their malware in the repository releases, and when a victim clicks on the download button, it would redirect their browser to a link such as `hxxps[://]github[.]com/odisdrotz71/thermia/releases/download/Thermia/ThermiaPredictor[.]exe`. Further inspection of the GitHub account and its other repositories led to the discovery of more malicious websites for different games, including Roblox, a popular game among kids, Stake Mines, a minesweeper casino game, and Rainbow 6 Siege, an FPS shooter game.

Some of those sites looked like this:

![](/assets/img/infostealer-turned-ransomware/valex-vercel-app.png)
![](/assets/img/infostealer-turned-ransomware/valexexecutor-vercel-app.png)
![](/assets/img/infostealer-turned-ransomware/thermiapredictor.png)
![](/assets/img/infostealer-turned-ransomware/r6s-recoil.png)

It is worth noting that none of the other buttons on the websites would work; they would redirect back to the top of the page.

Betray has also leveraged GitHub Gists and `hxxps[://]filedoge[.]com` for distribution and hosting of samples; however, the `filedoge[.]com`web server has been offline since August 2025, and still is at the time of this report.

## Conclusion

After their stint with hiding RATs in video game cheats, the TA expanded into the malware selling scene, attempting to sell a strain known as XWorm on hxxps[://]rce[.]lol, and a batch script obfuscator on hxxps[://]betray[.]cfd. Analysis of bitcoin addresses found to be linked with the TA reveals that they never ended up receiving any payment through cryptocurrency, but they also used PayPal and Roblox gift cards.

Some sites remain active as we work to take them down, but most have been categorized by search engines as unsafe to browse.

## Indicators of Compromise

*For the full list of IOCs and YARA rules, please check out [DeTraced-Security/detection-rules](https://github.com/DeTraced-Security/detection-rules)*

### RetracFix Sample:

```
Output DLL: AarSvcw.dll
Intermediates: windows.cmd, boot64x.w, netstat.c (used during reconstruction)

Hash – original BAT: 38aa08661729dd3c2ae3c1fb98f85f6aa4ff5e7385b0db2a65e9e85747848ad8
Hash - boot64x.w (Obfuscated): 5b1ed346d3a84543f527aa89135037d3bf56b9343b38cbeb340811da5d9a5e43 
Hash - AarSvcw.dll (Decoded): 2ce0dc292b81c72271bc9f0961271fac1e4d42b35292ce56b241174bbbeb4b46 
Hash - windows.cmd (Obfuscated): 07be8edabaa28e6d4ce30c5999b22aab53eac89a43fb036cd3cec15b63b7a81c
```

### Affiliated Samples
```
40b461edb9b2a18bc2ed8236789c1672  2fa.bat
7c92b6d50d1ab7ae24ee93d307c376f2  2faBeta.exe
bc1cfd626ef0eedcdcc46036b649c406  a.exe
780c2f5e127d12181b6650cededecd58  built-agbcfdxdfsdf.bat
161d57257ea219a030d2c902e85c5b18  CharmBootstrapper.bat
51b03d9bae4a53dd4e6210254084b806  ExecFix-2.bat
18bd43b2dfad0c247148db1afdf8462e  ExecFix.bat
220d8aa7e914dfbd52b29d25fbf5e9cd  LuckyGrid.exe
c8a8bf528e1ba3ff05ddd9368efd9f82  MinesPredictor.bat
b80538c353bd0a35e28b0b7c958a0689  r6_recoil.exe
0ee7449dd865145498ad23c43fba4754  retrac_fixer_loader.bat
da84fb352ca22ec2c94abd6f8851ea68  thermia.bat
e014911669d783a05005d48e9e6e8c2c  ThermiaPredictor-2.exe
8060fca6ac9ce3ebceba15f66db02443  ThermiaPredictor.exe
cf5005ebdc43ad19863b701025a4279b  ValexUpdater.exe
45bb4c63b0badff7721d2012b6482073  verbal.exe
fe5c839be7074513d2be80356e807fba  wcarrpt.bat
```

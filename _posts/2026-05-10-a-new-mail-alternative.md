---
title: JAMS A FOSS Alternative to Proton Mail
categories:
 - Development
tags:
 - blog
 - linux
 - mailserver
date: 2026-05-10
description: Bringing a FOSS alternative to secure mailing
authors: 
- tr4ceang3l
researchers: 
- slavetomints
- tr4ceang3l
- izzyboop
---

This post will be a relatively informal update on the current status of DeTraced, as well as an update on an upcoming project that we're excited to get public!

First off, I --Tr4ceAng3l-- would like to apologise for the absence of DeTraced within the cybersecurity community, our team (including myself) have had quite a lot going on and had to step back from CTI and malware analysis. Despite this, I myself have made a personal report on malware isolated from DeTraced and have decided to take on a project that should help better the availability of private, secure, mailing systems! This project has been dubbed as JAMS (Just Another Mail Server).

JAMS will be a DeTraced project that we'll maintain indefinitely or until we run out of resources to do so.

So what can you expect from JAMS? Well, as the title suggests, we're taking on [Proton](https://proton.me)'s concept of secure and private emailing systems but bringing it to the FOSS community with the chance for users to self-host without the risk of corporate intervention, Gag Clause orders, etc. The expected features to come are as follows:

- Email Tx/Rx + Client Access: IMAP4, SMTP, 
- Zero Access storage, 
- Email filtering, 
- DKIM/SPF/DMARC, 
- PGP/GPG signing, 
- Email Aliasing: configurable aliases:
- - Self-Terminating Addresses, 
- - Only receive from emails from domains you want
- - Automatic Email dropping (Timer based, preferable if you want to receive a confirmation link but no spam!)
- TLS: STARTLS, LetsEncrypt, etc.,
- And the normal you can expect from an email server

The above list is only a small portion of our current scope and it will expand as development continues. Expect to see additional features such as an optional SQLite database for email backups, custom WebUIs that allow us to extend the mail server's aliasing abilities, plug-n-play encryption options (encrypt emails with AES, Diffie, or your preferred asymmetric encryption), and more!

The project can be found on our GitHub: https://github.com/DeTraced-Security/JAMS where you can put forth feature requests, audit the code yourself, assist in documentation, and once the base of the project is ready: contribute your own PRs (subject to approval).

I hope your year goes well, and systems remain secure.
Tr4ceAng3l

> Want to keep up with the DeTraced team? Come join our Discord [here!](https://discord.gg/ahecAvxwhh)
{: .prompt-info }

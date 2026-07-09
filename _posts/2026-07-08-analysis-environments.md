
# Introduction
When we encounter malware, the most important thing to remember is to setup a proper analysis environment. This ensures that our main system (“host”) remains secure from the malicious content, but there’s one downside from this: malware already predict that we’ll be analysing it! So we need to setup a specialised environment that obfuscates our Virtual Machine (“VM”) to look like it’s running on a physical device, and we’ll show you exactly how to do that!

Throughout this guide, we’ll demonstrate some efficient tactics that you can use during an engagement to trick majority of malware into thinking we’re running it on the host!

## Contents:
- [Setting Up The Environment](#setting-up-the-environment)
- [Step 1: Creating Our VM](#step-1-creating-our-vm)
- [Step 2: Patching the BIOS](#step-2-patching-the-bios)
- [Step 3: Hardening the VMX](#step-3-hardening-the-vmx)
- [Next Steps?](#next-steps)

---

# Setting Up The Environment
For this guide, we’ll be relying on a Windows 10 ISO, which can be obtained from Microsoft, and VMware Workstation. The benefits of using VMw is that we have greater control over the VM via editable Virtual BIOS files and VMX (the VM’s configuration file) files to finetune our environment more effectively.

The reason for using Windows 10 instead of Windows 11, is that later on we will be using FlareVM as our foundation for tooling – and that Windows 10 allows us to use BIOS mode without Secure Boot!

# Step 1: Creating Our VM
From here, we’ll assume you have Windows 10’s ISO already downloaded from an official source. When we create our VM, we’re going to use `Custom (advanced)` so we can tell VMware exactly what kind of settings we want to change before the VM is created so we have less changes to the VMX file or within the VM itself.

>**Before Finishing Setup:** DO NOT install the VMware Guest Tools at any point! They leave driver signatures that malware uses as a quick bailout signal. Avoid them throughout the analysis workflow and between engagements.
{: .prompt-warning }

![](/assets/img/analysis-envs/vmware-new-vm.png)

### BIOS Type
When you’re prompted to, select the `BIOS` type, not UEFI/Secure Boot. This is required for the patched BIOS (described later on) to load correctly and avoid collisions with Secure Boot due to a lack of signing, or any internal security protocols in Windows that may prevent a custom BIOS from working.

![](/assets/img/analysis-envs/firmware.png)

### Processor/CPU Allocation
When you’re prompted to, set the `Processors` to match your *physical* CPU count (if you have one CPU, leave it at one “1”) and set the `Cores` to *half* of your available cores. For example, if you have 12 cores, you’ll allocate 6 to the VM.

![](/assets/img/analysis-envs/processor-settings.png)

### Memory Allocation
When allocating RAM to the VM, you’ll need to allocate at least 8GB for any OS that has a Desktop Environment (A graphical user interface). If your host has only 8GB of memory, allocate 4GB but it’s heavily suggested to consider upgrading your computer’s memory – if possible.

>The less RAM you give a VM means it’ll generally perform poorly and won’t be able to execute the full suite of tools you may need during the investigation
{: .prompt-info }

![](/assets/img/analysis-envs/memory.png)

### Disk/Storage Allocation
You can use the default allocation settings when creating a new virtual disk, but we generally recommend setting it to at least 120GB if you have enough storage on your host to do so.

### MAC Address Allocation
To access this panel, you can safely confirm your VM setup phase if you haven’t already, and navigate to `Customise Hardware -> Network Adapter -> Advanced` and navigate to the bottom of the `Network Adapter Advanced Settings`. Because VMware uses predefined MAC prefixes as a way to easily identify VMs on a LAN, we’re going to need to change the MAC to something completely random and avoid the following MAC addresses:
```
00:05:69
00:50:56
00:1C:14
00:0C:29
```

*Hardware Settings:*
![](/assets/img/analysis-envs/hardware-settings.png)

*Advanced Network Adapter Settings:*

![](/assets/img/analysis-envs/adapter-settings.png)

Once you’ve changed the MAC Address, you can save the new address with “OK” and Close the hardware page. 

# Step 2: Patching The BIOS
One of the most crucial parts of VM detections in malware is the ability to run `__syscall` and `__cpuid` calls to identify various signals from the environment that may indicate if it’s virtualised or running on the host device. To defeat this, we need to clone and patch VMware’s default BIOS to change a few strings, names: `QEMU`, `VMware`, and `VirtualBox` if they exist. A pre-patched BIOS ROM will be provided at the end of the page, or you can join our discord and ask Tr4ceAng3l for the BIOS if there’s issues downloading from our site! If you’re interested in patching the VMware BIOS, I recommend reading through [**William Lam’s blog: Customizing SMBIOS strings (hardware manufacturer and vendor) for Nested ESXi**](https://williamlam.com/2024/05/customizing-smbios-strings-hardware-manufacturer-and-vendor-for-nested-esxi.html).

To ensure our VM uses the correct BIOS ROM (our patched BIOS ROM), we’ll need to open up the VMX file (feel free to use your preferred text editor) and append the following and save:
```
bios440.filename = "C:\path\to\BIOS.440.PATCHED.ROM"
```

# Step 3: Hardening The VMX
With the patched BIOS in place, we’ll need to start working on some hardening procedures that will minimise the surface of information that a malware can use to signal that it’s an analysis environment. To do this, we’ll first start of with disabling Hypervisor CPUID instructions, some configurations that VMware uses to backdoor I/O and side channels, and some reporting tools.

### Disable CPUID Hypervisor Bit
Prevents the VM from advertising the Hypervisor presence via the CPUID instruction:
```
hypervisor.cpuid.v0 = "FALSE"
```

### Disable Timing And Backdoor Channels
These flags harden the VM against timing-based side-channel attacks and blocks the VMware I/O backdoor port. Please note that timing attacks are still possible, and cannot be prevented completely, this is just best practice to reduce the surface of information the malware can use.
```
monitor_control.restrict_backdoor    = "TRUE"
monitor_control.disable_directexec  = "TRUE"
monitor_control.disable_chksimd     = "TRUE"
monitor_control.disable_selfmod     = "TRUE"
monitor_control.disable_ntreloc     = "TRUE"
monitor_control.disable_reloc       = "TRUE"
monitor_control.disable_btmemspace  = "TRUE"
monitor_control.disable_btpriv      = "TRUE"
monitor_control.disable_btinout     = "TRUE"
monitor_control.disable_btseg       = "TRUE"
```

### Disable VMware Tools Version Reporting
This disables whatever telemetry VMware uses to report to it’s tooling (vSphere, Workstation, Guest Tools, etc.) about whatever version VMware Workstation is running as, or what VMware Version the box was made with.
```
isolation.tools.getVersion.disable = "TRUE" isolation.tools.setVersion.disable = "TRUE" isolation.tools.getPtrLocation.disable = "TRUE" isolation.tools.setPtrLocation.disable = "TRUE"
```

### Enable SMBIOS Host Reflection
This prevents VMware from overwriting parts of the patched BIOS ROM with it’s own SMBIOS data that could undo our work to prevent VM signals:
```
smbios.reflectHost = "TRUE"
```


# Next Steps?
From here, I would absolutely recommend following [FlareVM’s](https://github.com/mandiant/flare-vm) instructions on setting up an analysis VM and hardening Windows 10, they share amazing resources on how to do it! For bonus security points, I would also recommend following the Australian Signals Directorate’s [Internet Security Manual (ISM)](https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/hardening-microsoft-windows-11-workstations) for Hardening Windows 10/11 Workstations.


> Want to keep up with the DeTraced team? Come join our Discord [here!](https://discord.gg/ahecAvxwhh)
{: .prompt-info }

# Nutanix Guest VM Tools
API based Powershell for in-guest tools.
Please note, this is not official Nutanix software, use at your own risk.

**Requirements**
- Windows Machine with PowerShell 5
- Prism Central Credentials
- AOS 5.16 or above for Secure Boot.
- PC / AOS on 5.9 or above for API V3

**Capabilties**
- **Report** Reports the VM Details, on which host its running and host performance.
- **Add-Ram** Only adding Memory is supported regardless of power state.
- **Add-Disk** Adds a disk to the local or targeted VM.
- **Extend-Disk** Extends a disk to the local or targeted VM.
- **Enable-SecureBoot** Remote Targets only, Poweroff required.
- **Snapshot-Create** Creates a snapshot of the local or targeted VM
- **Set-VM-Description** Sets the VM Description of the local or targeted VM
- **Mount-ISO** Mounts an ISO from the PE image store on which the VM is hosted.
- **Mount-NGT** Mounts an NGT of the local or targeted VM

- **How to use** There are 2 methods to run:
	1. **Executeable** Use the compiled exe from this github repo, copy and click.
	2. **Run GuestVMTools.ps1** Please make sure the pwd is changed to the repo before you launch


# Detailed Info #

**Report**

![VM Report](./Artifacts/GuestVMTools-Report.gif)

**Writing config:**

![Create Config Demo](ps1.gif)

**Using Scan mode:**

![Scan Demo](ps2.gif)

**Using Execute mode:**

![Execute Demo](ps3.gif)

**End result**

![Email](Email1.png)

# Nutanix Guest VM Tools
API based Powershell for in-guest tools.
Compiled as a single executable for 1-click Experience.
Please note, this is not official Nutanix software, use at your own risk.

**Requirements**
- Windows Machine with PowerShell 5
- Prism Central Credentials, Local or Directory Based, no SSH access required.
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

Gets the PE host that this VM belongs too, this only works if the VM is powered on! Using host & VM info it builds a response table.

"HostCPU_Usage","VMGPUs","HostAHV_Ver","VMUEFI","VMCDrom","VMName","HostModel","HostStatus","VMSecureboot","VMDisks","HostPower","HostCores","HostDays_UP","HostRAM","HostRAM_Usage","Hostname"
"23","False","Nutanix 20190916.158","False","0","Windows-MGT-01","NX-MM3000","NORMAL","False","6","kConnected","8","184","128","38","mm-ahv-pribk-01"


![VM Report](./Artifacts/GuestVMTools-Report.gif)

**Writing config:**

![Create Config Demo](ps1.gif)

**Using Scan mode:**

![Scan Demo](ps2.gif)

**Using Execute mode:**

![Execute Demo](ps3.gif)

**End result**

![Email](Email1.png)
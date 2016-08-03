# WinRM_CertMgmt
A framework to streamline Certificates used for WinRM

Fully secured PowerShell has been the unattainable unicorn for many since the dawn of time.  But no longer!

##Why this is needed
Microsoft doesn't provide a GPO or other mechanism to automatically configure WinRM over HTTPs.  Most turn to scripting to enable these listeners.  

However, once the HTTPS listener is enabled, WinRM never checks again to see if the cert is still valid, and certs expire.  

So, if you're able to provision WinRM over HTTPs throughout your environment, you'll then be challenged to develop your own mechanism to handle updating certs too.  Not fun.

##How we solve these problems
This single script handles all of these problems. Here's how we handle each of these scenarios

*Don't HTTPs configured today*?  We'll check for a cert and if we find one, we'll configure the listeners and throw an `exit code 0`.

*Already have everything configured perfectly*? We throw an `exit code 0`.

*You don't have a cert available for HTTPs*? We'll throw an `exit code 1` which you can catch using SCCM or LanDesk to remediate.

*Have HTTPs but it's using an old cert*? We'll resolve the records for the new longest available cert and will update your machines HTTPs listener.


###Prerequisites

* A working PKI environment with a Server Authentication certifiacte template available to your target workstations
* An autoenrollment GPO assigned to this group of target workstations

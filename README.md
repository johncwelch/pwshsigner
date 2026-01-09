# pwshsigner
This is a PowerShell module to help facilitate signing PowerShell scripts on both Windows and macOS. Given the increase in use of SmartScreen and similar on Windows, and script signing being just a good idea in general (as well as a default requirement on Windows) this module is here to hopefully make that easier.  
  
## Basics  
As implied, this module is targeted at signing PowerShell scripts on macOS and Windows. Not cmd scripts, not shell scripts, not AppleScripts, python, etc. Those are all handled differently. This is really targeted at PowerShell.  
  
## Requirements
Currently, on Windows, you need a code signing cert in your local certificate store. That's the user store, not the machine store. On macOS, you need the OpenAuthenticode module, https://www.powershellgallery.com/packages/OpenAuthenticode/0.6.3. On Windows, this should work equally well with PowerShell 5.1 and the current 7.X branch.  
  
## Platform Differences  
There's not many. On Windows, you can also use this to sign executables. The Windows functionality uses the user cert store, not individual cert files, the macOS version only uses an individual cert (.p12) file.  
  
## Security  
On Windows, this uses the thumbprint of the cert in the cert store to generate the cert object passed to Set-AuthenticodeSignature, so there's no worry about storing passwords/passphrases. On macOS, since we (currently) can't generate the cert object directly from the Keychain, there has to be a physical .p12 cert file and a password/passphrase. The script stores that in the user's keychain, and retrieves it as necessary. I try to make sure that data exists in memory/variables for as little time as possible. But this way, you're not hoping my home-grown "security" works.  
  
## Limitations  
Windows: No cert files used, requires a code-signing cert in the user cert store  
macOS: requires a code-signing cert file, requires the Open-Authenticode module.  
  
## Future plans  
Windows: allow to also use cert files (if I can get this to work safely without rolling my own nonsense on PowerShell 5.1.)  
Both: allow passing an array of paths to the command rather than just a single path as a string

## More detailed help  
Each function has a help system so:  
Get-Help Set-MacPowerShellSig  
Get-Help Set-WinPowerShellSig  

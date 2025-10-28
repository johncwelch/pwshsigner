##windows functions
function getCertThumbprint {
	#get every user cert for current user
	$myCerts = Get-ChildItem -Path Cert:CurrentUser\My

	#create a list of objects we'll use to collect signing certs (and test for none)
	$mySigningCerts = [System.Collections.Generic.List[psobject]]::New()

	#get the code signing certs
	foreach ($item in $myCerts) {
		#we just use the enchancedKeyUsageList. all signing certs have this (at least for now)
		$enhancedKeyUsageList = $item | Select-Object -ExpandProperty EnhancedKeyUsageList

		#if it has the right friendly name, add it to $mySigningCerts
		if ($enhancedKeyUsageList.FriendlyName -eq "Code Signing") {
			$mySigningCerts.Add($item)
		}
	}

	if ($mySigningCerts.Count -lt 1) {
		#no signing certs
		return "nocerts"
	} else {
		foreach ($item in $mySigningCerts) {
			$thumbprint = $item.Thumbprint
			$issuer = $item.Issuer
			$friendlyName = $item.FriendlyName
			$intendedPurpose = $enhancedKeyUsageList.FriendlyName
			Write-Output "Signing cert found`n`nFriendly Name: $friendlyName`nIssuer: $issuer`nThumbprint: $thumbprint`nIntended Purpose: $intendedPurpose`n`n"
		}
	}
}



##macOS functions
function enterCertPassword {
	param (
		[Parameter(Mandatory = $true)][string] $userName
	)

	## this takes a username param and returns an error code of true if everything worked or false if it didn't
	## it exists to enter the password for the cert into the keychain as the user running the script
	## it also writes the hasCertPassword key to the prefs for this script

	#check for existing password, exit cleanly if it exists

	$certPassExists = security find-generic-password -a "$userName" -w -s "pwshsigner"

	if ([String]::IsNullOrEmpty($certPassExists)) {
		#no keychain entry exists, create it
		#yes I know, mask is not secure, however, converting from secure in pwsh on macOS kind of sucks. And it's a code signing cert
		#if you're using "real" passwords for this...
		$thePassword = Read-Host "Couldn't find the keychain entry for the certificate password`nEnter the password for the cert you'll be using to sign scripts with" -MaskInput

		# add the cert password to the keychain
		security add-generic-password -U -a "$userName" -s "pwshsigner" -w "$thePassword"

		# add the key to our prefs
		defaults write com.bynkii.pwshsigner hasCertPassword -bool TRUE

		#clear $thePassword so the password doesn't easily exist anymore
		$thePassword = ""

	} else {
		#keychain entry exists, ask if the user wants to update. if not, exit clean after setting preference
		#correctly since that key missing is the main way people get here
		defaults write com.bynkii.pwshsigner hasCertPassword -bool TRUE
	}
}

function getMultipleFilesMac {
	#always returns a string
	$theFiles = "choose file of type {`"ps1`",`"psd1`",`"psm1`",`"ps1xml`"} with multiple selections allowed"|/usr/bin/osascript -so
	if ($theFiles -contains "execution error: User canceled. (-128)") {
		$theErrorMessage = $theFiles.Split(":")[-1].Trim()
		$theErrorTitle = "Choose file canceled"
		displayInfoDialog -dialogText $theErrorMessage -dialogTitle $theErrorTitle
		return "cancelled"
	} else {
		#no errors returned, we have to scrub the "alias " from the front of the path and check for commas. 
		#Always convert this to a list of string so the signing is easier.
		#the list conversion should be a function
	}
}

#this converts the string we get from choose file to an array of one or more elements
function stringToListConversion {
	param (
		[Parameter(Mandatory = $true)][string] $filePathString
	)

	#check for how many times "alias " appears in the return. If one, then it's a single file

	#create an empty list of strings
	$thePathCollection = [System.Collections.Generic.List[string]]::New()
	
	#run split on ", alias ", this converts it to an array of strings. The first item [0] always stars with "alias "
	#which is manageable. also removes a lot of leading spaces, but we'll trim those anyway
	$filePathArray = $filePathString.Split(", alias ")

	#now we get rid of the extraneous stuff
	foreach ($item in $filePathArray) {
		if ($item.StartsWith("alias ")) {
			#if it starts with "alias ", we yank that, and trim leading/trailing whitespace
			#then put it in our string collection
			$item = $item.Substring(6)
			$item = $item.Trim()
			$thePathCollection.Add($item)|Out-Null
		} else {
			$item = $item.Trim()
			$thePathCollection.Add($item)|Out-Null
		}
	}

	#return our string collection
	return $thePathCollection
}

#converts macOS alias path to POSIX path, which is what's needed to sign the file
function aliasToPosixPath {
	param (
		#we're passing a list of strings, but treating it like an array until
		[Parameter(Mandatory = $true)][string[]] $filePathArray
	)

	#create our list of strings to hold the posixified paths
	$thePosixPaths = [System.Collections.Generic.List[string]]::New()

	#iterate through the array and posix up the paths
	foreach ($item in $filePathArray) {
		#build the osascript command
		$thePosixCommand = "get POSIX path of `"$item`""

		#convert the alias to a POSIX path
		$item = $thePosixCommand|/usr/bin/osascript -so

		#shove that into the list
		$thePosixPaths.Add($item)|Out-Null
	}

	#return the list
	return $thePosixPaths
}

#displayDialog() takes some dialog text and a title as parameters, displays the dialog and returns no value.
function displayInfoDialog {
	#parameters for the dialog (error, info, whatevs)
	param (
		[Parameter(Mandatory = $true)][string] $dialogText,
		[Parameter(Mandatory = $true)][string] $dialogTitle
	)
	
	#dd command
	"display dialog `"$dialogText`" with title `"$dialogTitle`""|/usr/bin/osascript -so
}

function getCertFilePath {
	$certFilePath = Read-Host "Enter the path to the signing certificate .p12 file. If there are spaces`nor special characters, you can escape them, but really`nthat is a silly idea for this kind of path"
	defaults write com.bynkii.pwshsigner certFilePath -string $certFilePath
	return $certFilePath
}

function Set-WinPowerShellSig {
	<#
	.SYNOPSIS
	This module makes signing PowerShell scripts on Windows and macOS easier, this help is for the windows functionality

	.DESCRIPTION
	Given the increased demand to sign PowerShell scripts, this module facilitates that. NOTE: YOU HAVE TO ALREADY HAVE A SIGNING CERT IN YOUR PERSONAL CERT STORAGE FOR THIS MODULE TO WORK! At the moment, this ONLY works with certs in your store (mmc.exe, add in the certificates snap-in.) A future update may allow for cert files if I can get secret storage working robustly and safely. Windows' lack of a keychain-like concept makes this harder than it should be.

	The module can be run with no parameters, in which case you get a file selection dialog that lets you choose one or more powershell (.ps1, .psm1, .psd1, .ps1xml) files to be signed. You can also pass it the path (in double-quotes) to a single PowerShell file and it will sign that. Note that if you pass the module a path as a parameter, it is not checking to make sure you passed it a powershell file. It will try to sign any file you pass it. Be careful.

	The parameter is -scriptPath, string, optional

	If you've never run the module before, it will search for all the code signing scripts in your personal (not machine) certificate store, then ask you to enter the thumbprint for the cert to use. That thumbprint is stored in a json file in AppData\Roaming in your home directory and used from then on. If you want or need to, you can changed the thumbprint in that file manually in any text editor. On all subsequent runs, the module will use that thumbprint.

	If you have no signing certs in your personal certificate store, the module will fuss at you and tell you to exit.

	The module has no specific outputs other than error outputs and a signed powershell script. It does display the standard signing outputs from Set-AuthenticodeSignature, the actual signing step, both success and failure messages.

	Since this script uses the user context to find certificates, if you run this with an admin account, it may not find certs for your non-admin account store. Be careful

	.PARAMETER scriptPath
	Optional string parameter that should be the path to a PowerShell file in double quotes. If -scriptPath is used, it will sign that file with no feedback.

	.EXAMPLE
	Running with no parameters:
	     Set-WinPowerShellSig

	Passing the path to a file:
	     Set-WinPowerShellSig -scriptPath "C:\Users\myUserName\Desktop\somescript.ps1"

	.NOTES
	If you're using this module it's assumed you know your way around PowerShell and script signing at least at a conceptual level.
	#>

	param (
		[Parameter(Mandatory = $false)][string] $scriptPath = ""
	)

	#test for windows
	#this version works with PS 5.1
	if (-Not ($env:OS -eq "Windows_NT")) {
		Write-Output "This function only runs on Windows, exiting"
		Return
	}

	#framework to use a file browser
	Add-Type -AssemblyName System.Windows.Forms

	##globals
	$theThumbPrint = ""
	$storedThumbPrint = ""

	##Test to see if we already have this stored. If we do, use that thumbprint to sign
	##if not, create the settings file with the desired thumbprint
	##This checks for the settings file being there

	if (!(Test-Path $env:APPDATA\pwshsigner.json)) {
		#there's no settings file
		##run GetCertThumbprint to show the available certs
		$hasCerts = getCertThumbprint
		if ($hasCerts -eq 'nocerts') {
			#no signing certs found
			Write-Output "You have no signing certs in the local cert store.`nPlease get a signing cert before running this command"
			return
		}

		#we have to put this here, because otherwise read-host blanks the resulst from getCertThumbprint
		#read-host is often dumb
		$theThumbPrint = Read-Host "Enter the thumbprint of the cert you want to use`nNOTE: this wil be written into the settings for this module, so choose correctly!"
		if([string]::IsNullOrEmpty($theThumbPrint)) {
			#if the thumbprint is empty, no sense in continuing
			Write-Output "Thumbprint is null or empty, exiting."
			return
		} else {
			#create the setting json file in user's appdata folder
			$settings = @{"Thumbprint" = "$theThumbPrint"}
			$theJsonSettings = $settings|ConvertTo-Json
			Write-Output "Creating JSON settings file with this thumbprint in $env:APPDATA\pwshsigner.json"
			Out-File -FilePath $env:APPDATA\pwshsigner.json -InputObject $theJsonSettings

			#so we don't have to read a file to get a value we already have
			$storedThumbPrint = $theThumbPrint
		}
	} else {
		#read the settings file contents
		$pwshSignerRaw = Get-Content $env:APPDATA\pwshsigner.json

		#convert that array to a string
		$pwshSignerString = $pwshSignerRaw | Out-String

		#read the actual JSON data in the string
		$pwshSignerJsonSettings = ConvertFrom-Json $pwshSignerString

		#grab the thumbprint value
		$storedThumbPrint = $pwshSignerJsonSettings.Thumbprint
	}

	#get the signing cert from the local store as a certificate object by thumbprint
	$theCert = Get-ChildItem -Path Cert:CurrentUser\My\$storedThumbPrint

	#Since the script can be passed a filepath, check for that. If not there, pop the filepicker
	if ([string]::IsNullOrEmpty($scriptPath)) {
		#no path, pop the dialog

		#create the file browser object, for only powershell files and executables
		$fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
			RestoreDirectory = $true

			#filetype filter
			Filter = "PowerShell Files (*.ps1;*.psm1;*.psd1;*.ps1xml)|*.ps1;*.psm1;*.psd1;*.ps1xml;|Executables(*.exe)|*.exe;"
			MultiSelect = $true
		}

		#display the filebrowser
		$null = $fileBrowser.ShowDialog()

		#set the filepath(s) to a var. Using .filenames returns an array, so return type is consistent, easier that way
		$filesToSign = $fileBrowser.filenames

		#check for cancel. If count of $filesToSign is 0, cancel was hit
		if ($filesToSign.Length -lt 1) {
			Return
		} else {
			foreach ($item in $filesToSign) {
				Set-AuthenticodeSignature -FilePath $item -Certificate $theCert
			}
		}
	} else {
		#path was passed to module func
		Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $theCert
	}
}

function Set-MacPowerShellSig {
	<#
	.SYNOPSIS
	This module makes signing PowerShell scripts on Windows and macOS easier, this help is for the macOS functionality

	.DESCRIPTION
	Given the increased demand to sign PowerShell scripts, this module facilitates that. The only real prequisites are that you have a cert file, preferably a .p12 file and the password for it, along with the OpenAuthenticode module, which is required for core functionality. On first run, you'll be asked for the path to the cert and the password/passphrase for the cert. The path will be stored in ~/Library/Preferences/com.bynkii.pwshsigner.plist. The password/passphrase will be stored in your keychain via /usr/bin/security, so it's not just existing as plain text. Obviously at certain points in the code, it exists as plain text, but the module tries to minimize that as much as possible.

	The module can be run with no parameters, in which case you'll be asked to enter the path to the powershell (.ps1, .psm1, .psd1, .ps1xml) files to be signed. You can also pass it the path (in double-quotes) to a single PowerShell file and it will sign that. Note that if you pass the module a path as a parameter, it is not checking to make sure you passed it a powershell file. It will try to sign any file you pass it. Be careful. A future update will tie into Display Dialog so you can more easily pick multiple files. Currently it's one file per run, which is tedious, but for now, it shouldn't be a huge problem. I mean, it's not like you can't set up an array of paths and then feed them to the module one at a time or anything ;-)

	The parameter is -scriptPath, string, optional

	The module has no specific outputs other than error outputs and a signed powershell script.

	.PARAMETER scriptPath
	Optional string parameter that should be the path to a PowerShell file in double quotes. If -scriptPath is used, it will sign that file with no feedback.

	.EXAMPLE
	Running with no parameters:
	     Set-MacPowerShellSig

	Passing the path to a file:
	     Set-MacPowerShellSig -scriptPath "C:\Users\myUserName\Desktop\somescript.ps1"

	.NOTES
	If you're using this module it's assumed you know your way around PowerShell and script signing at least at a conceptual level.
	#>

	param (
		[Parameter(Mandatory = $false)][string] $scriptPath = ""
	)

	#globals
	$theUser = whoami
	$theCertPassword = ""

	###requirements checks

	##test for macOS
	if (-Not $IsMacOS) {
		Write-Output "This function only runs on macOS, exiting"
		Return
	}

	##check for the module. If it's not there, tell the user and exit
	if (!(Get-Module -ListAvailable -Name "OpenAuthenticode")) {
		Write-Output "The OpenAuthenticode Module was not found on your machine. This is required for this module to work."
		Write-Output "To install, from your PowerShell window, run: Install-Module -Name OpenAuthenticode -Scope <CurrentUser\AllUsers"
		Write-Output "If you want to install for AllUsers scope, the command has to be run as root"
		Write-Output "Exiting"
		Return
	}


	#check for our preferences file
	if (!(Test-Path -Path "\Users\$theUser\Library\Preferences\com.bynkii.pwshsigner.plist")) {
		#file doesn't exist, create it with donothing key
		defaults write com.bynkii.pwshsigner donothing ""
	} else {
		#it exists, let the script know it exists
	}

	#check for cert password via prefs. If the return is null or empty, there's no password, create one
	#we don't return the password to this, because we want it existing for as little time as possible
	$certPasswordExists = defaults read com.bynkii.pwshsigner hasCertPassword
	if ([String]::IsNullOrEmpty($certPasswordExists)) {
		enterCertPassword -userName $theUser
	}

	#okay, we have our cert password set up, now do we have the path to the cert itself.
	#yes I know we can do this directly with test-path, but using proper defaults is good
	#here we return the path because that's not sensitive info
	$theCertFilePath = defaults read com.bynkii.pwshsigner certFilePath
	if ([String]::IsNullOrEmpty($theCertFilePath)) {
		$theCertFilePath = getCertFilePath
	}

	##we now have the cert file path set up, now to create our cert entry

	#get the cert password
	$theCertPassword = security find-generic-password -a "$theUser" -w -s "pwshsigner"

	#if $theCertPassword is null or empty, we want to call enterCertPassword again to create it
	if ([String]::IsNullOrEmpty($theCertPassword)) {
		enterCertPassword -userName $theUser
		#now get the password
		$theCertPassword = security find-generic-password -a "$theUser" -w -s "pwshsigner"
	}

	#create the certificate
	$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$theCertFilePath","$theCertPassword")

	#clear the cert password var
	$theCertPassword = ""

	#just in case, but if this is null at this point, something is really wrong
	if ([String]::IsNullOrEmpty($cert)) {
		Write-Output "something is terribly wrong, we can't get the cert info. Double check the cert password or the cert .p12 file path/file"
		Return
	}

	#so now we have our cert object, let's sign the script file. Get the path to the script
	#at some point, we may think about adding a choose file option here, but for now, this will work.
	#setup now allows for passing the path to the command.
	if ([string]::IsNullOrEmpty($scriptPath)) {
		#path param wasn't used
		$scriptPath = Read-Host "Enter the path to the script we want to sign. If there are spaces`nor special characters, you can escape them, but really`nthat is a silly idea for this kind of path"
	}

	#now sign the script
	Set-OpenAuthenticodeSignature -Path $scriptPath -Certificate $cert

	#and done. We don't return anything because if there's an error here, set-openauthenticode will flash it for us
	#and if there's not an error, we don't care
	Return
}

Export-ModuleMember -Function Set-MacPowerShellSig
Export-ModuleMember -Function Set-WinPowerShellSig


# SIG # Begin signature block
# MIIMgQYJKoZIhvcNAQcCoIIMcjCCDG4CAQMxDTALBglghkgBZQMEAgEwewYKKwYB
# BAGCNwIBBKBtBGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC1WLTWtxOPyJsk
# YU9L0O1LHFNKXaEdG12iL56E3WeWv6CCCawwggQEMIIC7KADAgECAggYeqmowpYh
# DDANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUg
# SW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAU
# BgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMTIwMjAxMjIxMjE1WhcNMjcwMjAxMjIx
# MjE1WjB5MS0wKwYDVQQDDCREZXZlbG9wZXIgSUQgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMw
# EQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAIl2TwZbmkHupSMrAqNf13M/wDWwi4QKPwYkf6eVP+tP
# DpOvtA7QyD7lbRizH+iJR7/XCQjk/1aYKRXnlJ25NaMKzbTA4eJg9MrsKXhFaWlg
# a1+KkvyeI+Y6wiKzMU8cuvK2NFlC7rCpAgMYkQS2s3guMx+ARQ1Fb7sOWlt/OufY
# CNcLDjJt+4Y25GyrxBGKcIQmqp9E0fG4xnuUF5tI9wtYFrojxZ8VOX7KXcMyXw/g
# Un9A6r6sCGSVW8kanOWAyh9qRBxsPsSwJh8d7HuvXqBqPUepWBIxPyB2KG0dHLDC
# ThFpJovL1tARgslOD/FWdNDZCEtmeKKrrKfi0kyHWckCAwEAAaOBpjCBozAdBgNV
# HQ4EFgQUVxftos/cfJihEOD8voctLPLjF1QwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBQr0GlHlHYJ/vRrjS5ApvdHTX8IXjAuBgNVHR8EJzAlMCOgIaAfhh1o
# dHRwOi8vY3JsLmFwcGxlLmNvbS9yb290LmNybDAOBgNVHQ8BAf8EBAMCAYYwEAYK
# KoZIhvdjZAYCBgQCBQAwDQYJKoZIhvcNAQELBQADggEBAEI5dGuh3MakjzcqjLMd
# CkS8lSx/vFm4rGH7B5CSMrnUvzvBUDlqRHSi7FsfcOWq3UtsHCNxLV/RxZO+7puK
# cGWCnRbjGhAXiS2ozf0MeFhJDCh/M+4Aehu0dqy2tbtP36gbncgZl0oLVmcvwj62
# s8SDOvB3bXTELiNR7pqlA29g9KVIpwbCu1riHx9GRX7kl/UnELcgInJvctrGUHXF
# PSWPXaMA6Z82jEg5j7M76pCALpWaYPR4zvQOClM+ovpP2B6uhJWNMrxWTYnpeBjg
# rJpCunpGG4Siic4U6IjRWIv2rlbELAUqRa8L2UupAg80rIjHYVWJRMkncwfuguVO
# 9XAwggWgMIIEiKADAgECAgg4/t1QcpKr9DANBgkqhkiG9w0BAQsFADB5MS0wKwYD
# VQQDDCREZXZlbG9wZXIgSUQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxJjAkBgNV
# BAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBs
# ZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yNTA1MjAxNzI2MzZaFw0yNzAyMDEyMjEy
# MTVaMIGPMRowGAYKCZImiZPyLGQBAQwKNzk2NDg4Vkc5NTE6MDgGA1UEAwwxRGV2
# ZWxvcGVyIElEIEFwcGxpY2F0aW9uOiBKb2huIFdlbGNoICg3OTY0ODhWRzk1KTET
# MBEGA1UECwwKNzk2NDg4Vkc5NTETMBEGA1UECgwKSm9obiBXZWxjaDELMAkGA1UE
# BhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDG5iTyi/Llb8QR
# mKSVEMaSkIAyXssehEKC1nJKp9ZkaRLxan/q6B7JeWzTNa6XCBG3Pf4Dz0IQnU6U
# qDsPFYpwhRtS14CNVnwmcMJeJ/hy6MW++cBymq9xEZD80c69muLZmYr2KLKFu6WJ
# nPK4JvYNqZ5Iug7UthcVeZBTdCDHCsVui8WMrFwDe112hqHFb9YiwrZF3w4v3G7X
# cU6KO6oiD79C26xelHqAjuPZUxHbiJDhrgI2xbr4phtyukq/aaUyvOEGRuzr9ViT
# imxjMH0Dzd3eYQNyZ/OgpBTg/u5bt4c4L+ivLNWpkImm5NLByjPWj2Rgxex9q7gu
# d8eXX5PBAgMBAAGjggITMIICDzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFFcX
# 7aLP3HyYoRDg/L6HLSzy4xdUMEAGCCsGAQUFBwEBBDQwMjAwBggrBgEFBQcwAYYk
# aHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1kZXZpZDA2MIIBHQYDVR0gBIIB
# FDCCARAwggEMBgkqhkiG92NkBQEwgf4wgcMGCCsGAQUFBwICMIG2DIGzUmVsaWFu
# Y2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNzdW1lcyBhY2Nl
# cHRhbmNlIG9mIHRoZSB0aGVuIGFwcGxpY2FibGUgc3RhbmRhcmQgdGVybXMgYW5k
# IGNvbmRpdGlvbnMgb2YgdXNlLCBjZXJ0aWZpY2F0ZSBwb2xpY3kgYW5kIGNlcnRp
# ZmljYXRpb24gcHJhY3RpY2Ugc3RhdGVtZW50cy4wNgYIKwYBBQUHAgEWKmh0dHA6
# Ly93d3cuYXBwbGUuY29tL2NlcnRpZmljYXRlYXV0aG9yaXR5LzAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU+vpKLJ3aUHMJjwgzoV2hMj3fKX8wDgYD
# VR0PAQH/BAQDAgeAMB8GCiqGSIb3Y2QGASEEEQwPMjAxOTAyMDYwMDAwMDBaMBMG
# CiqGSIb3Y2QGAQ0BAf8EAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQAV1Oma8FyEr7uz
# iO/jzM9Zv+vfk6USv3P/G444JO51tYK9pfyOBIw1bAQriiW4AmUbgYsOTPBRDaSn
# MuZBi/srL1G+mXngoiqaP4sdt3MgCt/mJTmz/PBxVZgLk8XKxZR8C6GBKX9vVSTR
# oAbwake9HBhJe4RnNoELGuXk62b1QKnkKDKUizZtuAib13yDSr5bN0KxezeGmySg
# t1maDJ+qCYpQUMB3Nls7taCozh4lsl7xtvc/2A8l2Nf9pcT0GGpkZdpf1WwUqm6O
# 3fUQ7+GCO2ctz8CfUchecgcBDMP40oTKDsW7d8oLP5LU8YK8lgoAzUeHA5JMscLU
# Ud176XtfMYICKzCCAicCAQEwgYUweTEtMCsGA1UEAwwkRGV2ZWxvcGVyIElEIENl
# cnRpZmljYXRpb24gQXV0aG9yaXR5MSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0
# aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMC
# CDj+3VBykqv0MAsGCWCGSAFlAwQCAaB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCAClulBRVJ9gUsGkgq0W9prmB4pjsw2QDQ+Js2R
# A72VWzALBgkqhkiG9w0BAQEEggEAdW0rGgZCkuXA5GPKIPLw8jJfZGH+wJ/TdWVi
# tLNZtAXReq3RMIoN7Orz7IUtcSogO4XMugM4IwGQj/RhZtnE3VfhugGTz25qr6bG
# kwVEspWjPjoexO7O/SpeB9Cn8b2gHrT7J3yOuRTSSPllwyUpvyhe1zfWH05uA2vl
# E/bEeGGwBZ1LcZxI7UrLvvWPgBZL+8OZ1Dz6aKEkEDOyZwek4nzmp9A8OrIoJBSy
# xYGDkwOdFAjqqK78d+eNTv1aHrCUs/oyHlFXSWyIg8bAaDPwck1I84K2EaNcGwJS
# V3lR5aub1GCUr4ZZxW66p0xokGsERPybhK9ZCXmcVoTGlVQisw==
# SIG # End signature block

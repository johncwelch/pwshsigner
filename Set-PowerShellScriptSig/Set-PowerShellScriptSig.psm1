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

function getCertFilePath {
	$certFilePath = Read-Host "Enter the path to the signing certificate .p12 file. If there are spaces`nor special characters, you can escape them, but really`nthat is a silly idea for this kind of path"
	defaults write com.bynkii.pwshsigner certFilePath -string $certFilePath
	return $certFilePath
}

function Set-WinPowerShellSig {
	
	param (
		[Parameter(Mandatory = $false)][string] $scriptPath = ""
	)
	
	#test for windows
	if (-Not $IsWindows) {
		Write-Output "This function only runs on Windows, exiting"
		Exit
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
	#globals
	$theUser = whoami
	$theCertPassword = ""

	###requirements checks

	##test for macOS
	if (-Not $IsMacOS) {
		Write-Output "This function only runs on macOS, exiting"
		Exit
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
	#at some point, we may think about adding a choose file option here, but for now, this will work
	$scriptFilePath = Read-Host "Enter the path to the script we want to sign. If there are spaces`nor special characters, you can escape them, but really`nthat is a silly idea for this kind of path"

	#now sign the script
	Set-OpenAuthenticodeSignature -Path $scriptFilePath -Certificate $cert

	#and done. We don't return anything because if there's an error here, set-openauthenticode will flash it for us
	#and if there's not an error, we don't care
	Return
}

Export-ModuleMember -Function Set-MacPowerShellSig
Export-ModuleMember -Function Set-WinPowerShellSig

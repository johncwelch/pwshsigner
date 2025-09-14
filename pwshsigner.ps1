##signing script
##we need to store some info, for powershell, like the password for the cert, etc.
##this requires using the security command line for setting and retrieving

##syntax to set generic password: security add-generic-password -a <username of user running script via whoami> -s "pwshsigner" -w "<thepassword>" 
##retrieval syntax: security find-generic-password -a "<username of user running script via whoami>" -w -s "pwshsigner" 
##to change an existing password, add a -U after add-generic-password before the -a

##when testing for a password, if the item is not there, the return will be null/empty, so use  [String]::IsNullOrEmpty($String) to test 

##command to set up $cert var: [System.Security.Cryptography.X509Certificates.X509Certificate2]::new('<path to p12 cert','<cert password>')

##check for open authenticode: if (Get-Module -ListAvailable -Name "OpenAuthenticode") {
## Write-Output "exists" 
## } 
## else {
##Write-Output "not found"
## }

#note that for reading defaults, true returns as 1, false as 0

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
		$thePassword = Read-Host "Enter the password for the cert you'll be using to sign with" -MaskInput
		
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

#globals
$theUser = whoami
$prefsFileExists = $false

##the first thing is to check for the module. If it's not there, tell the user and exit
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
	$prefsFileExists = $true
} else {
	#it exists, let the script know it exists
	$prefsFileExists = $true
}

#check for cert password via prefs. If the return is null or empty, there's no password, create one
$certPasswordExists = defaults read com.bynkii.pwshsigner hasCertPassword
if ([String]::IsNullOrEmpty($certPasswordExists)) {
	enterCertPassword -userName $theUser
}
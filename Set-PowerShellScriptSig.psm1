##module notes:

# add check for macOS or windows and incorporate both.
#use choose file as an option if no file path passed. Limits to Windows/macos but oh well
#one "main" function that passes off to other functions? or export win/mac? try the latter first

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

#globals
$theUser = whoami
$theCertPassword = ""

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

##get the cert password
$theCertPassword = security find-generic-password -a "$theUser" -w -s "pwshsigner"

#if $theCertPassword is null or empty, we want to call enterCertPassword again to create it
#even though this is technically a string function, it still works
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
$scriptFilePath = Read-Host "Enter the path to the script we want to sign. If there are spaces`nor special characters, you can escape them, but really`nthat is a silly idea for this kind of path"

#now sign the script
Set-OpenAuthenticodeSignature -Path $scriptFilePath -Certificate $cert

#and done
Return 


# SIG # Begin signature block
# MIIMgQYJKoZIhvcNAQcCoIIMcjCCDG4CAQMxDTALBglghkgBZQMEAgEwewYKKwYB
# BAGCNwIBBKBtBGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAtFWUK/MEnpXab
# Pio4nxHkkBmS2wSZ3aMLS5+8KGkRiaCCCawwggQEMIIC7KADAgECAggYeqmowpYh
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCAXc8rK3aywi6ro/bAGgGTu5ithbUb2ZjGdF8H5
# LLWAzDALBgkqhkiG9w0BAQEEggEAAXmR02KuPmLigIZqWAtZlm041ys1pYPyLdxE
# oUgzwCyTD0xnmArEpLDIiGeInGlVqi4AurICpR71LgDSKzWKilOlrmV8rIGl0Sk+
# Fey1Bt5rEiAHjUMtBzp+ANK0+gK10m/Ddswds3jfUk8v3155XUmqEHSORyRqcsJX
# hhHMg4a0FsC33y1ckDG9PUU/n0LSs6YoXLrKuVy9inJLG+AnHp9y7ZVjmjw5eteS
# mZBXdvKWnzYQGAVz2sbY5n3/5p1LJosgtM7mmmlaFdCkd8keJ0MPpE32k2ABvUBw
# tDbS7RdaJTsdd0H6EnQ0d3Y4Qq8C3ZCndmCDx1MLKtrdgEs40Q==
# SIG # End signature block

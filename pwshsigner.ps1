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
$theCertPassword = security find-generic-password -a "$userName" -w -s "pwshsigner"

#if $theCertPassword is null or empty, we want to call enterCertPassword again to create it
#even though this is technically a string function, it still works
if ([String]::IsNullOrEmpty($theCertPassword)) {
	enterCertPassword -userName $theUser
}
#now get the password
$theCertPassword = security find-generic-password -a "$userName" -w -s "pwshsigner"

#create the certificate
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$theCertFilePath","$theCertPassword") 

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
# MIIMgAYJKoZIhvcNAQcCoIIMcTCCDG0CAQMxDTALBglghkgBZQMEAgEwewYKKwYB
# BAGCNwIBBKBtBGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAM2wG2kQd1WYOv
# 2sh6JH88tR08SZmjtVwVfijuY16sKaCCCaswggQEMIIC7KADAgECAggYeqmowpYh
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
# 9XAwggWfMIIEh6ADAgECAggGHmabX9eOKjANBgkqhkiG9w0BAQsFADB5MS0wKwYD
# VQQDDCREZXZlbG9wZXIgSUQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxJjAkBgNV
# BAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBs
# ZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMDA5MTYwMzU4MzBaFw0yNTA5MTcwMzU4
# MzBaMIGNMRowGAYKCZImiZPyLGQBAQwKNzk2NDg4Vkc5NTE4MDYGA1UEAwwvRGV2
# ZWxvcGVyIElEIEluc3RhbGxlcjogSm9obiBXZWxjaCAoNzk2NDg4Vkc5NSkxEzAR
# BgNVBAsMCjc5NjQ4OFZHOTUxEzARBgNVBAoMCkpvaG4gV2VsY2gxCzAJBgNVBAYT
# AlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0uP+x8FCIpcy4DJ
# xqWRX3Pdtr55nnka0f22c7Ko+IAC//91iQxQLuz8fqbe4b3pEyemzfDB0GSVyhnY
# AYLVYMjVaUamr2j7apX8M3QxIcxrlHAJte1Mo+ntsQic4+syz5HZm87ew4R/52T3
# zzvtsjaKRIfy0VT35E9T4zVhpq3vdJkUCuQrHrXljxXhOEzJrJ9XllDDJ2QmYZc0
# K29YE9pVPFiZxkbf5xmtx1CZhiUulCI0ypnj7dGxLJxRtJhsFChzeSflkOBtn9H/
# RVuBjb0DaRib/mEK7FCbYgEbcIL5QcO3pUlIyghXaQoZsNaViszg7Xzfdh16efby
# y+JLaQIDAQABo4ICFDCCAhAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRXF+2i
# z9x8mKEQ4Py+hy0s8uMXVDBABggrBgEFBQcBAQQ0MDIwMAYIKwYBBQUHMAGGJGh0
# dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtZGV2aWQwNzCCAR0GA1UdIASCARQw
# ggEQMIIBDAYJKoZIhvdjZAUBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNl
# IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
# YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
# b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
# Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8v
# d3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wFwYDVR0lAQH/BA0w
# CwYJKoZIhvdjZAQNMB0GA1UdDgQWBBRdVgk/6FL+2RJDsLeMey31Hn+TBzAOBgNV
# HQ8BAf8EBAMCB4AwHwYKKoZIhvdjZAYBIQQRDA8yMDE5MDIwNjAwMDAwMFowEwYK
# KoZIhvdjZAYBDgEB/wQCBQAwDQYJKoZIhvcNAQELBQADggEBAHdfmGHh7XOchb/f
# reKxq4raNtrvb7DXJaubBNSwCjI9GhmoAJIQvqtAHSSt4CHsffoekPkWRWaJKgbk
# +UTCZLMy712KfWtRcaSNNzOp+5euXkEsrCurBm/Piua+ezeQWt6RzGNM86bOa34W
# 4r6jdYm8ta9ql4So07Z4kz3y5QN7fI20B8kG5JFPeN88pZFLUejGwUpshXFO+gbk
# GrojkwbpFuRAsiEZ1ngeqtObaO8BRKHahciFNpuTXk1I0o0XBZ2JmCUWzx3a6T4u
# fME1heNtNLRptGYMtZXH4tboV39Wf5lgHc4KR85Mbw52srsRU22NE8JWAvgFp/Qz
# qX5rmVIxggIrMIICJwIBATCBhTB5MS0wKwYDVQQDDCREZXZlbG9wZXIgSUQgQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRp
# b24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUwII
# Bh5mm1/XjiowCwYJYIZIAWUDBAIBoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIAVVn1RRhfUVdesJ+8jZ3a8v4eiYsj0o0hqtKEwK
# Vel1MAsGCSqGSIb3DQEBAQSCAQABO3WBnIco+ibM3xZREA9fGtlCgoeEx59YQVVA
# jtkIso6+fU/QOjcfZ12odj01XmaAAoDToXslyBTRoqYDf7kgCPRZn298VnSAxLtS
# ahCENleGvPtg57rLetqaemI/8XHLltyIeNjVUAHs8s/+8Ug2teYw1Br7O8IawUkr
# 1zuQhwGSEkt/1NHRF5j5LImLJTvdYjMAkWdqForxYQA46oAGKiVo0V1UOe8eQ5ax
# gPP7DzTw7pdEvHjQwNUkUOA0nQ4ke3Xc1cvX8Yv5/hviliC1dKh91nvNVnKfVBe4
# Sr6P6y8GJ5lpb/PXgCQ63iqjQ/UNu5Lw4RrMUjSdPWzi54Ws
# SIG # End signature block

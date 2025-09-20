function Set-WinPowerShellSig {
	write-host "Windows function"
}

function Set-MacPowerShellSig {
	write-host "macOS function"
}

Export-ModuleMember -Function Set-MacPowerShellSig
Export-ModuleMember -Function Set-WinPowerShellSig

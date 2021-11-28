function menu {
	Clear-Host
	Write-Host "Manage Interfaces : `n
	1) Get-Configuration
	2) Set-Configuration (static/dynamic)
	q) Quit`n"
} 

function Set-Configuration {
	Clear-Host
	$iftype = Read-Host "`nConfigure statically or dynamically [s/d]"
	if ($iftype -eq "d"){
		Set-NetIPInterface -InterfaceIndex $ifIndex -Dhcp Enabled
		pause
	}
	elseif ($iftype -eq "s"){
		$ifip = Read-Host "`nIP Address"
		$ifmask = Read-Host "Mask [0-31]"
		$ifgw = Read-Host "Gateway"
		$ifns1 = Read-Host "DNS IP Address 1"
		$ifns2 = Read-Host "DNS IP Address 2"
		
		New-NetIPAddress –InterfaceIndex $ifIndex –IPAddress $ifip –PrefixLength $ifmask –DefaultGateway $ifgw
		Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $ifns1,$ifns2
		pause
	}
	else{
		Set-Configuration
	}
}

function main {
    Clear-Host
    Get-NetAdapter

	$ifIndex = Read-Host "`nWhat interface ? [ifIndex]"
	
    do {
        menu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Get-NetIPConfiguration -InterfaceIndex $ifIndex -Detailed
				pause
            }
            "2" {
                Set-Configuration
            }
            "q" {
                return
            }
        }
    }

    until ($choice -eq 'q')
}

main

#Requires -RunAsAdministrator

function menu {
    Clear-Host
    Write-Host "Manage Users : `n
    1) LocalAccount
    2) LocalGroup
    3) LocalMember
    4) LocalUserStatus
    5) LocalPassword
    6) ADAccount
    7) ADGroup
    8) ADMember
    9) ADUserStatus
    10) ADPassword
    11) OU
    12) CSV
    q) Quit`n"
}

function submenu {
    Clear-Host
    Write-Host "Action : `n
    1) Get
    2) Add
    3) Remove
    q) Quit`n"
}

function Get-LocalGroupMembership ($User){
    foreach ($Group in (Get-LocalGroup).Name){
        if (Get-LocalGroupMember -Group $Group | Where-Object {$_.Name -match $User}){
            Write-Host $Group
        }
    }
}

function LocalAccount {
    do {
        submenu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                (Get-LocalUser).Name
                pause
            }
            "2" {
                Clear-Host
                $User = Read-Host "User"
                $Password = Read-Host "Password" -AsSecureString
                $FullName = Read-Host "FullName"
                $Description = Read-Host "Description"
                try {   
                    New-LocalUser -Name $User -Password $Password -FullName $FullName -Description $Description -ErrorAction Stop
                    Write-Host "User has been created"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.UserExistsException] {
                    Write-Host "User already exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "3" {
                Clear-Host
                (Get-LocalUser).Name
                $User = Read-Host "`nUser"
                try {   
                    Remove-LocalUser -Name $User -ErrorAction Stop
                    Write-Host "User has been deleted"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
                    Write-Host "User doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')
}

function LocalGroup {
    do {
        submenu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                (Get-LocalGroup).Name
                pause
            }
            "2" {
                Clear-Host
                $Group = Read-Host "Group"
                $Description = Read-Host "Description"
                try {   
                    New-LocalGroup -Name $Group -Description $Description -ErrorAction Stop
                    Write-Host "Group has been created"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.GroupExistsException] {
                    Write-Host "Group already exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "3" {
                Clear-Host
                $Group = Read-Host "Group"
                try {   
                    Remove-LocalGroup -Name $Group -ErrorAction Stop
                    Write-Host "Group has been deleted"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.GroupNotFoundException] {
                    Write-Host "Group doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')
}    

function LocalMember {
    do {
        submenu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                $information = Read-Host "Information about group or user ? [g/u]"
                if ($information -eq "g"){
                    (Get-LocalGroup).Name
                    $Group = Read-Host "`nGroup"
                    Get-LocalGroupMember -Group $Group
                    pause
                }
                elseif ($information -eq "u"){
                    (Get-LocalUser).Name
                    $User = Read-Host "`nUser"
                    Get-LocalGroupMembership($User)
                    pause
                }
                else {
                    Write-Host "Bad choice"
                    pause
                    LocalMember
                }
            }
            "2" {
                Clear-Host
                (Get-LocalGroup).Name
                $Group = Read-Host "`nGroup"
                $User = Read-Host "User"
                try {   
                    Add-LocalGroupMember -Group $Group -Member $User -ErrorAction Stop
                    Write-Host "Member has been added"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.MemberExistsException] {
                    Write-Host "Member already present"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.GroupNotFoundException],[Microsoft.PowerShell.Commands.PrincipalNotFoundException] {
                    Write-Host "User or Group doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "3" {
                Clear-Host
                $User = Read-Host "User"
                Get-LocalGroupMembership($User)
                $Group = Read-Host "`nGroup"
                try {   
                    Remove-LocalGroupMember -Group $Group -Member $User -ErrorAction Stop
                    Write-Host "Member has been deleted"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.MemberNotFoundException] {
                    Write-Host "Member is absent"
                    pause
                }
                catch [Microsoft.PowerShell.Commands.GroupNotFoundException],[Microsoft.PowerShell.Commands.PrincipalNotFoundException] {
                    Write-Host "User or Group doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')
}

function LocalUserStatus {
    Clear-Host
    do {
        Write-Host "Action : `n
        1) Get
        2) Change
        q) Quit`n"
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                $User = Read-Host "User"
                Get-LocalUser -Name $User | Select-Object Name, Enabled
                pause
            }
            "2" {
                Clear-Host
                Get-LocalUser | Select-Object SamAccountName, Enabled
                $User = Read-Host "`nUser"
                try {
                    if((Get-LocalUser -Name $User).Enabled -eq $False) {
                        Enable-LocalUser -Name $User -ErrorAction Stop
                        Write-Host "User has been Enabled"
                        pause
                    }
                    else {
                        Disable-LocalUser -Name $User -ErrorAction Stop
                        Write-Host "User has been Disabled"
                        pause
                    }   
                }
                catch [Microsoft.PowerShell.Commands.UserNotFoundException]{
                    Write-Host "User doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')  
}

function LocalPassword {
    Clear-Host
    $User = Read-Host "User"
    $Password = Read-Host "Password" -AsSecureString
    try {
        Set-LocalUser -Name $User -Password $Password
        Write-Host "Password has been modified"
        pause
    }
    catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
        Write-Host "User doesn't exist"
        pause
    }
    catch {
        Write-Host "Something else was wrong"
        pause
    }
}

function ADAccount {
    do {
        submenu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                Get-ADUser @Session -Properties * -Filter * | Select-Object DistinguishedName, SamAccountName, mail
                pause
            }
            "2" {
                Clear-Host
                $Name = Read-Host "Name"
                $Surname = Read-Host "Surname"
                $Password = Read-Host "Password" -AsSecureString
                if ($Surname -eq ""){
                    $Display = $Name
                    $Login = $Name.ToLower()
                    $Email = $Login+"@"+$DName.ToLower()
                }
                else {
                    $Display = $Name+" "+$Surname
                    $Login = ($Name[0]+$Surname).ToLower()
                    $Email = $Name.ToLower()+"."+$Surname.ToLower()+"@"+$DName.ToLower()
                }
                try {
                    New-ADOrganizationalUnit @Session -Name "tmp" -Path $dc
                }
                catch [Microsoft.ActiveDirectory.Management.ADException]{
                    Write-Host ""
                }
                try {
                    New-ADUser @Session -Name $Display -DisplayName $Display -GivenName $Name -Surname $Surname -EmailAddress $Email -SamAccountName $Login -UserPrincipalName $Login"@"$DName -AccountPassword $Password -Path $ou -Enabled $true -ErrorAction Stop
                    Write-Host "User has been created"
                    pause
                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                    Write-Host "User already exist"
                    pause
                }
                catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException] {
                    Write-Host "User has been created but your password is bad"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "3" {
                Clear-Host
                Get-ADUser @Session -Properties * -Filter * | Select-Object SamAccountName
                $User = Read-Host "`nUser"
                try {
                    Remove-ADUser @Session -Identity $User -ErrorAction Stop
                    Write-Host "User has been deleted"
                    pause
                }  
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    Write-Host "User doesn't exist"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')
}

function ADGroup {
    do {
        submenu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                Get-ADGroup @Session -Filter * -Properties * | Select-Object DistinguishedName, SamAccountName, Description
                pause
            }
            "2" {
                Clear-Host
                $Name = Read-Host "Name"
                $Description = Read-Host "Description"
                try {
                    New-ADOrganizationalUnit @Session -Name "tmp" -Path $dc
                }
                catch [Microsoft.ActiveDirectory.Management.ADException]{
                    Write-Host ""
                }
                try {
                    New-ADGroup @Session -GroupCategory Security -GroupScope Global -Name $Name -DisplayName $Name -SamAccountName $Name -Description $Description -Path $ou -ErrorAction Stop
                    Write-Host "Group has been created"
                    pause
                    }
                catch [Microsoft.ActiveDirectory.Management.ADException] {
                    Write-Host "Group already exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "3" {
                Clear-Host
                try {
                    Get-ADGroup @Session -Filter * -Properties * | Select-Object SamAccountName
                    $Group = Read-Host "`nGroup"
                    Remove-ADGroup -Server $SName -Credential $Cred -Identity $Group -ErrorAction Stop
                    Write-Host "Group has been deleted"
                    pause
                }  
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    Write-Host "Group doesn't exist"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')    
}

function ADMember {
    do {
        submenu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                $information = Read-Host "Information about group or user ? [g/u]"
                if ($information -eq "g"){
                    Get-ADGroup @Session -Filter * -Properties * | Select-Object SamAccountName
                    $Group = Read-Host "`nGroup"
                    Get-ADGroupMember @Session -Identity $Group -Recursive
                    pause
                }
                elseif ($information -eq "u"){
                    Get-ADUser @Session -Properties * -Filter * | Select-Object SamAccountName
                    $User = Read-Host "`nUser"
                    Get-ADPrincipalGroupMembership @Session -Identity $User
                    pause
                }
                else {
                    Write-Host "Bad choice"
                    pause
                    ADMember
                }
            }
            "2" {
                Clear-Host
                Get-ADGroup @Session -Filter * -Properties * | Select-Object SamAccountName
                $Group = Read-Host "`nGroup"
                $User = Read-Host "User"
                try {   
                    Add-ADGroupMember @Session -Identity $Group -Members $User -ErrorAction Stop
                    Write-Host "Member has been added"
                    pause
                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                    Write-Host "User or Group doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "3" {
                Clear-Host
                $User = Read-Host "User"
                Get-ADPrincipalGroupMembership @Session -Identity $User
                $Group = Read-Host "`nGroup"
                try {
                    Remove-ADGroupMember @Session -Identity $Group -Members $User -ErrorAction Stop
                    Write-Host "Member has been deleted"
                    pause
                }  
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    Write-Host "User or Group doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')  
}

function ADUserStatus {
    Clear-Host
    do {
        Write-Host "Action : `n
        1) Get
        2) Change
        q) Quit`n"
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                $User = Read-Host "User"
                Get-ADUser @Session -Identity $User | Select-Object SamAccountName, Enabled
                pause
            }
            "2" {
                Clear-Host
                Get-ADUser @Session -Filter * | Select-Object SamAccountName, Enabled
                $User = Read-Host "`nUser"
                try {
                    if((Get-ADUser @Session -Identity $User).Enabled -eq $False) {
                        Enable-ADAccount @Session -Identity $User -ErrorAction Stop
                        Write-Host "User has been Enabled"
                        pause
                    }
                    else {
                        Disable-ADAccount @Session -Identity $User -ErrorAction Stop
                        Write-Host "User has been Disabled"
                        pause
                    }   
                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                    Write-Host "User doesn't exist"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')  
}        

function ADPassword {
    Clear-Host
    $User = Read-Host "User"
    $Password = Read-Host "Password" -AsSecureString
    try {
        Set-ADAccountPassword @Session -Identity $User -NewPassword $Password -Reset
        Write-Host "Password has been modified"
        pause
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Host "User doesn't exist"
        pause
    }
    catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException] {
        Write-Host "Password has been modified but is bad"
        pause
    }
    catch {
        Write-Host "Something else was wrong"
        pause
    }
}

function OU {
    do {
        submenu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                Clear-Host
                Get-ADOrganizationalUnit @Session -Filter * | Select-Object DistinguishedName
                pause
            }
            "2" {
                Clear-Host
                Write-Host "Example : `nRoot path : " $dc "`nChild path : " $ou
                $Name = Read-Host "`nName"
                $_Path = Read-Host "Path"
                try {
                    New-ADOrganizationalUnit @Session -Name $Name -Path $_Path
                    pause
                }
                catch [Microsoft.ActiveDirectory.Management.ADException]{
                    Write-Host "Organizational Unit already exist or Path is invalid"
                    pause
                }
                catch {
                    Write-Host "Something else was wrong"
                    pause
                }
            }
            "3" {
                Clear-Host
                Get-ADOrganizationalUnit @Session -Filter * | Select-Object DistinguishedName
                $Name = Read-Host "`nName"
                try {
                    Get-ADOrganizationalUnit -F * | Where-Object {$_.Name -eq $Name} | Set-ADObject -ProtectedFromAccidentalDeletion $False
                    Remove-ADOrganizationalUnit @Session -Identity $Name -ErrorAction Stop
                    Write-Host "Organizational Unit has been deleted"
                    pause
                }  
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    Write-Host "Organizational Unit doesn't exist"
                    pause
                }
            }
            "q" {
                return
            }
        }
    }
    until ($choice -eq 'q')        
}

function CSV {
    Clear-Host
    $_Path = Read-Host "CSV path"
    $Delimiter = Read-Host "Delimiter"
    try {
        $Condition = (Get-Content $_Path -ErrorAction Stop) -match $Delimiter
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Write-Host "csv file not found"
    }
    catch {
        Write-Host "Something else was wrong"
    }

    if ($Condition) {
        $CsvFile = Import-Csv -Path $_Path -Delimiter $Delimiter 
        foreach ($Line in $CsvFile) { 
            $Name = $Line.Name
            $Surname = $Line.Surname
            $Password = ConvertTo-SecureString $Line.Password -AsPlainText -Force
            $Group = $Line.Group
            $Display = $Name+" "+$Surname
            $Login = ($Name[0]+$Surname).ToLower()
            $Email = $Name.ToLower()+"."+$Surname.ToLower()+"@"+$DName.ToLower()
        }
        try {
            New-ADOrganizationalUnit @Session -Name "tmp" -Path $dc
        }
        catch [Microsoft.ActiveDirectory.Management.ADException]{
            Write-Host ""
        }
        Write-Host "Creating user...`n"
        try {
            New-ADUser @Session -Name $Display -DisplayName $Display -GivenName $Name -Surname $Surname -EmailAddress $Email -SamAccountName $Login -UserPrincipalName $Login"@"$DName -AccountPassword $Password -Path $ou -Enabled $true -ErrorAction Stop
            Write-Host "User has been created"
            pause
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
            Write-Host "User already exist"
            pause
        }
        catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException] {
            Write-Host "User has been created but your password is bad"
            pause
        }
        catch {
            Write-Host "Something else was wrong"
            pause
        }
        Write-Host "Adding user to group...`n"
        try {   
            Add-ADGroupMember @Session -Identity $Group -Members $Login -ErrorAction Stop
            Write-Host "Member has been added"
            pause
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
            Write-Host "User or Group doesn't exist"
            pause
        }
        catch {
            Write-Host "Something else was wrong"
            pause
        }
    }
    else {
	    Write-Host "Bad delimiter"
        pause
    }
}

function main {
    Clear-Host
    $q = Read-Host "This script is execute remotely ? [y/n]"
    if($q -eq "y"){
        $global:SName = Read-Host "`nServer name"
        $SUser = Read-Host "User"
        $SPassword = Read-Host "Password" -AsSecureString
        $global:Cred = New-Object System.Management.Automation.PSCredential ($SUser, $SPassword)
        $global:DName = (Get-WmiObject Win32_ComputerSystem -ComputerName $SName -Credential $Cred).Domain
        $global:Session = @{ Server = $SName
                             Credential = $Cred
                           }
    }
    else {
        $global:DName = (Get-WmiObject Win32_ComputerSystem).Domain
    }
    $global:dc = "dc="+$DName.split('.')[0]+",dc="+$DName.split('.')[1]
    $global:ou = "ou=tmp,"+$dc
    do {
        menu
        $choice = Read-Host "What's your choice"
        switch ($choice) {
            "1" {
                LocalAccount
            }
            "2" {
                LocalGroup
            }
            "3" {
                LocalMember
            }
            "4" {
                LocalUserStatus
            }
            "5" {
                LocalPassword
            }
            "6" {
                ADAccount
            }
            "7" {
                ADGroup
            }
            "8" {
                ADMember
            }
            "9" {
                ADUserStatus
            }
            "10" {
                ADPassword
            }
            "11" {
                OU
            }
            "12" {
                CSV
            }
            "q" {
                return
            }
        }
    }

    until ($choice -eq 'q')
}

main

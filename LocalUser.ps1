Clear-Host
$choice = Read-Host "User"

$user = Get-LocalUser | Where-Object {$_.Name -eq $choice}
if ($user){
    Get-LocalUser -Name $choice| Select-Object Name,Description,Lastlogon,PasswordExpires | Format-List
}
else {
    Write-Host "Doesn't exist"
}

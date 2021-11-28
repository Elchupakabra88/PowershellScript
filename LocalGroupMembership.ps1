(Get-LocalUser).Name
$User = Read-Host "`nUser"
foreach ($Group in (Get-LocalGroup).Name){
    if (Get-LocalGroupMember -Group $Group | Where-Object {$_.Name -match $User}){
        Write-Host $Group
    }
}

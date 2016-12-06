 Function Backup-DNSZoneInScope {
param (
[Parameter(Mandatory=$False)] $ComputerName = $env:COMPUTERNAME
)
Get-DnsServerZone -ComputerName $ComputerName | Where-Object {$_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' -and $_.IsAutoCreated -eq $False} | Select * | Export-CSV -NoTypeInformation .\Backup_$ComputerName_$(Get-Date -f yyyy-MM-dd_hh_mm_ss).csv
}

　
　
Function Get-DNSZoneInScope {
param (
[Parameter(Mandatory=$False)] $ComputerName = $env:COMPUTERNAME
)
Get-DnsServerZone -ComputerName $ComputerName | Where-Object {$_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' -and $_.IsAutoCreated -eq $False -and $_.SecureSecondaries -eq 'TransferToSecureServers'} 
}

Function Update-DNSZoneTransferAllowList {
param (
[Parameter(Mandatory=$True)] $IPsToAdd,
[Parameter(Mandatory=$True)] $ZoneNameToEdit,
[Parameter(Mandatory=$False)] $ComputerName = $env:COMPUTERNAME,
[Parameter(Mandatory=$False)] [switch]$ForceToAllow
)

# Backup Zone Info
Get-DnsServerZone -ComputerName $ComputerName | Select * | Export-CSV -NoTypeInformation .\Backup_$ComputerName_$(Get-Date -f yyyy-MM-dd_hh_mm_ss).csv

# Get Scope 
$Scope = Get-DnsServerZone -ComputerName $ComputerName -Name $ZoneNameToEdit 

Switch ($Scope.SecureSecondaries)
{
    TransferAnyServer{Write-Warning "$ZoneNameToEdit is already set to TransferAnyServer and will not be modified"}
    TransferToSecureServers{
        # Displays the current settings
        Get-DnsServerZone -ComputerName $ComputerName | Where-Object {$_.ZoneName -eq $ZoneNameToEdit} | Select ZoneName,SecureSecondaries,SecondaryServers 
        
        # Gets this DNS Zone Secondaries
        $Secondaries = $Scope | Select ZoneName,SecureSecondaries,SecondaryServers

        # Extracts the secondaries from the live zone
        $ExistingIPs = $Secondaries.SecondaryServers | select IPAddressToString

        # Makes an empty array
        $IPArray = @()

        # Puts in the existing IPs
        $IPArray += $($ExistingIPs.IPAddressToString)

        # Adds the ones we want to add
        $IPArray += $IPsToAdd

        # Takes the array, sorts it, selects unique values so we don't double up
        $IPArray = $IPArray | Sort-Object | Get-Unique

        # Does the needful 
        Set-DnsServerPrimaryZone -ComputerName $ComputerName -name $Scope.ZoneName -SecureSecondaries TransferToSecureServers -SecondaryServers $IPArray

        #Write-Host "Completed, New settings"
        Get-DnsServerZone -ComputerName $ComputerName | Where-Object {$_.ZoneName -eq $ZoneNameToEdit} | Select ZoneName,SecureSecondaries,SecondaryServers 

        } # End TransferToSecureServers
    NoTransfer{
        switch ($ForceToAllow.IsPresent)
            {
            $False{
                    Write-Warning "$ZoneNameToEdit No transfers allowed use -ForceToAllow to change from NoTransfer to TransferToSecureServers"
                    } # end $false
            $True{        
            Write-Warning "$ZoneNameToEdit Overriding settings from NoTransfer to TransferToSecureServers and adding IPs"
            
            # Displays the current settings
            Get-DnsServerZone -ComputerName $ComputerName | Where-Object {$_.ZoneName -eq $ZoneNameToEdit} | Select ZoneName,SecureSecondaries,SecondaryServers 
        
            # Makes an empty array
            $IPArray = @()

            # Adds the ones we want to add
            $IPArray += $IPsToAdd

            # Does the needful 
            Set-DnsServerPrimaryZone -ComputerName $ComputerName -name $Scope.ZoneName -SecureSecondaries TransferToSecureServers -SecondaryServers $IPArray

            #Write-Host "Completed, New settings"
            Get-DnsServerZone -ComputerName $ComputerName | Where-Object {$_.ZoneName -eq $ZoneNameToEdit} | Select ZoneName,SecureSecondaries,SecondaryServers 
                    } #End $true
        } # end switch forcetoallow
    
    
    
    } # end no transfer
    } # End Switch securesecondaries
} # End Function

　
 

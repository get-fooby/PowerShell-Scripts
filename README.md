# Update-DNSZoneTransferAllowList

This simple script can be used to update DNS zones with additional entries to the zone transfer allow list. It retains the original forwarders too. 

It skips over zones where they are allowed to transfer anywhere, as adjusting these would probably cause other issues

## Function Backup-DNSZoneInScope
Simple dump of the information we edit with the update function

## Function Get-DNSZoneInScope
Gets and does some filtering

## Function Update-DNSZoneTransferAllowList
Does the magic


<#
.Synopsis
   Parse Nmap XML to PSObject
.DESCRIPTION
   Parse XML output files of the nmap port scanner (www.nmap.org) and  
   emit custom objects with properties containing the scan data. 

   Not 100% sure about script scans, I think I need to write some more object handlers.
.EXAMPLE
   Parse-NmapXML .\scan1.xml
.EXAMPLE
   I reckon you can gci *.xml | parse-nmapxml 
.Notes 
 Updated by fooby
 http://graem.es
 http://github.com/get-fooby

Original Note
 I know that the proper PowerShell way is to output $null instead of
 strings like "<no-os>" for properties with no data, but this actually
 caused confusion with people new to PowerShell and makes the output
 more digestible when exported to CSV and other formats.


 Original Version
     URL: https://cyber-defense.sans.org/blog/2009/06/11/powershell-script-to-parse-nmap-xml-output/
  Author: Enclave Consulting LLC, Jason Fossen (http://www.sans.org/sec505)  
 Version: 4.6
 Updated: 27.Feb.2016
   LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF 
          ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
          A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
          THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
          ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
          LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOW PROHIBITED TO HAVE IT.
#>
function Parse-NmapXML
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$FullName

        

    )

    Begin
    {
    $NmapReport = New-Object System.Collections.ArrayList
    #if ($Path -eq $null) {$Path = @(); $input | foreach { $Path += $_ } } 

	#if (($Path -ne $null) -and ($Path.gettype().name -eq "String")) {$Path = dir $path} #To support wildcards in $path.  

    $OutputDelimiter = "`n"

    }
    Process
    {
        $xmldoc = new-object System.XML.XMLdocument
	
        $xmlpath = (Get-Item $FullName).FullName
        $xmldoc.Load($xmlpath)
        
        foreach ($hostnode in $xmldoc.nmaprun.host) {
        
        $HostName = $null
        $FQDN = $null
        $Status = $null
        $IPv4 = $null
        $IPv6 = $null
        $MAC = $null
        $Services = $null
        $OS = $null
        $Script = $null
        $PortNumber = $null
        $PortState = $null
        $PortProtocol = $null
        $PortName = $null



#region Status
        if ($hostnode.Status -ne $null -and $hostnode.Status.length -ne 0) { $Status = $hostnode.status.state.Trim() }  
		if ($Status.length -lt 2) { $Status = "<no-status>" }
#endregion

#region Hostname
        # Extract computer names provided by user or through PTR record, but avoid duplicates and allow multiple names.
        # Note that $hostnode.hostnames can be empty, and the formatting of one versus multiple names is different.
        # The crazy foreach-ing here is to deal with backwards compatibility issues...
        $tempFQDN = $tempHostName = ""
		ForEach ($hostname in $hostnode.hostnames)
        {
            ForEach ($hname in $hostname.hostname)
            {
                ForEach ($namer in $hname.name)
                {
                    if ($namer -ne $null -and $namer.length -ne 0 -and $namer.IndexOf(".") -ne -1) 
                    {
                        #Only append to temp variable if it would be unique.
                        if($tempFQDN.IndexOf($namer.tolower()) -eq -1)
                        { $tempFQDN = $tempFQDN + " " + $namer.tolower() }
                    }
                    elseif ($namer -ne $null -and $namer.length -ne 0)
                    {
                        #Only append to temp variable if it would be unique.
                        if($tempHostName.IndexOf($namer.tolower()) -eq -1)
                        { $tempHostName = $tempHostName + " " + $namer.tolower() } 
                    }
                }
            }
        }

            

        $tempFQDN = $tempFQDN.Trim()
        $tempHostName = $tempHostName.Trim()

        if ($tempHostName.Length -eq 0 -and $tempFQDN.Length -eq 0) { $tempHostName = "<no-hostname>" } 

        #Extract hostname from the first (and only the first) FQDN, if FQDN present.
        if ($tempFQDN.Length -ne 0 -and $tempHostName.Length -eq 0) 
        { $tempHostName = $tempFQDN.Substring(0,$tempFQDN.IndexOf("."))  } 

        if ($tempFQDN.Length -eq 0) { $tempFQDN = "<no-fullname>" }

        $FQDN = $tempFQDN
        $HostName = $tempHostName  #This can be different than FQDN because PTR might not equal user-supplied hostname.
#endregion

#region addresses
	# Process each of the <address> nodes, extracting by type.
	ForEach ($addr in $hostnode.address)
    {
		if ($addr.addrtype -eq "ipv4") { $IPv4 += $addr.addr}
		if ($addr.addrtype -eq "ipv6") { $IPv6 += $addr.addr}
		if ($addr.addrtype -eq "mac")  { $MAC  += $addr.addr}
	}        
	if ($IPv4 -eq $null) { $IPv4 = "<no-ipv4>" } else { $IPv4 = $IPv4.Trim()}
	if ($IPv6 -eq $null) { $IPv6 = "<no-ipv6>" } else { $IPv6 = $IPv6.Trim()}
	if ($MAC  -eq $null) { $MAC  = "<no-mac>"  } else { $MAC  = $MAC.Trim() }
#endregion addresses

#region operatingSystem
	# Extract fingerprinted OS type and percent of accuracy.
	ForEach ($osm in $hostnode.os.osmatch) {$OS += $osm.name + " <" + ([String] $osm.accuracy) + "%-accuracy>$OutputDelimiter"} 
    ForEach ($osc in $hostnode.os.osclass) {$OS += $osc.type + " " + $osc.vendor + " " + $osc.osfamily + " " + $osc.osgen + " <" + ([String] $osc.accuracy) + "%-accuracy>$OutputDelimiter"}  
    if ($OS -ne $null -and $OS.length -gt 0)
    {
        $OS = $OS.Replace("  "," ")
        $OS = $OS.Replace("<%-accuracy>","") #Sometimes no osmatch.
		$OS = $OS.Trim()
    }
	if ($OS.length -lt 16) { $OS = "<no-os>" }
#endregion operatingSystem

#region scripts and ports
    if ($hostnode.ports.port -eq $null) { $PortNumber = "<no-ports>" ; $Services = "<no-services>" } 
        else 
    {
	    ForEach ($porto in $hostnode.ports.port)
        {
		    $Script = $null
            $services = $null
            if ($porto.service.name -eq $null) { $service = "unknown" } else { $service = $porto.service.name } 
		    
            #services
            # Build Services property. What a mess...but exclude non-open/non-open|filtered ports and blank service info, and exclude servicefp too for the sake of tidiness.
            if ($porto.state.state -like "open*" -and ($porto.service.tunnel.length -gt 2 -or $porto.service.product.length -gt 2 -or $porto.service.proto.length -gt 2)) { $Services += $service + ":" + ($porto.service.product + " " + $porto.service.version + " " + $porto.service.tunnel + " " + $porto.service.proto + " " + $porto.service.rpcnum).Trim() + " <" + ([Int] $porto.service.conf * 10) + "%-confidence>$OutputDelimiter" }
            
            #ports
            #$entry.Ports += $porto.state.state + ":" + $porto.protocol + ":" + $porto.portid + ":" + $service + $OutputDelimiter 
            $PortState = $porto.state.state
            $PortProtocol = $porto.protocol
            $PortNumber = $porto.portid
            $PortName = $service
            
            #portscropts
            if ($porto.script -ne $null) { 
            ForEach ($portscript in $porto.script) {
            $Script += "<PortScript id=""" + $portscript.id + """>$OutputDelimiter" + ($portscript.output -replace "`n","$OutputDelimiter") + "$OutputDelimiter</PortScript> $OutputDelimiter $OutputDelimiter" 
            }
            }
            
            #hostscripts
            if ($hostnode.hostscript -ne $null) {
            ForEach ($scr in $hostnode.hostscript.script)
            {
                $Script += '<HostScript id="' + $scr.id + '">' + $OutputDelimiter + ($scr.output.replace("`n","$OutputDelimiter")) + "$OutputDelimiter</HostScript> $OutputDelimiter $OutputDelimiter" 
            }
            }

            if ($Script -eq $null) { $Script = "<no-script>" }        

            #$Ports = $Ports.Trim()
            if ($Services -eq $null) { $Services = "<no-services>" } else { $Services = $Services.Trim() }
            if ($Services -ne $null) { $Services = $Services.Trim() } 

            $entry
            $i++  #Progress counter...
        $NmapObject = New-Object -TypeName System.Management.Automation.PSObject
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $HostName
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'FQDN' -Value $FQDN
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'Status' -Value $Status
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'IPv4' -Value $IPv4
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'IPv6' -Value $IPv6
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'MAC' -Value $MAC
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'Service' -Value $Services
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'OS' -Value $OS
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'Script' -Value $Script
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'PortNumber' -Value $PortNumber
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'PortState' -Value $PortState
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'PortProtocol' -Value $PortProtocol
        $NmapObject | Add-Member -MemberType NoteProperty -Name 'PortName' -Value $PortName

        $null = $NmapReport.Add($NmapObject)


	    }

    
    }
    
    
    
    
#endregion scripts
      

        }#end foreach ports


    }
    #end 41/each nmaprun.host

   

    
    
    End
    {
     $NmapReport #| Sort-Object { [version]$_.IPv4 } #>
    }

}

Function Test-Port {
    <#
		.SYNOPSIS
			Tests if a TCP or UDP is listening on a computer.

		.DESCRIPTION
			The Test-Port cmdlet tests for the availability of a TCP or UDP port on a local or remote server.

		.PARAMETER Port
			The port number to test. This must be between 1 and 65535.

		.PARAMETER ComputerName
			The IP or DNS name of the computer to test. This defaults to "localhost".

		.PARAMETER ReceiveTimeout
			The timeout in milliseconds to wait for a response. This defaults to 1000.

		.PARAMETER Source
			The source IP address the test should originate from on the local machine. If this is not specified, the Windows networking
			stack chooses the source interface. The first available port between 49152 and 65535 is used for the source port.

		.PARAMETER Tcp
			Indicates that TCP should be used. This is the default

		.PARAMETER Udp
			Indicates that UDP should be used.

        .PARAMETER Payload
            The byte array payload to send for a UDP connection test.

        .EXAMPLE
			Test-Port -Port 443 -ComputerName RemoteServer.test.local -Tcp

			Tests for the availability of port 443 via TCP on RemoteServer.test.local

        .EXAMPLE
           Test-Port -Port 123 -ComputerName dc1.contoso.com -Udp -Payload @(0x00, 0x01)

           Tests for the availability of port 123 (NTP) via UDP on dc1.contoso.com. The payload to send via UDP is also specified.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/26/2017
    #>
    [CmdletBinding(DefaultParameterSetName = "tcp")]
    [OutputType()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
		[ValidateRange(1, 65535)]
        [System.Int32]$Port,

        [Parameter(Position = 1)]
		[ValidateNotNullOrEmpty()]
        [System.String]$ComputerName = "localhost",

        [Parameter(Position = 2)]
        [ValidateScript({
            $_ -gt 0
        })]
        [System.Int32]$ReceiveTimeout = 1000,

        [Parameter()]
        [ValidateNotNull()]
        [System.Net.IPAddress]$Source = $null,

        [Parameter(ParameterSetName = "tcp")]
        [Switch]$Tcp,

        [Parameter(ParameterSetName = "udp")]
        [Switch]$Udp,

        [Parameter(ParameterSetName = "udp")]
        [ValidateNotNull()]
        [System.Byte[]]$Payload = $null
    )

    Begin {
    }

    Process {
        $Success = $false

        [System.Collections.Hashtable]$Splat = @{}
            
        # If a source was specified, choose a source port to use
        if ($Source -ne $null)
        {
            [System.Collections.Hashtable]$SourceSplat = @{}
            if ($PSCmdlet.ParameterSetName -eq "tcp")
            {
                $SourceSplat.Add("Tcp", $true)
            }
            else
            {
                $SourceSplat.Add("Udp", $true)
            }

            [System.Int32]$LocalPort = Get-InUsePorts -ReturnAvailable @SourceSplat | Select-Object -First 1
            [System.Net.IPEndPoint]$LocalEndpoint = New-Object -TypeName System.Net.IPEndPoint($Source, $LocalPort)
            $Splat.Add("ArgumentList", @($LocalEndpoint))
        }

        if ($PSCmdlet.ParameterSetName -eq "tcp")
        {
            # Create the TCP client
            [System.Net.Sockets.TcpClient]$TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient @Splat

            try
            {
                # Begin the connection and wait for a response
                $Connection = $TcpClient.BeginConnect($ComputerName, $Port, $null, $null)
                [System.Boolean]$Wait = $Connection.AsyncWaitHandle.WaitOne($ReceiveTimeout, $false)

                # If the response was successful, close the connection
                if ($Wait)
                {
                    $TcpClient.EndConnect($Connection) | Out-Null
                    $Success = $true
                }
            }
            catch [System.Net.Sockets.SocketException]
            {
                Write-Log -ErrorRecord $_ -Level VERBOSEERROR
            }
            finally
            {
                $TcpClient.Close()
                $TcpClient.Dispose()
            }
        }
        else
        {
            # Create the UDP client
            [System.Net.Sockets.UdpClient]$UdpClient = New-Object -TypeName System.Net.Sockets.UdpClient @Splat
            $UdpClient.Client.ReceiveTimeout = $ReceiveTimeout

            Write-Log -Message "Connecting to $ComputerName." -Level VERBOSE
            
            try
            {
                $UdpClient.Connect($ComputerName, $Port)
            
                if ($Payload -ne $null)
                {
                    # Create a default payload to send
                    $Payload = [System.Byte[]](0x00)
                }
            
                Write-Log -Message "Sending data." -Level VERBOSE
                [System.Int32]$SentBytes = $UdpClient.Send($Bytes, $Bytes.Length)
			    [System.Byte[]]$Buffer = New-Object -TypeName System.Byte[](512)
			    [System.Int32]$ReceivedBytes = $UdpClient.Client.Receive($Buffer)

                $Success = $ReceivedBytes > 0
            }
            catch [System.Net.Sockets.SocketException]
            {
                if (@([System.Net.Sockets.SocketError]::Success, [System.Net.Sockets.SocketError]::TimedOut,
                    [System.Net.Sockets.SocketError]::IsConnected, [System.Net.Sockets.SocketError]::IOPending) -contains
                    $_.Exception.SocketErrorCode)
                {
                    $Success = $true
                }
                else
                {
                    Write-Log -ErrorRecord $_ -Level VERBOSEERROR
                }
            }
            finally
            {
                $UdpClient.Close()
                $UdpClient.Dispose()
            }
        }

        Write-Output -InputObject $Success
    }

    End {
    }
}

Function Get-InUsePorts {
    <#
        .SYNPOSIS
            Gets the ports currently in use by TCP or UDP connections.

        .DESCRIPTION
            The cmdlet gets the ports that are currently in use by active TCP or UDP connections or listeners. The ports can be limited to either
            IPv4 or IPv6 connections, but default to including both IPv4 and IPv6. Additionally, the cmdlet can provide the available ports
            between 49152 and 65535 instead of all in use ports.

        .PARAMETER IPv4
            This specifies that only ports being used for IPv4 connections are utilized.

        .PARAMETER IPv6
            This specifies that only ports being used for IPv6 connections are utilized.

        .PARAMETER ReturnAvailable
            This specifies that available ports between 49152 and 65535 are returned instead of all in use ports.

		.PARAMETER Tcp
			Specifies that ports in use for TCP connections will be returned. This is the default.

		.PARAMETER Udp
			Specifies that ports in use for UDP connections will be returned.

        .EXAMPLE
            Get-InUsePorts -IPv4

            The cmdlet will return a list of in use IPv4 TCP ports.

        .EXAMPLE 
            Get-InUsePorts -Udp

            The cmdlet will return a list of in use IPv4 and IPv6 UDP ports.

        .INPUTS
            None

        .OUTPUTS
            System.Int32[]

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 10/25/2017
    #>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[Switch]$IPv4,

		[Parameter()]
		[Switch]$IPv6,

		[Parameter()]
		[Switch]$ReturnAvailable,

		[Parameter(ParameterSetName = "tcp")]
		[Switch]$Tcp,

		[Parameter(ParameterSetName = "udp")]
		[Switch]$Udp
	)

	Begin {
	}

	Process {
		$IPTypes = @()

		if (-not $IPv4 -and -not $IPv6)
		{
			$IPTypes = @([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.AddressFamily]::InterNetworkV6)
		}
		else
		{
			if ($IPv4)
			{
				$IPTypes += [System.Net.Sockets.AddressFamily]::InterNetwork
			}

			if ($IPv6)
			{
				$IPTypes += [System.Net.Sockets.AddressFamily]::InterNetworkV6
			}
		}

		[System.Net.IPEndpoint[]]$Listeners = $null

		if ($PSCmdlet.ParameterSetName -eq "tcp")
		{
			$Listeners = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).GetActiveTcpListeners()
		}
		else
		{
			$Listeners = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).GetActiveUdpListeners()
		}

		[System.Int32[]]$UsedPorts = $Listeners | Where-Object {$IPTypes -contains $_.AddressFamily} | Select-Object -ExpandProperty Port

		if ($ReturnAvailable)
		{
			[System.Int32[]]$Temp = 49152..65535
            # Add comma so the array isn't unrolled
			[System.Collections.ArrayList]$List = New-Object -TypeName System.Collections.ArrayList(,$Temp)

			foreach ($Port in $UsedPorts)
			{
				$List.Remove($Port)
			}

			Write-Output -InputObject ([System.Int32[]]$List | Sort-Object)
		}
		else
		{
			Write-Output -InputObject ($UsedPorts | Sort-Object)
		}
	}

	End{
	}
}

Function Set-NetAdapterDnsSuffix {
	<#
		.SYNOPSIS
			Sets the DNS suffix search order for TCP/IP.

		.DESCRIPTION
			This cmdlet allows you to specify either a list of DNS suffixes, a single DNS suffix that should be at the top of the ordering and optionally replace
			all other entries, or revert to using the primary and connection specific suffixes with optional domain name devolution (the "append parent suffixes of the primary dns suffix" option).

		.PARAMETER Domains
			The domains to set as the DNS suffix search list.

		.PARAMETER DefaultDomain
			The domain that should appear at the top of the search list. If it does not currently exist in the list it will be added, otherwise it will be moved to the top.

		.PARAMETER Replace
			Indicates whether the default domain should replace all of the current entries in the list. This is equivalent to specifying the parameter -Domains @("my.newdomain.com").
		
		.PARAMETER AppendPrimaryAndConnectionSpecificSuffixes
			This parameter removes all entries from the Search List and uses provided primary and connection specific DNS suffixes when resolving unqualified domain names.

		.PARAMETER UseDomainNameDevolution
			This parameter indiciates that domain name devolution will be used. The resolver performs name devolution on the primary DNS suffix. 
			It strips off the leftmost label and tries the resulting domain name until only two labels remain. For example, if your primary DNS suffix 
			is mfg.fareast.isp01-ext.com, and then queried for the unqualified, single-label name "coffee," the resolver queries in order the following FQDNs:
			
				coffee.fareast.isp01-ext.com.
				coffee.isp01-ext.com.

		.PARAMETER ReturnStringErrorMessage
			If this is specified, instead of an integer return value, the string representation of the error code is returned.

		.EXAMPLE
			$Result = Set-NetAdapterDnsSuffix -Domains @("contoso.com", "tailspintoys.com")

			This sets the DNS suffix search list to the domains provided. The Result indicates the success or failure code of the operation.

		.EXAMPLE
			$Result = Set-NetAdapterDnsSuffix -DefaultDomain "contoso.com"

			This sets contoso.com to be the first entry in the search list and does not modify any existing entries.

		.EXAMPLE
			$Result = Set-NetAdapterDnsSuffix -AppendPrimaryAndConnectionSpecificSuffixes

			This removes all items in the Search List and uses primary and connection specific suffixes (like those received from DHCP).

		.INPUTS
			System.String[]

		.OUTPUTS
			System.Int32

			The output is 0 for success and non-zero for failure. The exit code may correspond to a known error message that can be accessed through the
			Get-NetAdapterErrorCode cmdlet.
		
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 10/2/2017
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([System.Int32])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Domains")]
		[ValidateNotNullOrEmpty()]
		[System.String[]]$Domains = @(),

		[Parameter(Mandatory = $true, ParameterSetName = "UpdateDefault")]
		[ValidateNotNullOrEmpty()]
		[System.String]$DefaultDomain,
		
		[Parameter(ParameterSetName = "UpdateDefault")]
		[System.Boolean]$Replace = $false,

		[Parameter(ParameterSetName = "AppendPrimary", Mandatory = $true)]
		[Switch]$AppendPrimaryAndConnectionSpecificSuffixes,

		[Parameter(ParameterSetName = "AppendPrimary")]
		[System.Boolean]$UseDomainNameDevolution,
		
		[Parameter()]
		[Switch]$ReturnStringErrorMessage,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
		if (-not (Test-IsLocalAdmin)) {
			throw "You must run this cmdlet with admin credentials."
		}
	}
	
	Process {
		$Result = 65 # Unknown failure

		switch ($PSCmdlet.ParameterSetName)
		{
			"AppendPrimary" {
				$Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

				Write-Log -Message "Updating registry at $Path." -Level VERBOSE
				$Prop = Get-ItemProperty -Path $Path -Name SearchList

				if ($Prop -eq $null)
				{
					New-ItemProperty -Path $Path -Name SearchList -Value "" -PropertyType ([Microsoft.Win32.RegistryValueKind]::String) | Out-Null
				}
				else
				{
					# This will create the value if it doesn't exist, or update the existing property,
					# but we can't specify a property type with it
					Set-ItemProperty -Path $Path -Name SearchList -Value "" | Out-Null
				}

				if ($PSBoundParameters.ContainsKey("UseDomainNameDevolution")) {
					$Prop = Get-ItemProperty -Path $Path -Name UseDomainNameDevolution

					if ($Prop -eq $null)
					{
						New-ItemProperty -Path $Path -Name UseDomainNameDevolution ([System.Int32]$UseDomainNameDevolution) -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord) | Out-Null
					}
					else
					{
						Set-ItemProperty -Path $Path -Name UseDomainNameDevolution -Value ([System.Int32]$UseDomainNameDevolution) | Out-Null
					}
				}

				$Result = 0

				break
			}
			{$_ -in @("UpdateDefault", "Domains")} {

				$NewDns = @()

				# Just set the new domains to the provided ones
				if ($PSCmdlet.ParameterSetName -eq "Domains")
				{
					$NewDns = $Domains
				}
				# Otherwise, if we're replacing, only add the new default domain
				elseif ($Replace)
				{
					$NewDns += $DefaultDomain
				}
				# Otherwise, we got a default domain, but we want to move it to the top
				else
				{
					[System.String[]]$Dns = (Get-CimClass -ClassName Win32_NetworkAdapterConfiguration).CimClassProperties["DNSDomainSuffixSearchOrder"].Value

					$Index = [System.Array]::IndexOf($Dns, $DefaultDomain)

					# Index will be -1 if not found, otherwise, we found it, so move it first
					if ($Index -ge 0)
					{
						$NewDns += $Dns[$Index]
					}

					for ($i = 0; $i -lt $Dns.Length; $i++)
					{
						if ($i -ne $Index)
						{
							$NewDns += $Dns[$i]
						}
					}
				}

				Write-Log -Message "Calling SetDNSSuffixSearchOrder CIM method." -Level VERBOSE
				$Result = (Invoke-CimMethod -ClassName Win32_NetworkAdapterConfiguration -MethodName SetDNSSuffixSearchOrder -Arguments @{"DNSDomainSuffixSearchOrder" = $NewDns}).ReturnValue
				
				break
			}
		}

		if ($ReturnStringErrorMessage)
		{
			if ($script:NicErrorMessages.ContainsKey([System.UInt32]$Result) )
			{
				Write-Output -InputObject ($script:NicErrorMessages[[System.UInt32]$Result])
			}
			else
			{
				Write-Output -InputObject "$Result"
			}
		}
		else
		{
			Write-Output -InputObject $Result
		}
	}

	End {
	}
}

Function Get-NetAdapterErrorCode {
	<#
		.SYNOPSIS 
			Returns the string error message from a net adapter WMI method return value for the Win32_NetworkAdapterConfiguration class.

		.DESCRIPTION
			Attempts the find the string error message corresponding to the SetDNSSuffixSearchOrder method call on the Win32_NetworkAdapterConfiguration class. 
			If the error message is not found, the error code is returned as a string. This cmdlet can be used with the Set-NetAdapterDnsSuffix cmdlet to translate
			the return code.

		.PARAMETER ErrorCode
			The error code returned by the Win32_NetworkAdapterConfiguration class method.

		.EXAMPLE
			Get-NetAdapterErrorCode -ErrorCode 73

			This returns the string "Invalid domain name".

		.INPUTS
			System.Int32

		.OUTPUTS
			System.String

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 10/2/2017
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
		[System.UInt32]$ErrorCode
	)

	Begin {
	}

	Process {
		if ($script:NicErrorMessages.ContainsKey($ErrorCode))
		{
			Write-Output -InputObject $script:NicErrorMessages[$ErrorCode]
		}
		else
		{
			Write-Output -InputObject "$ErrorCode"
		}
	}

	End {
	}
}

Function Get-IPv6ConfigurationOptions {
	<#
		.SYNOPSIS
			Writes the HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters DisabledComponents key property possible options.

		.DESCRIPTION
			The Get-IPv6ConfigurationOptions cmdlet writes the HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters DisabledComponents key property possible options. This registry key entry determines which components of IPv6 are enabled or disabled.

			The cmdlet writes the possible values to enter in this key entry.

		.EXAMPLE
			Get-IPv6ConfigurationOptions

			This command returns the possible registry key settings as an array of PSCustomObjects.

		.INPUTS
			None

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]
		
		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/28/2016
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject[]])]
	Param()

	Begin {}

	Process {
		Write-Output -InputObject $script:IPv6Configs
	}

	End {}
}

$script:IPv6Configs = @(
	[PSCustomObject]@{Name="IPv6 Disabled On All Interfaces";Value="0xFFFFFFFF"},
	[PSCustomObject]@{Name="IPv6 Enabled only on tunnel interfaces";Value="0xFFFFFFFE"}, 
	[PSCustomObject]@{Name="IPv6 Disabled On Tunnel Interfaces, Enabled On All Others";Value="0xFFFFFFEF"},
	[PSCustomObject]@{Name="IPv6 Disabled On Loopback Interface, Enabled On All Others";Value="0xFFFFFFEE"},
	[PSCustomObject]@{Name="IPv6 Disabled, Prefer IPv6 over IPv4";Value="0xFFFFFFDF"},
	[PSCustomObject]@{Name="IPv6 Enabled Only On Tunnel Interfaces, Prefer IPv6 of IPv4";Value="0xFFFFFFDE"},
	[PSCustomObject]@{Name="IPv6 Enabled On All Non Tunnel Interfaces, Prefer IPv6 over IPv4";Value="0xFFFFFFCF"},
	[PSCustomObject]@{Name="IPv6 Disabled On Loopback Interface, Prefer IPv6 over IPv4";Value="0xFFFFFFCE"},
	[PSCustomObject]@{Name="IPv6 Disabled On All Interfaces";Value="0x000000FF"},
	[PSCustomObject]@{Name="IPv6 Prefer IPv4 over IPv6 by changing entries in prefix policy table";Value="0x00000020"},
	[PSCustomObject]@{Name="IPv6 Disabled on LAN and PPP interfaces ";Value="0x00000010"},
	[PSCustomObject]@{Name="Disable Teredo";Value="0x00000008"},
	[PSCustomObject]@{Name="Disable ISATAP";Value="0x00000004"},
	[PSCustomObject]@{Name="Disable 6to4";Value="0x00000002"},
	[PSCustomObject]@{Name="IPv6 Disabled on Tunnel Interfaces including ISATAP, 6to4 and Teredo";Value="0x00000001"}
)

$script:NicErrorMessages = @{
			[System.UInt32]0 = "Successful completion, no reboot required";
			[System.UInt32]1 = "Successful completion, reboot required";
			[System.UInt32]64 = "Method not supported on this platform";
			[System.UInt32]65 = "Unknown failure";
			[System.UInt32]66 = "Invalid subnet mask";
			[System.UInt32]67 = "An error occurred while processing an Instance that was returned";
			[System.UInt32]68 = "Invalid input parameter";
			[System.UInt32]69 = "More than 5 gateways specified";
			[System.UInt32]70 = "Invalid IP address";
			[System.UInt32]71 = "Invalid gateway IP address";
			[System.UInt32]72 = "An error occurred while accessing the Registry for the requested information";
			[System.UInt32]73 = "Invalid domain name";
			[System.UInt32]74 = "Invalid host name";
			[System.UInt32]75 = "No primary/secondary WINS server defined";
			[System.UInt32]76 = "Invalid file";
			[System.UInt32]77 = "Invalid system path";
			[System.UInt32]78 = "File copy failed";
			[System.UInt32]79 = "Invalid security parameter";
			[System.UInt32]80 = "Unable to configure TCP/IP service";
			[System.UInt32]81 = "Unable to configure DHCP service";
			[System.UInt32]82 = "Unable to renew DHCP lease";
			[System.UInt32]83 = "Unable to release DHCP lease";
			[System.UInt32]84 = "IP not enabled on adapter";
			[System.UInt32]85 = "IPX not enabled on adapter";
			[System.UInt32]86 = "Frame/network number bounds error";
			[System.UInt32]87 = "Invalid frame type";
			[System.UInt32]88 = "Invalid network number";
			[System.UInt32]89 = "Duplicate network number";
			[System.UInt32]90 = "Parameter out of bounds";
			[System.UInt32]91 = "Access denied";
			[System.UInt32]92 = "Out of memory";
			[System.UInt32]93 = "Already exists";
			[System.UInt32]94 = "Path, file or object not found";
			[System.UInt32]95 = "Unable to notify service";
			[System.UInt32]96 = "Unable to notify DNS service";
			[System.UInt32]97 = "Interface not configurable";
			[System.UInt32]98 = "Not all DHCP leases could be released/renewed";
			[System.UInt32]100 = "DHCP not enabled on adapter";
			[System.UInt32]2147786788 = "Write lock not enabled";
			[System.UInt32]2147749891 = "Must be run with admin privileges"
		}
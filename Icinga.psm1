#Requires -Version 4.0

function GetIcingaHeader {
[CmdletBinding()]
param(
    [Parameter()]
    [System.Uri]
    $Uri = 'https://raw.githubusercontent.com/Icinga/icinga-core/4e19d7d74905a0c1060d5dfe7c3a478bce569b11/include/common.h' ,

    [Parameter()]
    [ValidateScript(
        { $_ | Test-Path }
    )]
    [String]
    $Default = ($PSScriptRoot | Join-Path -ChildPath 'common.h')
)
    try {
        $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
        $response.Content
    } catch {
        Write-Warning "Error retrieving file from '$Uri'. Falling back to cached file."
        Get-Content $Default -Raw
    }
}

function NewIcingaCmdEnumDefinition {
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Header = (GetIcingaHeader)
)

    $pre = @"
public enum IcingaCommand
{

"@
    $post = @"

}
"@
    $defs = @()

    $Header -csplit '\r?\n' | ForEach-Object {
        if ($_ -cmatch '^#define (?<cmd>CMD_(?!ERROR)\S+)\s+(?<val>\d+)') {
            $defs += ('{0} = {1}' -f $Matches['cmd'], $Matches['val'] )
        }
    }
    
    "$pre$($defs -join ",`r`n")$post"
}

function NewIcingaCheckStateEnumDefinition {
[CmdletBinding()]
param()
    @'
public enum IcingaCheckState
{
    OK = 0,
    WARNING = 1,
    CRITICAL = 2,
    UNKNOWN = 3
}
'@
}

function NewIcingaHostChildOptionsEnumDefinition {
[CmdletBinding()]
param()
    @'
public enum IcingaHostChildOptions
{
    DO_NOTHING = 0,
    SCHEDULE_TRIGGERED_DOWNTIME = 1,
    SCHEDULE_NON_TRIGGERED_DOWNTIME = 2
}
'@
}

function AddIcingaEnum {
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $Definition
)
    foreach($typedef in $Definition) {
        Add-Type -TypeDefinition $typedef -ErrorAction Stop
    }
}

function AddSSLValidator {
[CmdletBinding()]
param()
    Add-Type @"
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;

    public static class SSLValidator
    {
        private static Stack<RemoteCertificateValidationCallback> funcs = new Stack<RemoteCertificateValidationCallback>();

        private static bool OnValidateCertificate(object sender, X509Certificate certificate, X509Chain chain,
                                                    SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        public static void OverrideValidation()
        {
            funcs.Push(ServicePointManager.ServerCertificateValidationCallback);
            ServicePointManager.ServerCertificateValidationCallback =
                OnValidateCertificate;
        }

        public static void RestoreValidation()
        {
            if (funcs.Count > 0) {
                ServicePointManager.ServerCertificateValidationCallback = funcs.Pop();
            }
        }
    }
"@
}

function JoinUri {
[CmdletBinding(DefaultParameterSetName='AllAtOnce')]
param(
    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ParameterSetName='LTR'
    )]
    [ValidateNotNullOrEmpty()]
    [System.Uri]
    $Uri ,

    [Parameter(
        Mandatory,
        ParameterSetName='LTR'
    )]
    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ParameterSetName='AllAtOnce'
    )]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $ChildPath ,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [String]
    $Delimeter = '/'
)

    Begin {
        $result = [String]::Empty
    }

    Process {
        switch ($PSCmdlet.ParameterSetName) {
            'LTR' {
                $result = $Uri.ToString()
                foreach ($component in $ChildPath) {
                    $result = "{0}$Delimeter{1}" -f $result.TrimEnd($Delimeter), $component.TrimStart($Delimeter)
                }
                $result
            }

            'AllAtOnce' {
                foreach($component in $ChildPath) {
                    if (!$result) {
                        $result = $component
                    } else {
                        $result = "{0}$Delimeter{1}" -f $result.TrimEnd($Delimeter), $component.TrimStart($Delimeter)
                    }
                }
            }
        }
    }

    End {
        if ($PSCmdlet.ParameterSetName -eq 'AllAtOnce') {
            $result
        }
    }
}

function NewNameValueCollection {
[CmdletBinding()]
[OutputType([System.Collections.Specialized.NameValueCollection])]
param(
    [hashtable]$Hash
)
    $nvc = New-Object System.Collections.Specialized.NameValueCollection
    foreach($h in $Hash.GetEnumerator()) {
        $nvc.Add($h.Key, $h.Value.ToString()) | Out-Null
    }
    ,$nvc
}

function InvokeCustomPostRequest {
[CmdletBinding()]
param(
    [Parameter(
        Mandatory
    )]
    [Uri]
    $Uri ,

    [Parameter(
        Mandatory
    )]
    [Hashtable]
    $Body ,

    [Parameter()]
    [PSCredential]
    $Credential ,

    [Parameter()]
    [Switch]
    $SkipSslValidation
)
    try {
        if ($SkipSslValidation) {
            [SSLValidator]::OverrideValidation()
        }
        $data = NewNameValueCollection -Hash $Body
        $client = New-Object System.Net.WebClient
        if ($Credential) {
            $client.Credentials = $Credential.GetNetworkCredential()
        }
        $response = $client.UploadValues($Uri, $data)
        [System.Text.Encoding]::UTF8.GetString($response)
    } catch [System.Net.WebException] {
        throw
    } finally {
        if ($SkipSslValidation) {
            [SSLValidator]::RestoreValidation()
        }
    }
}

function ParseIcingaResponse {
[CmdletBinding()]
param(
    [Parameter(
        Mandatory
    )]
    [ValidateNotNullOrEmpty()]
    [String]
    $HtmlResponse
)

    $document = New-Object HtmlAgilityPack.HtmlDocument
    $document.LoadHtml($HtmlResponse)

    $hasError = $false

    $table = $document.DocumentNode.SelectSingleNode("//table[@class='errorTable']")
    if ($table) {
        $hasError = $true
        $errorMessage = "One or more errors occurred:`n"
        $errorCount = 0
        foreach ($row in $table.SelectNodes("tr")) {
            $errorCount++
            $errorMessage += ("{0}. {1}`n" -f $errorCount, ($row.SelectSingleNode("td[@class='errorContent']").InnerText))
        }
    } else {
        $div = $document.DocumentNode.SelectSingleNode("//div[@class='errorMessage']")
        if ($div) {
            $hasError = $true
            $errorMessage = $div.InnerText
        }
        $div = $document.DocumentNode.SelectSingleNode("//div[@class='errorDescription']")
        if ($div) {
            $hasError = $true
            $errorMessage = @($errorMessage, $div.InnerText) -join "`n"
        }
    }
    if ($hasError) {
        throw [System.ArgumentException]$errorMessage
    }
}

function ProcessDuration {
[CmdletBinding(DefaultParameterSetName='Process')]
[OutputType([DateTime], ParameterSetName='Process')]
[OutputType([bool], ParameterSetName='Verify')]
param(
    [Parameter(
        Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName='Process'
    )]
    [DateTime]
    $StartTime ,

    [Parameter(
        Mandatory,
        ValueFromPipelineByPropertyName,
        ParameterSetName='Process'
    )]
    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ParameterSetName='Verify'
    )]
    [String]
    $Duration ,

    [Parameter(
        Mandatory,
        ParameterSetName='Verify'
    )]
    [Switch]
    $Verify
)

    Process {
        $Span = New-TimeSpan
        $formats = @(
            '%d\d%h\h%m\m%s\s'
            '%d\d%h\h%m\m'
            '%d\d%h\h'
            '%d\d'
            '%h\h%m\m%s\s'
            '%h\h%m\m'
            '%h\h'
            '%m\m%s\s'
            '%m\m'
            '%s\s'
        )
        Write-Verbose "Trying to parse '$Duration' as a duration."
        $verdict = [TimeSpan]::TryParseExact($Duration, [string[]]$formats, $null, [ref]$Span)
        if ($Verify) {
            $verdict
        } else {
            if ($verdict) {
                $end = $StartTime + $Span
                Write-Verbose "'$StartTime' + '$Duration' = '$end'"
                $end
            } else {
                throw [System.Management.Automation.MethodInvocationException]"Error interpreting '$Duration'"
            }
        }
    }
}

function ConvertToIcingaDateTime {
[CmdletBinding()]
[OutputType([String])]
param(
    [Parameter(
        Mandatory,
        ValueFromPipeline
    )]
    [DateTime]
    $DateTime
)

    Process {
        $DateTime.ToString('MM-dd-yyyy HH:mm:ss')
    }
}

# Exports


function Invoke-IcingaCommand {
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(
        Mandatory
    )]
    [Uri]
    $IcingaUrl ,

    [Parameter(
        Mandatory
    )]
    [Alias('cmd')]
    [Alias('cmd_typ')]
    [IcingaCommand]
    $Command ,

    [Parameter(
        Mandatory
    )]
    [hashtable]
    $Data ,

    [Parameter()]
    [PSCredential]
    $Credential ,

    [Parameter()]
    [Switch]
    $SkipSslValidation
)
    $Data['cmd_typ'] = $Command.value__
    $Data['cmd_mod'] = 2  # Commit
    $params = @{
        Uri = [Uri]($IcingaUrl | JoinUri -ChildPath '/cgi-bin/cmd.cgi')
        Body = $Data
        SkipSslValidation = $SkipSslValidation
    }
    if ($Credential) {
        $params.Credential = $Credential
    }

    Write-Verbose "Invoking the POST with the following parameters:"
    $params | Out-String | Write-Verbose

    if ($PSCmdlet.ShouldProcess($params['Uri'])) {
        $response = InvokeCustomPostRequest @params
        ParseIcingaResponse -HtmlResponse $response
    }
}

function Submit-IcingaCustomNotification {
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(
        Mandatory
    )]
    [Uri]
    $IcingaUrl ,

    [Parameter(
        Mandatory,
        ValueFromPipeline
    )]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $Host ,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [Alias('Svc')]
    [String[]]
    $Service ,
    
    [Parameter(
        Mandatory
    )]
    [ValidateNotNullOrEmpty()]
    [Alias('Message')]
    [String]
    $Comment ,

    [Parameter()]
    [PSCredential]
    $Credential ,

    [Parameter()]
    [Switch]
    $SkipSslValidation
)

    Begin {
        $params = @{
            IcingaUrl = $IcingaUrl
            SkipSslValidation = $SkipSslValidation
            Command = [IcingaCommand]::CMD_SEND_CUSTOM_SVC_NOTIFICATION
        }
        if ($Credential) {
            $params.Credential = $Credential
        }
    }

    Process {
        foreach($hostname in $Host) {
            if ($Service) {
                $params.Command = [IcingaCommand]::CMD_SEND_CUSTOM_SVC_NOTIFICATION
                foreach($svc in $Service) {
                    Write-Verbose "Sending Custom Service Notification for '$svc' on '$hostname'"
                    $params.Data = @{
                        hostservice = "$hostname^$svc"
                        com_data = $Comment
                    }
                    Invoke-IcingaCommand @params
                }
            } else {
                $params.Command = [IcingaCommand]::CMD_SEND_CUSTOM_HOST_NOTIFICATION
                Write-Verbose "Sending Custom Host Notification for '$hostname'"
                $params.Data = @{
                    host = $hostname
                    com_data = $Comment
                }
                Invoke-IcingaCommand @params
            }
        }
    }
}

function Start-IcingaDowntime {
[CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='HostsOnlyDuration')]
param(
    [Parameter(
        Mandatory
    )]
    [Uri]
    $IcingaUrl ,

    [Parameter(
        Mandatory,
        ValueFromPipeline
    )]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $Host ,

    [Parameter(
        Mandatory,
        ParameterSetName='ServiceDowntimeDuration'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='ServiceDowntimeEndTime'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias('Svc')]
    [String[]]
    $Service ,

    [Parameter(
        Mandatory,
        ParameterSetName='HostAndAllServicesDuration'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='HostAndAllServicesEndTime'
    )]
    [Alias('AndAllServices')]
    [Switch]
    $AllServices ,
        
    [Parameter(
        Mandatory
    )]
    [ValidateNotNullOrEmpty()]
    [Alias('Message')]
    [String]
    $Comment ,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(
         'Fixed'
        ,'Flexible'
    )]
    [Alias('flexible_selection')]
    [String]
    $Type = 'Fixed' ,

    [Parameter(
        Mandatory
    )]
    [Alias('start_time')]
    [Alias('StartAt')]
    [Alias('Begin')]
    [Alias('Start')]
    [DateTime]
    $StartTime ,

    [Parameter(
        Mandatory,
        ParameterSetName='HostsOnlyEndTime'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='HostAndAllServicesEndTime'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='ServiceDowntimeEndTime'
    )]
    [Alias('end_time')]
    [Alias('EndAt')]
    [Alias('End')]
    [DateTime]
    $EndTime ,

    [Parameter(
        Mandatory,
        ParameterSetName='HostsOnlyDuration'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='HostAndAllServicesDuration'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='ServiceDowntimeDuration'
    )]
    [ValidateScript( { $_ | ProcessDuration -Verify } )]
    [Alias('EndAfter')]
    [Alias('For')]
    [String]
    $Duration ,

    [Parameter(
        ParameterSetName='HostsOnlyDuration'
    )]
    [Parameter(
        ParameterSetName='HostsOnlyEndTime'
    )]
    [Alias('childoptions')]
    [IcingaHostChildOptions]
    $ChildOption = [IcingaHostChildOptions]::DO_NOTHING ,

    [Parameter()]
    [PSCredential]
    $Credential ,

    [Parameter()]
    [Switch]
    $SkipSslValidation
)

    Begin {
        $params = @{
            IcingaUrl = $IcingaUrl
            SkipSslValidation = $SkipSslValidation
        }
        if ($Credential) {
            $params.Credential = $Credential
        }
    }

    Process {
        if ($PSCmdlet.ParameterSetName -like '*Duration') {
            $recurser = ([HashTable]$PSBoundParameters).Clone()
            $recurser.Remove('Duration')
            $recurser.EndTime = [PSCustomObject][HashTable]$PSBoundParameters | ProcessDuration
            Start-IcingaDowntime @recurser
            return
        }
        if ($EndTime -le $StartTime) {
            throw [System.ArgumentException]"EndTime must be later than StartTime"
        }
        $data_base = @{
            com_data = $Comment
            start_time = $StartTime | ConvertToIcingaDateTime
            end_time = $EndTime | ConvertToIcingaDateTime
            flexible_selection = $Type.ToLower()
        }
        foreach($hostname in $Host) {
            switch -Wildcard ($PSCmdlet.ParameterSetName)
            {
                'HostsOnly*' { 
                    $params.Command = [IcingaCommand]::CMD_SCHEDULE_HOST_DOWNTIME
                    $params.Data = $data_base.Clone()
                    $params.Data.host = $hostname
                    $params.Data.childoptions = $ChildOption.value__

                    Write-Verbose "Scheduling downtime for host '$hostname'."

                    Invoke-IcingaCommand @params
                }
                
                'HostAndAllServices*' { 
                    $params.Command = [IcingaCommand]::CMD_SCHEDULE_HOST_SVC_DOWNTIME
                    $params.Data = $data_base.Clone()
                    $params.Data.host = $hostname

                    Write-Verbose "Scheduling downtime for host '$hostname' and all of its services."

                    Invoke-IcingaCommand @params
                }

                'ServiceDowntime*' { 
                    $params.Command = [IcingaCommand]::CMD_SCHEDULE_SVC_DOWNTIME
                    foreach($svc in $Service) {
                        $params.Data = $data_base.Clone()
                        $params.Data.hostservice = "$hostname^$svc"

                        Write-Verbose "Scheduling downtime for service '$svc' on host '$hostname'."

                        Invoke-IcingaCommand @params
                    }
                }
                default { throw [System.NotImplementedException]"Error in function definition. This should never have happened." }
            }
        }
    }
}

AddIcingaEnum -Definition @(
    (NewIcingaCheckStateEnumDefinition)
    (NewIcingaCmdEnumDefinition)
    (NewIcingaHostChildOptionsEnumDefinition)
)

AddSSLValidator

#Export-ModuleMember -Function *-*

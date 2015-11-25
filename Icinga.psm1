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

function NewIcingaHostCheckResultEnumDefinition {
[CmdletBinding()]
param()
    @'
public enum IcingaHostCheckResult
{
    UP = 0,
    DOWN = 1,
    UNREACHABLE = 2
}
'@
}

function NewIcingaServiceCheckResultEnumDefinition {
[CmdletBinding()]
param()
    @'
public enum IcingaServiceCheckResult
{
    OK = 0,
    WARNING = 1,
    CRITICAL = 2,
    UNKNOWN = 3
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

function InvokeCustomGetRequest {
[CmdletBinding()]
param(
    [Parameter(
        Mandatory
    )]
    [Uri]
    $Uri ,

    [Parameter()]
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
        $client = New-Object System.Net.WebClient
        if ($Credential) {
            $client.Credentials = $Credential.GetNetworkCredential()
        }
        if ($Body) {
            $client.QueryString = NewNameValueCollection -Hash $Body
        }
        $response = $client.DownloadData($Uri)
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
[OutputType([Timespan], ParameterSetName='AsTimespan')]
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
    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ParameterSetName='AsTimespan'
    )]
    [String]
    $Duration ,

    [Parameter(
        Mandatory,
        ParameterSetName='Verify'
    )]
    [Switch]
    $Verify ,

    [Parameter(
        Mandatory,
        ParameterSetName='AsTimespan'
    )]
    [Switch]
    $AsTimespan
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
        switch ($PSCmdlet.ParameterSetName)
        {
            'Verify' { $verdict }
            'Process' {
                if ($verdict) {
                    $end = $StartTime + $Span
                    Write-Verbose "'$StartTime' + '$Duration' = '$end'"
                    $end
                } else {
                    throw [System.Management.Automation.MethodInvocationException]"Error interpreting '$Duration'"
                }
            }
            'AsTimespan' {
                if ($verdict) {
                    $Span
                } else {
                    throw [System.Management.Automation.MethodInvocationException]"Error interpreting '$Duration'"
                }
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

function FormatIcingaDowntimeTrigger {
[CmdletBinding()]
param(
    [Parameter(
        Mandatory,
        ValueFromPipeline
    )]
    [PSObject[]]
    $DowntimeObject
)

    Process {
        $fmtDateTime = 'MM-dd-yyyy_HH:mm:ss'
        foreach($downtime in $DowntimeObject) {
            $formatter = @(
                        $downtime.downtime_id
                        $downtime.host_display_name -replace '\s','_'
                        $downtime.start_time.ToString($fmtDateTime)
            )
            if ($downtime.is_service) {
                'ID:{0}/Service:{3}/Host:{1}/starting@{2}' -f ($formatter + $downtime.service_display_name -replace '\s','_')
            } else {
                'ID:{0}/Host:{1}/starting@{2}' -f $formatter
            }
        }
    }
}


# Exports


function Get-IcingaDowntime {
[CmdletBinding()]
[OutputType([PSObject])]
param(
    [Parameter(
        Mandatory
    )]
    [Uri]
    $IcingaUrl ,
    
    [Parameter()]
    [PSCredential]
    $Credential ,

    [Parameter()]
    [Switch]
    $SkipSslValidation
)

    $params = @{}

    $params.Uri = $IcingaUrl | JoinUri -ChildPath cgi-bin,extinfo.cgi
    $params.SkipSslValidation = $SkipSslValidation
    if ($Credential) {
        $params.Credential = $Credential
    }
    $params.Body = @{
        type = 6
        limit = 0
        start = 1
        jsonoutput = ''
    }

    $raw = InvokeCustomGetRequest @params
    if (!$raw) {
        throw [System.Net.WebException]"Could not retrieve Icinga downtimes."
    }
    $dtobj = $raw | ConvertFrom-Json

    $dtobj.extinfo.host_downtimes + $dtobj.extinfo.service_downtimes | ForEach-Object {
        $props = [Ordered]@{
            host_name = $_.host_name
            host_display_name = $_.host_display_name
            service_description = $null
            service_display_name = $null
            entry_time = [DateTime]$_.entry_time
            author = $_.author
            comment = $_.comment
            start_time = [DateTime]$_.start_time
            end_time = [DateTime]$_.end_time
            type = $_.type
            trigger_time = $null
            duration = [TimeSpan]($_.duration -replace '\s','' | ProcessDuration -AsTimespan)
            is_in_effect = [Bool]$_.is_in_effect
            downtime_id = [int]$_.downtime_id
            trigger_id = $null
        }
        if ($_.service_description) {
            $props.service_description = $_.service_description
        }
        if ($_.service_display_name) {
            $props.service_display_name = $_.service_display_name
        }
        if ($_.trigger_time -and $_.trigger_time -ne 'null') {
            $props.trigger_time = [DateTime]$_.trigger_time
        }
        if ($_.trigger_id -and $_.trigger_id -ne 'null') {
            $props.trigger_id = [int]$_.trigger_id
        }

        New-Object PSObject -Property $props | Add-Member -MemberType ScriptProperty -Name is_service -Value { [bool]($this.service_description -or $this.service_display_name) } -PassThru
    }
}

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
    $params.Clone().Remove('Body') | Out-String | Write-Verbose
    Write-Verbose "with body:"
    $params.Body | Out-String | Write-Verbose

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

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( { [int]$_ } )]
    [String] # Eventually this might take a longer string as a trigger, from which the ID will be extracted, hence [String] and not [int]
    $TriggeredBy ,

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
    [Switch]
    $Unique ,

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
        $flex = switch ($Type)
        {
            'Fixed' { 1 } #'1"' }
            'Flexible' { 0 } #'0"' }
        }
        if ($Unique) {
            $currentDowntimes = Get-IcingaDowntime @params -Verbose:$false
        }
    }

    Process {
        if ($PSCmdlet.ParameterSetName -like '*Duration') {
            $recurser = ([HashTable]$PSBoundParameters).Clone()
            $recurser.Remove('Duration')
            #$recurser.EndTime = [PSCustomObject][HashTable]$PSBoundParameters | ProcessDuration -Verbose:$false
            $recurser.EndTime = ProcessDuration -StartTime $StartTime -Duration $Duration -Verbose:$false
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
            fixed = $flex
            trigger = [int]$TriggeredBy
        }
        foreach($hostname in $Host) {
            $skipDup = $false
            switch -Wildcard ($PSCmdlet.ParameterSetName)
            {
                'HostsOnly*' { 
                    $params.Command = [IcingaCommand]::CMD_SCHEDULE_HOST_DOWNTIME
                    $params.Data = $data_base.Clone()
                    $params.Data.host = $hostname
                    $params.Data.childoptions = $ChildOption.value__

                    if ($Unique) {
                        foreach ($downtime in $currentDowntimes) {
                            $skipDup = $skipDup -or (
                                $downtime.host_name -eq $params.Data.host -and
                                $downtime.start_time -eq $params.Data.start_time -and
                                $downtime.end_time -eq $params.Data.end_time -and
                                $downtime.type -ieq $Type -and
                                [int]$downtime.trigger_id -eq [int]$params.Data.trigger -and
                                $downtime.comment -eq $params.Data.com_data
                            )
                        }
                    }

                    if ($skipDup) {
                        Write-Verbose -Message "Skipping duplicate downtime request for '$hostname'."
                    } else {
                        Write-Verbose "Scheduling downtime for host '$hostname'."
                        Invoke-IcingaCommand @params
                    }
                }
                
                'HostAndAllServices*' { 
                    $params.Command = [IcingaCommand]::CMD_SCHEDULE_HOST_SVC_DOWNTIME
                    $params.Data = $data_base.Clone()
                    $params.Data.host = $hostname

                    if ($Unique) {
                        foreach ($downtime in $currentDowntimes) {
                            $skipDup = $skipDup -or (
                                $downtime.host_name -eq $params.Data.host -and
                                $downtime.start_time -eq $params.Data.start_time -and
                                $downtime.end_time -eq $params.Data.end_time -and
                                $downtime.type -ieq $Type -and
                                [int]$downtime.trigger_id -eq [int]$params.Data.trigger -and
                                $downtime.comment -eq $params.Data.com_data
                            )
                        }
                    }

                    if ($skipDup) {
                        Write-Verbose -Message "Skipping duplicate downtime request for '$hostname'."
                    } else {
                        Write-Verbose "Scheduling downtime for host '$hostname' and all of its services."
                        Invoke-IcingaCommand @params
                    }
                }

                'ServiceDowntime*' { 
                    $params.Command = [IcingaCommand]::CMD_SCHEDULE_SVC_DOWNTIME
                    foreach($svc in $Service) {
                        $params.Data = $data_base.Clone()
                        $params.Data.hostservice = "$hostname^$svc"

                        if ($Unique) {
                            foreach ($downtime in $currentDowntimes) {
                                $skipDup = $skipDup -or (
                                    $downtime.host_name -eq $hostname -and
                                    $downtime.service_description -eq $svc -and
                                    $downtime.start_time -eq $params.Data.start_time -and
                                    $downtime.end_time -eq $params.Data.end_time -and
                                    $downtime.type -ieq $Type -and
                                    [int]$downtime.trigger_id -eq [int]$params.Data.trigger -and
                                    $downtime.comment -eq $params.Data.com_data
                                )
                            }
                        }

                        if ($skipDup) {
                            Write-Verbose -Message "Skipping duplicate downtime request for '$svc' on '$hostname'."
                        } else {
                            Write-Verbose "Scheduling downtime for service '$svc' on host '$hostname'."
                            Invoke-IcingaCommand @params
                        }
                    }
                }
                default { throw [System.NotImplementedException]"Error in function definition. This should never have happened. ParameterSet: $($PSCmdlet.ParameterSetName)" }
            }
        }
    }
}

function Stop-IcingaDowntime {
[CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='HostAndAllServices')]
param(
    [Parameter(
        Mandatory
    )]
    [Uri]
    $IcingaUrl ,

    [Parameter(
        Mandatory,
        ParameterSetName='ByDowntimeID'
    )]
    [Alias('ID')]
    [Alias('DownID')]
    [Alias('down_id')]
    [int[]]
    $DowntimeId ,

    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ParameterSetName='HostAndAllServices'
    )]
    [Parameter(
        Mandatory,
        ValueFromPipeline,
        ParameterSetName='Service'
    )]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $Host ,

    [Parameter(
        Mandatory,
        ParameterSetName='Service'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias('Svc')]
    [String[]]
    $Service ,

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
        $data_base = @{}
        switch ($PSCmdlet.ParameterSetName)
        {
            'ByDowntimeID' {
                foreach($down_id in $DowntimeId) {
                    $params.Command = [IcingaCommand]::CMD_DEL_SVC_DOWNTIME
                    $params.Data = $data_base.Clone()
                    $params.Data.down_id = $down_id

                    Write-Verbose "Deleting downtime ID '$down_id'."

                    Invoke-IcingaCommand @params
                }
            }

            'HostAndAllServices' { 
                foreach($hostname in $Host) {
                    $params.Command = [IcingaCommand]::CMD_DEL_DOWNTIME_BY_HOST_NAME
                    $params.Data = $data_base.Clone()
                    $params.Data.host = $hostname

                    Write-Verbose "Deleting downtime for host '$hostname' and all of its services."

                    Invoke-IcingaCommand @params
                }
            }

            'Service' { 
                foreach($hostname in $Host) {
                    $downs = Get-IcingaDowntime @params 
                    foreach($svc in $Service) {
                        $down_id = $downs | Where-Object { 
                            $_.host_name -ieq $hostname -and
                            $_.service_description -ieq $svc
                        } | Select-Object -ExpandProperty downtime_id
                        if (!$down_id) {
                            throw [System.InvalidOperationException]"No downtime found for '$svc' on '$hostname'."
                        }

                        Write-Verbose "Deleting downtime for service '$svc' on host '$hostname'."

                        Stop-IcingaDowntime @params -DowntimeId $down_id
                    }
                }
            }
            default { throw [System.NotImplementedException]"Error in function definition. This should never have happened. ParameterSet: $($PSCmdlet.ParameterSetName)" }
        }
    }
}

function Add-IcingaAcknowledgement {
[CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='Host')]
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
        ParameterSetName='Service'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='ServiceExpireDuration'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='ServiceExpireEnd'
    )]
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
    [Switch]
    $Persistent ,

    [Parameter()]
    [Switch]
    $Sticky ,

    [Parameter()]
    [Switch]
    $Notfy ,

    [Parameter(
        Mandatory,
        ParameterSetName='HostExpireDuration'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='ServiceExpireDuration'
    )]
    [ValidateScript( { $_ | ProcessDuration -Verify } )]
    [Alias('EndAfter')]
    [Alias('For')]
    [String]
    $Duration ,

    [Parameter(
        Mandatory,
        ParameterSetName='HostExpireEnd'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='ServiceExpireEnd'
    )]
    [Alias('end_time')]
    [Alias('EndAt')]
    [Alias('End')]
    [DateTime]
    $EndTime ,

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
            $recurser.EndTime = ProcessDuration -StartTime ([DateTime]::Now) -Duration $Duration
            Add-IcingaAcknowledgement @recurser
            return
        }
        if ($EndTime -and $EndTime -le [DateTime]::Now) {
            throw [System.ArgumentException]"EndTime must be in the future."
        }
        $data_base = @{
            com_data = $Comment
        }
        if ($Persistent) {
            $data_base.persistent = 'on'
        }
        if ($EndTime) {
            $data_base.use_ack_end_time = 'on'
            $data_base.end_time = $EndTime | ConvertToIcingaDateTime
        }
        if ($Sticky) {
            $data_base.sticky_ack = 'on'
        }
        if ($Notfy) {
            $data_base.send_notification = 'on'
        }
        $params.Command = switch -Wildcard ($PSCmdlet.ParameterSetName)
        {
            'Host*' {
                [IcingaCommand]::CMD_ACKNOWLEDGE_HOST_PROBLEM
            }
            'HostExpireEnd' {
                # [IcingaCommand]::CMD_ACKNOWLEDGE_HOST_PROBLEM_EXPIRE

            }
            'Service*' {
                [IcingaCommand]::CMD_ACKNOWLEDGE_SVC_PROBLEM
            }
            'ServiceExpireEnd' {
                # [IcingaCommand]::CMD_ACKNOWLEDGE_SVC_PROBLEM_EXPIRE
            }
            default { throw [System.NotImplementedException]"Error in function definition. This should never have happened. ParameterSet: $($PSCmdlet.ParameterSetName)" }
        }
        foreach ($hostname in $Host) {
            $params.Data = $data_base.Clone()
            if ($Service) {
                foreach($svc in $Service) {
                    $params.Data.hostservice = "$hostname^$svc"

                    Write-Verbose -Message "Acknowleding problem for '$svc' on '$hostname'."

                    Invoke-IcingaCommand @params
                }
            } else {
                $params.Data.host = $hostname

                Write-Verbose -Message "Acknowleding problem for host '$hostname'."

                Invoke-IcingaCommand @params
            }
        }
    }
}

function Remove-IcingaAcknowledgement {
[CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='Host')]
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
        ParameterSetName='Service'
    )]
    [String[]]
    $Service ,

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
        $data_base = @{}
        foreach($hostname in $Host) {
            if ($PSCmdlet.ParameterSetName -eq 'Service') {
                $params.Command = [IcingaCommand]::CMD_REMOVE_SVC_ACKNOWLEDGEMENT
                $params.Data = $data_base.Clone()
                foreach ($svc in $Service) {
                    $params.Data.hostservice = "$hostname^$svc"
                    
                    Write-Verbose -Message "Removing service acknowledgement for '$svc' on '$hostname'."
                    
                    Invoke-IcingaCommand @params 
                }
            } else {
                $params.Command = [IcingaCommand]::CMD_REMOVE_HOST_ACKNOWLEDGEMENT
                $params.Data = $data_base.Clone()
                $params.Data.host = $hostname

                Write-Verbose -Message "Removing host acknowledgement for '$hostname'."

                Invoke-IcingaCommand @params
            }
        }
    }
}

function Submit-IcingaCheckResult {
[CmdletBinding(SupportsShouldProcess,DefaultParameterSetName='Host')]
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
        ParameterSetName='Service'
    )]
    [ValidateNotNullOrEmpty()]
    [Alias('Svc')]
    [String[]]
    $Service ,
    
<#    [Parameter(
        Mandatory,
        ParameterSetName='Host'
    )]
    [Parameter(
        Mandatory,
        ParameterSetName='Service'
    )]
    [int]
    [Alias('plugin_state')]
    $CheckResult ,
#>

    [Parameter(
        Mandatory
    )]
    [ValidateNotNullOrEmpty()]
    [Alias('plugin_output')]
    [String]
    $CheckOutput ,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [Alias('performance_data')]
    [String]
    $PerformanceData ,

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
            Data = @{
                plugin_result = $CheckResult
                plugin_output = $CheckOutput
            }
        }
        if ($Credential) {
            $params.Credential = $Credential
        }
    }

    DynamicParam {            
                    
        # For blog width...            
        # As you can see - also abusing splatting.            
        # Here - to pass positional parameter TypeName            
            
        $Type = @(            
            'Management.Automation.ParameterAttribute'            
        )            
        $Attributes = New-Object @Type            
        $Attributes.ParameterSetName = "__AllParameterSets"            
        $Attributes.Mandatory = $true  
        $Type = @(            
            'Collections.ObjectModel.Collection[Attribute]'            
        )            
        $AttributeCollection = New-Object @Type            
        $AttributeCollection.Add($Attributes)
        $AttributeCollection.Add((New-Object System.Management.Automation.AliasAttribute -ArgumentList @('plugin_state')))

        Write-Verbose $PSCmdlet.ParameterSetName -Verbose

        $DataType = switch ($PSCmdlet.ParameterSetName)
        {
            'Host' { [IcingaHostCheckResult] }
            'Service' { [IcingaServiceCheckResult] }
        }

        $MyParameter = @{            
            TypeName = 'Management.Automation.RuntimeDefinedParameter'            
            ArgumentList = @(            
                'CheckResult' <# name #>            
                $DataType <# ParameterType #>            
                , $AttributeCollection <# Attributes #>            
            )            
        }            
        $Dynamic = New-Object @MyParameter            
                        
        $Type = @(            
            'Management.Automation.RuntimeDefinedParameterDictionary'            
        )            
        $ParamDictionary = New-Object @Type            
        $ParamDictionary.Add("CheckResult", $Dynamic)            
        $ParamDictionary            
    }

    Process {
        foreach($hostname in $Host) {
            if ($Service) {
                $params.Command = [IcingaCommand]::CMD_PROCESS_SERVICE_CHECK_RESULT
                foreach($svc in $Service) {
                    Write-Verbose "Sending Service Check Result '$svc' on '$hostname'"
                    $params.Data.hostservice = "$hostname^$svc"
                    if ($PerformanceData) {
                        $params.Data.performance_data = $PerformanceData
                    }
                    Invoke-IcingaCommand @params
                }
            } else {
                $params.Command = [IcingaCommand]::CMD_PROCESS_HOST_CHECK_RESULT
                Write-Verbose "Sending Host Check Result for '$hostname'"
                $params.Data.host = $hostname
                if ($PerformanceData) {
                    $params.Data.performance_data = $PerformanceData
                }
                Invoke-IcingaCommand @params
            }
        }
    }
}


AddIcingaEnum -Definition @(
    (NewIcingaCheckStateEnumDefinition)
    (NewIcingaCmdEnumDefinition)
    (NewIcingaHostChildOptionsEnumDefinition)
    (NewIcingaHostCheckResultEnumDefinition)
    (NewIcingaServiceCheckResultEnumDefinition)
)

AddSSLValidator

New-Alias -Name Confirm-IcingaProblem -Value Add-IcingaAcknowledgement

Export-ModuleMember -Function *-* -Alias *-*

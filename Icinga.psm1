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
<#
function Submit-IcingaCustomHostNotification {
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
    [ValidateNotNullOrEmpty()]
    [String]
    $Host ,

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
    $params = @{
        IcingaUrl = $IcingaUrl
        SkipSslValidation = $SkipSslValidation
        Command = [IcingaCommand]::CMD_SEND_CUSTOM_HOST_NOTIFICATION
    }
    if ($Credential) {
        $params.Credential = $Credential
    }
    $params.Data = @{
        host = $Host
        com_data = $Comment
    }
    Invoke-IcingaCommand @params
}

#>
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
    [Alias('SVC')]
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

function Start-IcingaCustomHostNotification {
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
    [ValidateNotNullOrEmpty()]
    [String]
    $Host ,

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
    $params = @{
        IcingaUrl = $IcingaUrl
        SkipSslValidation = $SkipSslValidation
        Command = [IcingaCommand]::CMD_SEND_CUSTOM_HOST_NOTIFICATION
    }
    if ($Credential) {
        $params.Credential = $Credential
    }
    $params.Data = @{
        host = $Host
        com_data = $Comment
    }
    Invoke-IcingaCommand @params
}

AddIcingaEnum -Definition @((NewIcingaCheckStateEnumDefinition),(NewIcingaCmdEnumDefinition))
AddSSLValidator

Export-ModuleMember -Function *-*

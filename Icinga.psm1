﻿#Requires -Version 4.0

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
    Write-Verbose $nvc.GetType()
    foreach($h in $Hash.GetEnumerator()) {
        $nvc.Add($h.Key, $h.Value.ToString()) | Out-Null
    }
    Write-Verbose $nvc.GetType()
    Write-Verbose $nvc[0]
    Write-Verbose $nvc
    Write-Output -InputObject $nvc
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
        $client.UploadValues([Uri]$Uri, [System.Collections.Specialized.NameValueCollection]$data)
    } finally {
        if ($SkipSslValidation) {
            [SSLValidator]::RestoreValidation()
        }
    }
}

function Invoke-IcingaCommand {
[CmdletBinding()]
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
    $params = @{
        Uri = [Uri]($IcingaUrl | JoinUri -ChildPath '/cgi-bin/cmd.cgi')
        Body = $Data
        SkipSslValidation = $SkipSslValidation
    }
    if ($Credential) {
        $params['Credential'] = $Credential
    }
    InvokeCustomPostRequest @params
}

AddIcingaEnum -Definition @((NewIcingaCheckStateEnumDefinition),(NewIcingaCmdEnumDefinition))
AddSSLValidator

#Export-ModuleMember -Function *-*
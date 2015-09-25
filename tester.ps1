Import-Module ([IO.Path]::Combine($PSScriptRoot,'Icinga')) -Force

if (!$cred) {
    $cred = Get-Credential
}

$PSDefaultParameterValues = @{
    "*-Icinga*:IcingaUrl" = 'https://it-icinga01.cshl.edu/icinga/'
    "*-Icinga*:SkipSslValidation" = $true
    "*-Icinga*:Credential" = $cred
    "*-Icinga*:Verbose" = $true
}

#return

<#
#Start-IcingaDowntime -Host radar -Comment 'test' -StartTime (Get-Date).AddSeconds(-30) -Duration 5m -Service Ping,"Disk Usage","Remote Desktop"


do { 
    Start-Sleep -Seconds 1 
    Write-Verbose "Checking for downtime." -Verbose
} until (Get-IcingaDowntime -Verbose:$false | ? { $_.host_name -ieq 'radar' })

Read-Host

Stop-IcingaDowntime -Host radar -Service "Disk Usage"
#>

Confirm-IcingaProblem -Host sidv -Service HTTP -Comment "testing module" -Duration 1m -Notfy
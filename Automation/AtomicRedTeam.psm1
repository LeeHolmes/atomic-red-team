## Create the directory for invocation proofs
if(-not (Test-Path $env:TEMP\AtomicRedTeam))
{
    $null = New-Item -Type Directory $env:TEMP\AtomicRedTeam
}

## Register for cleanup
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    Remove-Item $env:TEMP\AtomicRedTeam -Recurse
}

$actions = @{
    'Windows/Execution/BitsAdmin' = {

        ## Extract the command from the page
        $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Execution/BitsAdmin.md -SectionName bitsadmin.exe

        ## Launch the action
        Invoke-Expression $commands[0]
    }
    
    'Windows/Execution/Trusted_Developer_Utilities/MSBuild' = {

        ## Extract the command from the page
        $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Execution/Trusted_Developer_Utilities.md -SectionName msbuild.exe
        $commandToInvoke,$commandArgs = $commands[0] -split ' '

        ## Run it, but with the real MSBuildBypass we've got in /Windows/Payloads
        & $commandToInvoke ..\Windows\Payloads\MSBuildBypass.csproj
    }

    'Windows/Lateral_Movement/Remote_Desktop_Protocol_Hijack' = {

        ## Extract the command from the page
        $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Lateral_Movement/Remote_Desktop_Protocol.md -SectionName 'RDP hijacking'

        ## Launch the actions
        foreach($command in $commands)
        {
            Invoke-Expression $command 2>&1
        }
    }

    'Windows/Defense_Evasion/Indicator_Removal_on_Host/System' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to clear the System log?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Indicator_Removal_on_Host.md -SectionName 'wevtutil' |
                Where-Object { $_ -match 'System' }
                           
            ## Launch the action
            Invoke-Expression $commands[0]
        }
    }
    
    'Windows/Defense_Evasion/Indicator_Removal_on_Host/Security' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to clear the Security log?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Indicator_Removal_on_Host.md -SectionName 'wevtutil'

            ## Launch the action
            Invoke-Expression $commands[1]
        }
    }

    'Windows/Defense_Evasion/Indicator_Removal_on_Host/Setup' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to clear the Setup log?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Indicator_Removal_on_Host.md -SectionName 'wevtutil'
               
            ## Launch the action
            Invoke-Expression $commands[2]
        }
    }
    
    'Windows/Defense_Evasion/Indicator_Removal_on_Host/Application' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to clear the Application log?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Indicator_Removal_on_Host.md -SectionName 'wevtutil'
               
            ## Launch the action
            Invoke-Expression $commands[3]
        }
    }
        
    'Windows/Defense_Evasion/Indicator_Removal_on_Host/Stop_Event_Logs' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to stop Event Logs?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Indicator_Removal_on_Host.md -SectionName 'wevtutil' 
            
            ## Launch the action
            Invoke-Expression $commands[4]
        }
    }

    'Windows/Defense_Evasion/Disabling_Security_Tools/Disable_Firewall' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to disable Windows Firewall?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Disable Firewall' 
            
            ## Launch the action
            Invoke-Expression $commands[0]
        }
    }

    
    'Windows/Defense_Evasion/Disabling_Security_Tools/Stop_Windows_Security_Center' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to stop Windows Security Center?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Stop Windows Security Center' 
            
            ## Launch the action
            Invoke-Expression $commands[0]
        }
    }
    
    'Windows/Defense_Evasion/Disabling_Security_Tools/Stop_Windows_Defender/DisableRealtimeMonitoring' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to Disable Realtime Monitoring?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Windows 10' 
            
            ## Launch the action
            Invoke-Expression $commands[0]
        }
    }
    
    'Windows/Defense_Evasion/Disabling_Security_Tools/Stop_Windows_Defender/DisableIOAVProtection' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to Disable IO AV Protection?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Windows 10' 
            
            ## Launch the action
            Invoke-Expression $commands[1]
        }
    }
    
    'Windows/Defense_Evasion/Disabling_Security_Tools/Stop_Windows_Defender/DisableBehaviorMonitoring' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to Disable Behavior Monitoring?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Windows 10' 
            
            ## Launch the action
            Invoke-Expression $commands[2]
        }
    }
    
    'Windows/Defense_Evasion/Disabling_Security_Tools/Stop_Windows_Defender/DisableIntrusionPreventionSystem' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to Disable Intrusion Prevention System?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Windows 10' 
            
            ## Launch the action
            Invoke-Expression $commands[3]
        }
    }
    
    'Windows/Defense_Evasion/Disabling_Security_Tools/Stop_Windows_Defender/DisablePrivacyMode' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to Disable Privacy Mode?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Windows 10' 
            
            ## Launch the action
            Invoke-Expression $commands[4]
        }
    }
    
    'Windows/Defense_Evasion/Disabling_Security_Tools/Stop_Windows_Defender/Windows 7/8' = {

        if($Force -or $PSCmdlet.ShouldContinue("Do you wish to Disable Privacy Mode?", "Confirm impactful change"))
        {
            ## Extract the command from the page
            $commands = Get-ActionCode -Path $PSScriptRoot/../Windows/Defense_Evasion/Disabling_Security_Tools.md -SectionName 'Windows 7/8' 
            
            ## Launch the action
            Invoke-Expression $commands[0]
        }
    }
    
}

function Get-ActionCode
{
    param($Path, $SectionName)

    $sections = Get-Content $Path -Delimiter '###'
    ,@($sections |
        Where-Object { $_ -like "*$SectionName*" } |
        Select-String "    (.*)" -AllMatches |
        ForEach-Object { $_.Matches.Captures.Value.Trim() })
}

function Invoke-Action
{
    param(
        [Parameter(Mandatory, Position = 0)]
        $Action,

        [Parameter()]
        [Switch] $Force       
    )

    $Action = $Action -replace "\\","/"

    foreach($possibleAction in $actions.Keys)
    {
        if($possibleAction -like $Action)
        {
            $actionCode = $actions[$possibleAction]
            & $actionCode
        }
    }
    
}

function Get-Action
{
    param(
        [Parameter(Position = 0)]
        $Action = "*"
    )

    $Action = $Action -replace "\\","/"

    foreach($possibleAction in $actions.Keys)
    {
        if($possibleAction -like $Action)
        {
            $possibleAction
        }
    }
    
}

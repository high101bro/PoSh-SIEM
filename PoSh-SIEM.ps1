<#
    .Description

    PoSh-SEIM ...if you like this, check out Posh-EasyWin!
    Want a way to view sysmon logs with Pure PowerShell and easily view them with Out-GridView?!?!? Well, here you go.

    Author:    Dan Komnick (high101bro)
    Co-Author: Cole VanLandingham
    Date:      28 April 2022
    Credits:   Based on & inspired by IPSec's Power-SEIM

    .Link
    https://github.com/high101bro/PoSh-SEIM
#>

param(
    [switch]$Verbose,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Check
)

if (-not $Start -and -not $Stop -and -not $Check) {
    Write-Host "`n[!] " -ForegroundColor Red -NoNewline
    Write-Host "...hey pal, you want to use one of the switches!" -ForegroundColor Yellow
    Write-Host "`n[!] " -ForegroundColor Red -NoNewline
    Write-Host ".\PoSh-SIEM.ps1 -Start`n" -ForegroundColor Yellow
}

if ($Start) {
    
    $Running = Get-Job -Name "high101bro" -ErrorAction SilentlyContinue

    if (-not $Running) {
        Start-Job -ScriptBlock {

            $ErrorActionPreference = "SilentlyContinue"

            Function Parse-Event {
                # Credit: https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-WinEventData.ps1
                param(
                    [Parameter(ValueFromPipeline=$true)] $Event
                )

                Process
                {
                    foreach($entry in $Event)
                    {
                        $XML = [xml]$entry.ToXml()
                        $X = $XML.Event.EventData.Data
                        For( $i=0; $i -lt $X.count; $i++ ){
                            $Entry = Add-Member -InputObject $entry -MemberType NoteProperty -Name "$($X[$i].name)" -Value $X[$i].'#text' -Force -Passthru
                        }
                        $Entry
                    }
                }
            }

            Function Write-Alert {
                param(
                    $alerts
                )
                $alerts | Select-Object -Property TimeCreated, *
            }

            $LogName = "Microsoft-Windows-Sysmon"

            $index =  (Get-WinEvent -Provider "Microsoft-Windows-Sysmon" -max 1).RecordID
            while ($true)
            {
                Start-Sleep 1

                $NewIndex = (Get-WinEvent -Provider $LogName -max 1).RecordID

                if ($NewIndex -gt $Index) {
                    # We Have New Events.
                    $logs =  Get-WinEvent -provider $LogName -max ($NewIndex - $index) | Sort-Object RecordID
                    foreach($log in $logs) {
                        $evt = $log | Parse-Event

            <#
                        if ($evt.id -eq 1) {
                            $output = @{}
                            $output.add("Type", "Process Create")
                            $output.add("PID", $evt.ProcessId)
                            $output.add("Image", $evt.Image)
                            $output.add("CommandLine", $evt.CommandLine)
                            $output.add("CurrentDirectory", $evt.CurrentDirectory)
                            $output.add("User", $evt.User)
                            $output.add("ParentImage", $evt.ParentImage)
                            $output.add("ParentCommandLine", $evt.ParentCommandLine)
                            $output.add("ParentUser", $evt.ParentUser)
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 2) {
                            $output = @{}
                            $output.add("Type", "File Creation Time Changed")
                            $output.add("PID", $evt.ProcessId)
                            $output.add("Image", $evt.Image)
                            $output.add("TargetFilename", $evt.TargetFileName)
                            $output.add("CreationUtcTime", $evt.CreationUtcTime)
                            $output.add("PreviousCreationUtcTime", $evt.PreviousCreationUtcTime)
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 3) {
                            $output = @{}
                            $output.add("Type", "Network Connection")
                            $output.add("Image", $evt.Image)
                            $output.add("DestinationIp", $evt.DestinationIp)
                            $output.add("DestinationPort", $evt.DestinationPort)                           
                            $output.add("DestinationHost", $evt.DestinationHostname)
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
            #>
                        if ($evt.id -eq 5) {
                            # high101bro, "Nope, I think a pscustomobject would be better to use..."
                            #$output = @{}
                            #$output.add("Type", "Process Ended")
                            #$output.add("TimeCreated", $evt.TimeCreated)
                            #$output.add("PID", $evt.ProcessId)
                            #$output.add("Image", $evt.Image)
                
                            # high101bro, "I want a pscustom object..."
                            $output = [pscustomobject]@{
                                Type        = 'Process Ended'
                                TimeCreated = $evt.TimeCreated
                                PID         = $evt.ProcessId
                                Image       = $evt.Image
                            }           
                            Write-Alert $output
                            if ($Verbose) {$evt | Select *}
                        }
            <#
                        if ($evt.id -eq 6) {
                            $output = @{}
                            $output.add("Type", "Driver Loaded")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 7) {
                            $output = @{}
                            $output.add("Type", "DLL Loaded By Process")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 8) {
                            $output = @{}
                            $output.add("Type", "Remote Thread Created")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 9) {
                            $output = @{}
                            $output.add("Type", "Raw Disk Access")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 10) {
                            $output = @{}
                            $output.add("Type", "Inter-Process Access")
                            # ($evt | Select-Object -ExpandProperty message).split("`n") | ForEach-Object {
                            #     $key   = $_.split(":")[0]
                            #     $value = $_.split(":")[1..$($_.split(":").length-1)] -join ':'
                            #     if ($key -eq 'SourceImage') {$output.add($key,$value)}
                            #     if ($key -eq 'TargetImage') {$output.add($key,$value)}
                            # }
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 11) {
                            $output = @{}
                            $output.add("Type", "File Create")
                            $output.add("RecordID", $evt.RecordID)
                            $output.add("TargetFilename", $evt.TargetFileName)
                            $output.add("User", $evt.User)
                            $output.add("Process", $evt.Image)
                            $output.add("PID", $evt.ProcessID)                
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 12) {
                            $output = @{}
                            $output.add("Type", "Registry Added or Deleted")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 13) {
                            $output = @{}
                            $output.add("Type", "Registry Set")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 14) {
                            $output = @{}
                            $output.add("Type", "Registry Object Renamed")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 15) {
                            $output = @{}
                            $output.add("Type", "ADFS Created")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 16) {
                            $output = @{}
                            $output.add("Type", "Sysmon Configuration Change")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 17) {
                            $output = @{}
                            $output.add("Type", "Pipe Created")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 18) {
                            $output = @{}
                            $output.add("Type", "Pipe Connected")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 19) {
                            $output = @{}
                            $output.add("Type", "WMI Event Filter Activity")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 20) {
                            $output = @{}
                            $output.add("Type", "WMI Event Consumer Activity")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 21) {
                            $output = @{}
                            $output.add("Type", "WMI Event Consumer To Filter Activity")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 22) {
                            $output = @{}
                            $output.add("Type", "DNS Query")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 23) {
                            $output = @{}
                            $output.add("Type", "File Delete")
                            $output.add("RecordID", $evt.RecordID)
                            $output.add("TargetFilename", $evt.TargetFileName)
                            $output.add("User", $evt.User)
                            $output.add("Process", $evt.Image)
                            $output.add("PID", $evt.ProcessID)                
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 24) {
                            $output = @{}
                            $output.add("Type", "Clipboard Event Monitor")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 25) {
                            $output = @{}
                            $output.add("Type", "Process Tamper")
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
                        if ($evt.id -eq 26) {
                            $output = @{}
                            $output.add("Type", "File Delete Logged")
                            $output.add("RecordID", $evt.RecordID)
                            $output.add("TargetFilename", $evt.TargetFileName)
                            $output.add("User", $evt.User)
                            $output.add("Process", $evt.Image)
                            $output.add("PID", $evt.ProcessID)                
                            write-alert $output
                            if ($Verbose) {$evt | Select *}
                        }
            #>            
                    }
                    $index = $NewIndex
                }
            }
        } -Name "high101bro"
        
        Write-Host "`n[!] " -ForegroundColor Red -NoNewline
        Write-Host "...PoSh-SIEM has started as a background job..." -ForegroundColor Yellow

    }

    Write-Host "`n[!] " -ForegroundColor Red -NoNewline
    Write-Host "PoSh-SIEM is outputting sysmon logs to Out-GridView, happy hunting..." -ForegroundColor Yellow
    Write-Host "`n[!] " -ForegroundColor Red -NoNewline
    Write-Host "Trouble? Try running the script with elevated permissions..." -ForegroundColor Yellow
    Write-Host "`n[!] " -ForegroundColor Green -NoNewline
    Write-Host "Pro Tip... Make sure to sort by the top TimeCreated column to keep the most recent alerts at the top!`n" -ForegroundColor Yellow

    Get-Job -Name "high101bro" | Receive-Job -Wait | Select-Object * -ExcludeProperty RunspaceId, PSSourceJobInstanceId | Out-GridView -Title "PowerSiem - Powered by high101bro!"
}

if ($Stop) {
    $StopStatus = Get-Job -Name "high101bro" -ErrorAction SilentlyContinue

    if ( $StopStatus ) {
        Write-Host "`n[!] " -ForegroundColor Red -NoNewline
        Write-Host "PoSh-SIEM is is stopping...`n" -ForegroundColor Yellow

        $StopStatus | Remove-Job -Force -ErrorAction SilentlyContinue

        Get-Job -Name "high101bro" -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "`n[!] " -ForegroundColor Red -NoNewline
        Write-Host "PoSh-SIEM is not running as a background job...`n" -ForegroundColor Yellow
    }    
}

if ($Check) {
    $CheckStatus = Get-Job -Name "high101bro" -ErrorAction SilentlyContinue

    if ( $CheckStatus ) {
        $CheckStatus
    }
    else {
        Write-Host "`n[!] " -ForegroundColor Red -NoNewline
        Write-Host "PoSh-SIEM is not running as a background job...`n" -ForegroundColor Yellow        
    }
}



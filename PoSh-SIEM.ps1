
Start-Job -ScriptBlock {
    & "C:\Users\danie\Documents\GitHub\PoSh-EasyWin\DevOps\PowerSIEM.ps1"
} -Name "high101bro"

Get-Job -Name "high101bro" | Receive-Job -Wait | Out-GridView -Title "PowerSiem - Powered by high101bro!"

& "C:\Users\danie\Documents\GitHub\PoSh-EasyWin\DevOps\PowerSIEM.ps1"
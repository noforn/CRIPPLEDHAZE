# Run from inside the DocShare ISO folder (same cwd model as cr.ps1 / newIMG.ps1).
$ErrorActionPreference = 'Stop'
$IsoRoot = (Get-Location).ProviderPath
$Stamp   = Get-Date "2026-05-12 14:30:00"

Write-Host "[*] ISO root: $IsoRoot"

$stampPaths = @(
    (Join-Path $IsoRoot 'Microsoft')
    (Join-Path $IsoRoot 'Microsoft\DocShare.ps1')
    (Join-Path $IsoRoot 'Shared Documents')
    (Join-Path $IsoRoot 'Shared Documents\Agenda_15-19_6-2026.pdf')
    (Join-Path $IsoRoot 'Agenda_15-19_6-2026.pdf.lnk')
)

$hidePaths = @(
    (Join-Path $IsoRoot 'Microsoft')
    (Join-Path $IsoRoot 'Microsoft\DocShare.ps1')
    (Join-Path $IsoRoot 'Shared Documents')
    (Join-Path $IsoRoot 'Shared Documents\Agenda_15-19_6-2026.pdf')
)

foreach ($path in $stampPaths) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing: $path (cd into ISO folder and run cr.ps1 first)"
    }
}

foreach ($path in $stampPaths) {
    Get-Item -LiteralPath $path -Force | ForEach-Object {
        $_.CreationTime   = $Stamp
        $_.LastWriteTime  = $Stamp
        $_.LastAccessTime = $Stamp
    }
    if ((Get-Item -LiteralPath $path -Force).PSIsContainer) {
        Get-ChildItem -LiteralPath $path -Recurse -Force | ForEach-Object {
            $_.CreationTime   = $Stamp
            $_.LastWriteTime  = $Stamp
            $_.LastAccessTime = $Stamp
        }
    }
}

foreach ($path in $hidePaths) {
    Get-Item -LiteralPath $path -Force | ForEach-Object {
        $_.Attributes = 'Hidden', 'System'
    }
    if ((Get-Item -LiteralPath $path -Force).PSIsContainer) {
        Get-ChildItem -LiteralPath $path -Recurse -Force | ForEach-Object {
            $_.Attributes = 'Hidden', 'System'
        }
    }
}

Write-Host "[+] stamped + hidden (lnk left visible): $IsoRoot"

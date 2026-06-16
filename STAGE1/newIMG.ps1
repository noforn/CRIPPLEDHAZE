# newIMG
#
# run from inside folder, dont copy .ps1 into folder!
#

[CmdletBinding()]
param(
    [string]$OutFile    = 'C:\temp\DocShare.img',
    [string]$VolumeName = 'DocShare'
)

$ErrorActionPreference = 'Stop'

$SourcePath = (Get-Location).ProviderPath
Write-Host "[*] Packing ISO from: $SourcePath"
$OutDir = Split-Path -Parent $OutFile
if ($OutDir -and -not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

if (Test-Path -LiteralPath $OutFile) {
    Write-Host "[-] Removing old image"
    Remove-Item -LiteralPath $OutFile -Force
}

if (-not ('ISOHelper.Writer' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
namespace ISOHelper {
  public static class Writer {
    public static void Write(object comStream, string file) {
      IStream s = (IStream)comStream;
      using (var fs = File.OpenWrite(file)) {
        byte[] buf = new byte[1048576];
        IntPtr cbRead = Marshal.AllocCoTaskMem(4);
        try {
          int read;
          do {
            s.Read(buf, buf.Length, cbRead);
            read = Marshal.ReadInt32(cbRead);
            if (read > 0) fs.Write(buf, 0, read);
          } while (read == buf.Length);
        } finally {
          Marshal.FreeCoTaskMem(cbRead);
        }
      }
    }
  }
}
'@
}

$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = 3 
$fsi.VolumeName = $VolumeName
$fsi.FreeMediaBlocks = 0

$fsi.Root.AddTree($SourcePath, $false)

$result = $fsi.CreateResultImage()
[ISOHelper.Writer]::Write($result.ImageStream, $OutFile)

$size = (Get-Item -LiteralPath $OutFile).Length
Write-Host ("[+] Created: {0} ({1:N1} MB)" -f $OutFile, ($size / 1MB))
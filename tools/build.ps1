param(
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$bootstrap = Join-Path $root 'wp-encrypted-fields.php'

if (-not $Version) {
    $match = Select-String -LiteralPath $bootstrap -Pattern '^\s*\*\s*Version:\s*([0-9][0-9A-Za-z\.\-]*)'
    if (-not $match) {
        throw 'Could not read the plugin Version header.'
    }
    $Version = $match.Matches[0].Groups[1].Value
}

$include = @(
    'src',
    'config',
    'wp-encrypted-fields.php',
    'uninstall.php',
    'readme.txt',
    'README.md',
    'CHANGELOG.md',
    'LICENSE'
)

$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('kec-build-' + [guid]::NewGuid().ToString('N'))
$target = Join-Path $stageRoot 'wp-encrypted-fields'
$dist = Join-Path $root 'dist'
$zip = Join-Path $dist "wp-encrypted-fields-$Version.zip"

New-Item -ItemType Directory -Path $target -Force | Out-Null
New-Item -ItemType Directory -Path $dist -Force | Out-Null

foreach ($item in $include) {
    $source = Join-Path $root $item
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing package file: $item"
    }
    Copy-Item -LiteralPath $source -Destination $target -Recurse -Force
}

if (Test-Path -LiteralPath $zip) {
    Remove-Item -LiteralPath $zip -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::Open($zip, [System.IO.Compression.ZipArchiveMode]::Create)
$basePath = (Resolve-Path -LiteralPath $target).Path
Get-ChildItem -LiteralPath $target -Recurse -File -Force | ForEach-Object {
    $relative = $_.FullName.Substring($basePath.Length + 1).Replace('\', '/')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $_.FullName, ('wp-encrypted-fields/' + $relative), [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
}
$archive.Dispose()

Add-Type -AssemblyName System.IO.Compression.FileSystem

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
$count = $archive.Entries.Count
$leaked = @($archive.Entries | Where-Object {
    $_.FullName -match '^wp-encrypted-fields/(tests|docs|\.git|\.github)/' -or
    $_.FullName -match '(phpunit\.xml|composer\.json|composer\.lock)$'
})
$archive.Dispose()

Remove-Item -LiteralPath $stageRoot -Recurse -Force

if ($leaked.Count -gt 0) {
    throw ('Unexpected files in package: ' + ($leaked.FullName -join ', '))
}

Write-Output "Built $zip ($count entries, version $Version)"


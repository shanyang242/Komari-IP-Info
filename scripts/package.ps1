$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $projectRoot "komari-plugin.json"
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
$distDir = Join-Path $projectRoot "dist"
$stageDir = Join-Path $projectRoot ".package-stage"
$zipPath = Join-Path $distDir ("komari-ip-info-v" + $manifest.version + ".zip")

if (Test-Path -LiteralPath $stageDir) {
  Remove-Item -Recurse -Force -LiteralPath $stageDir
}
New-Item -ItemType Directory -Path $stageDir | Out-Null
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

Copy-Item -LiteralPath $manifestPath -Destination $stageDir
Copy-Item -LiteralPath (Join-Path $projectRoot "script.js") -Destination $stageDir
Copy-Item -LiteralPath (Join-Path $projectRoot "README.md") -Destination $stageDir
Copy-Item -LiteralPath (Join-Path $projectRoot "LICENSE") -Destination $stageDir
Copy-Item -LiteralPath (Join-Path $projectRoot "CHANGELOG.md") -Destination $stageDir

if (Test-Path -LiteralPath $zipPath) {
  Remove-Item -Force -LiteralPath $zipPath
}
Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal
Remove-Item -Recurse -Force -LiteralPath $stageDir

Write-Host "Created $zipPath"

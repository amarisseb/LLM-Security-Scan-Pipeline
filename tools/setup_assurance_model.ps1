# Optional Windows CPU-only local lab. Downloads stay inside this checkout.
# No administrator installation, API key, provider account or Docker required.
$ErrorActionPreference = 'Stop'
$arisecRoot = Split-Path -Parent $PSScriptRoot
$arisecDestination = Join-Path $arisecRoot '.venv\assurance-model'
New-Item -ItemType Directory -Path $arisecDestination -Force | Out-Null
$arisecRuntimeUrl = 'https://github.com/ggml-org/llama.cpp/releases/download/b12651/llama-b12651-bin-win-cpu-x64.zip'
$arisecRuntimeHash = 'b2d794fa7587aba29f654d717ff9b73e31caeabf50a7766692903008bbe0855d'
$arisecArchive = Join-Path $arisecDestination 'llama-b12651-bin-win-cpu-x64.zip'
if (-not (Test-Path -LiteralPath $arisecArchive)) {
    Write-Output 'Downloading the official llama.cpp CPU runtime (about 25 MB).'
    Invoke-WebRequest -Uri $arisecRuntimeUrl -OutFile $arisecArchive -TimeoutSec 180
}
if ((Get-FileHash -LiteralPath $arisecArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $arisecRuntimeHash) {
    throw 'Runtime checksum mismatch. The archive has not been extracted.'
}
$arisecBin = Join-Path $arisecDestination 'runtime'
if (-not (Test-Path -LiteralPath $arisecBin)) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $arisecZip = [IO.Compression.ZipFile]::OpenRead($arisecArchive)
    try {
        $arisecAllowed = [IO.Path]::GetFullPath($arisecBin) + [IO.Path]::DirectorySeparatorChar
        foreach ($arisecEntry in $arisecZip.Entries) {
            $arisecResolved = [IO.Path]::GetFullPath((Join-Path $arisecBin $arisecEntry.FullName))
            if (-not $arisecResolved.StartsWith($arisecAllowed, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Unexpected archive path.'
            }
        }
    } finally { $arisecZip.Dispose() }
    Expand-Archive -LiteralPath $arisecArchive -DestinationPath $arisecBin
}
$arisecModelName = 'Qwen3-0.6B-Q8_0.gguf'
$arisecModelRevision = '23749fefcc72300e3a2ad315e1317431b06b590a'
$arisecModelHash = '9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031'
$arisecModelFile = Join-Path $arisecDestination $arisecModelName
$arisecModelUrl = 'https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/' + $arisecModelRevision + '/' + $arisecModelName
if (-not (Test-Path -LiteralPath $arisecModelFile)) {
    Write-Output 'Downloading the official Qwen3 0.6B Q8 model (about 640 MB).'
    Invoke-WebRequest -Uri $arisecModelUrl -OutFile $arisecModelFile -TimeoutSec 600
}
if ((Get-FileHash -LiteralPath $arisecModelFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $arisecModelHash) {
    throw 'Model checksum mismatch. Do not start the model.'
}
[ordered]@{
    runtime_url = $arisecRuntimeUrl; runtime_sha256 = $arisecRuntimeHash
    model_repository = 'Qwen/Qwen3-0.6B-GGUF'; model_revision = $arisecModelRevision
    model_file = $arisecModelName; model_sha256 = $arisecModelHash
    purpose = 'Small local integration model; not evidence of broad agent capability.'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $arisecDestination 'provenance.json') -Encoding utf8
Write-Output ('Local CPU model verified at ' + $arisecModelFile)

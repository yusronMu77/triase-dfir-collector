<#
.SYNOPSIS  Build the Windows onedir distribution and record its checksums.
.EXAMPLE   pwsh -File scripts\build.ps1
#>
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:UV_PROJECT_ENVIRONMENT = '.venv'
# Reproducible output: fixed hash seed and a timestamp derived from the last commit that touched the sources.
$env:PYTHONHASHSEED = '1'
$epoch = git log -1 --format=%ct -- src scripts astria-collector.spec pyproject.toml uv.lock 2>$null
$env:SOURCE_DATE_EPOCH = if ($epoch) { $epoch } else { '1767225600' }  # 2026-01-01 when nothing is committed yet

uv sync --locked
uv run --no-active pyinstaller astria-collector.spec --noconfirm --clean --distpath dist --workpath build
if ($LASTEXITCODE) { throw 'PyInstaller failed' }

$exe = 'dist\astria-collector\astria-collector.exe'
# Smoke test: the frozen binary starts and reports its version without Python installed on PATH.
$version = & $exe --version
if ($LASTEXITCODE -or $version -notmatch '^astria-collector \d+\.\d+\.\d+$') { throw "smoke test failed: $version" }

Copy-Item README.md, config.example.toml dist\astria-collector\ -Force
$sums = Get-ChildItem dist\astria-collector -Recurse -File | Sort-Object FullName | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.FullName.Substring((Resolve-Path dist\astria-collector).Path.Length + 1).Replace('\', '/')
}
[IO.File]::WriteAllText((Join-Path (Resolve-Path dist).Path 'SHA256SUMS'), (($sums -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"OK: $version"
(Get-FileHash $exe -Algorithm SHA256).Hash.ToLower() + '  astria-collector.exe'

# ==============================================================================
# 09_ConvertToJson.ps1
# Purpose : Convert all NDJSON export files to proper JSON arrays for use in
#           Excel (Get Data -> JSON / Power Query) and other JSON-strict tools
# Run on  : Any machine with access to the output files
# Requires: 00_Config.ps1 (shared configuration)
#           One or more *.ndjson files in $RunOutputPath (run scripts 03-08 first)
#
# Why this exists:
#   NDJSON (one JSON object per line) is the transitive format used by the
#   export scripts — it streams efficiently and handles large datasets without
#   loading everything into memory at once. Excel and Power Query require a
#   valid JSON array: [{...}, {...}]. This script converts between the two
#   formats, also fixing the UTF-8 BOM that Windows PowerShell writes by
#   default (which trips up Excel's JSON parser).
#
# Conversion is streamed line-by-line — no full file load into memory.
# Output files use the same name as the source with a .json extension.
# ==============================================================================

. "$PSScriptRoot\00_Config.ps1"

# --- Module imports -----------------------------------------------------------
$loggingModulePath = Join-Path $PSScriptRoot '..\..\Common\Modules\Shared\Logging.psm1'
Import-Module $loggingModulePath -Force -ErrorAction Stop

# --- Run output directory -----------------------------------------------------
if (-not (Get-Variable -Name RunOutputPath -ErrorAction SilentlyContinue)) {
    # Standalone: use the most recent timestamped run directory
    $latestRun = Get-ChildItem -Path $OutputPath -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $latestRun) {
        throw "No timestamped run directories found in '$OutputPath'. Run scripts 03-08 first."
    }
    $RunOutputPath = $latestRun.FullName
    Write-Warning "No RunOutputPath set; using most recent run: $RunOutputPath"
}
Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
Write-Log "=== 09_ConvertToJson started ==="

# --- Find source files --------------------------------------------------------
$ndjsonFiles = Get-ChildItem -Path $RunOutputPath -Filter "*.ndjson" -ErrorAction SilentlyContinue |
    Sort-Object Name

if ($null -eq $ndjsonFiles -or $ndjsonFiles.Count -eq 0) {
    Write-Log "WARNING: No .ndjson files found in '$RunOutputPath'. Run scripts 03-05 first."
    Write-Warning "No .ndjson files found in '$RunOutputPath'. Run scripts 03-05 first."
    exit 0
}

Write-Log "Found $($ndjsonFiles.Count) NDJSON file(s) in $RunOutputPath. Converting to JSON arrays..."

# UTF-8 without BOM — Windows PowerShell's default Out-File adds a BOM that
# Excel's Power Query JSON connector rejects
$encoding = [System.Text.UTF8Encoding]::new($false)

$converted = 0
$skipped   = 0

foreach ($file in $ndjsonFiles) {
    $jsonPath    = [System.IO.Path]::ChangeExtension($file.FullName, ".json")
    $recordCount = 0
    $writer      = $null

    try {
        $writer = [System.IO.StreamWriter]::new($jsonPath, $false, $encoding)
        $writer.WriteLine("[")

        # Buffer one line ahead so we can omit the trailing comma on the last record
        $lineBuffer = $null

        foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            if ($null -ne $lineBuffer) {
                $writer.WriteLine($lineBuffer + ",")
            }
            $lineBuffer = $line
            $recordCount++
        }

        # Last record — no trailing comma
        if ($null -ne $lineBuffer) {
            $writer.WriteLine($lineBuffer)
        }

        $writer.WriteLine("]")

        $status = if ($recordCount -eq 0) { "(empty)" } else { "$recordCount records" }
        Write-Log ("  {0,-45} -> {1} ({2})" -f $file.Name, [System.IO.Path]::GetFileName($jsonPath), $status)
        $converted++
    }
    catch {
        Write-Log "  WARNING: Failed to convert $($file.Name): $_"
        Write-Warning "  Failed to convert $($file.Name): $_"
        $skipped++
    }
    finally {
        if ($null -ne $writer) { $writer.Dispose() }
    }
}

Write-Log "=== 09_ConvertToJson complete — $converted file(s) converted, $skipped skipped ==="

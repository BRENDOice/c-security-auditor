<#
.SYNOPSIS
    Automated Windows PowerShell build and test script for c-security-auditor.

.DESCRIPTION
    Compiles all C source files with strict GCC flags (-Wall -Wextra -Werror -pedantic -std=c11),
    links the c-security-auditor executable, and runs the automated SAST test suite.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Clean
#>

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

# Set base paths relative to script location
$ProjectRoot = $PSScriptRoot
$BuildDir    = Join-Path $ProjectRoot "build"
$BinName     = "c-security-auditor.exe"
$BinPath     = Join-Path $BuildDir $BinName
$RootBinPath = Join-Path $ProjectRoot $BinName
$IncludeDir  = Join-Path $ProjectRoot "include"
$SrcDir      = Join-Path $ProjectRoot "src"
$TestsDir    = Join-Path $ProjectRoot "tests"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Failure {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

# 1. Clean if requested
if ($Clean) {
    Write-Step "Cleaning build artifacts..."
    if (Test-Path $BuildDir) {
        Remove-Item -Recurse -Force $BuildDir
    }
    if (Test-Path $RootBinPath) {
        Remove-Item -Force $RootBinPath
    }
    Write-Success "Build directory cleaned."
}

# Ensure build directory exists
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

# 2. Check GCC compiler
Write-Step "Checking for GCC toolchain..."
try {
    $gccVer = & gcc --version
    Write-Success "GCC detected: $($gccVer[0])"
} catch {
    Write-Failure "GCC compiler not found in PATH. Please install MinGW-w64 or GCC."
    exit 1
}

# 3. Source files to compile
$SourceFiles = @(
    (Join-Path $SrcDir "scanner.c"),
    (Join-Path $SrcDir "rules.c"),
    (Join-Path $SrcDir "report.c"),
    (Join-Path $SrcDir "main.c")
)

foreach ($src in $SourceFiles) {
    if (-not (Test-Path $src)) {
        Write-Failure "Required source file not found: $src"
        exit 1
    }
}

# 4. Strict compilation flags
$CFlags = @(
    "-Wall",
    "-Wextra",
    "-Werror",
    "-pedantic",
    "-std=c11",
    "-O2",
    "-I$IncludeDir"
)

Write-Step "Compiling c-security-auditor with strict flags (-Wall -Wextra -Werror -pedantic -std=c11)..."
$compileArgs = $CFlags + $SourceFiles + @("-o", $BinPath)

$process = Start-Process -FilePath "gcc" -ArgumentList $compileArgs -NoNewWindow -Wait -PassThru
if ($process.ExitCode -ne 0) {
    Write-Failure "Compilation failed with exit code $($process.ExitCode)."
    exit $process.ExitCode
}

# Also mirror binary in project root for convenience
Copy-Item -Path $BinPath -Destination $RootBinPath -Force
Write-Success "Compilation succeeded: $BinPath"
Write-Success "Mirrored executable: $RootBinPath"

# 5. Run automated test suite
if (-not $SkipTests) {
    Write-Step "Executing SAST Automated Test Suite..."

    $vulnerableSample = Join-Path $TestsDir "vulnerable_sample.c"
    $cleanSample      = Join-Path $TestsDir "clean_sample.c"
    $mdReport         = Join-Path $BuildDir "audit_report.md"
    $jsonReport       = Join-Path $BuildDir "audit_report.json"

    # Test A: Scan vulnerable sample (expect non-zero exit code due to policy violation)
    Write-Host "`n--- Test A: Scanning Vulnerable Sample (Expecting Policy Failure) ---" -ForegroundColor Yellow
    $vulnProc = Start-Process -FilePath $BinPath -ArgumentList @($vulnerableSample, "-o", $mdReport, "-f", "markdown") -NoNewWindow -Wait -PassThru
    if ($vulnProc.ExitCode -eq 1) {
        Write-Success "Vulnerability detection verified! Policy gate triggered correctly."
    } else {
        Write-Failure "Expected exit code 1 on vulnerable sample, but got $($vulnProc.ExitCode)."
        exit 1
    }

    # Verify Markdown export
    if (Test-Path $mdReport) {
        Write-Success "Markdown audit report successfully generated: $mdReport"
    } else {
        Write-Failure "Markdown report missing."
        exit 1
    }

    # Test B: Export JSON
    Write-Host "`n--- Test B: Exporting JSON Report ---" -ForegroundColor Yellow
    $jsonProc = Start-Process -FilePath $BinPath -ArgumentList @($vulnerableSample, "-o", $jsonReport, "-f", "json") -NoNewWindow -Wait -PassThru
    if (Test-Path $jsonReport) {
        Write-Success "JSON audit report successfully generated: $jsonReport"
    } else {
        Write-Failure "JSON report missing."
        exit 1
    }

    # Test C: Scan clean sample (expect exit code 0)
    Write-Host "`n--- Test C: Scanning Clean Sample with Suppression ---" -ForegroundColor Yellow
    $cleanProc = Start-Process -FilePath $BinPath -ArgumentList @($cleanSample) -NoNewWindow -Wait -PassThru
    if ($cleanProc.ExitCode -eq 0) {
        Write-Success "Clean sample passed policy check with zero active vulnerabilities!"
    } else {
        Write-Failure "Clean sample unexpectedly failed with exit code $($cleanProc.ExitCode)."
        exit 1
    }

    Write-Step "All automated tests PASSED successfully!"
}

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "  c-security-auditor build & verification COMPLETE!" -ForegroundColor Green
Write-Host "========================================================`n" -ForegroundColor Green

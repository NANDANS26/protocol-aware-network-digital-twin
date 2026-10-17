<#
.SYNOPSIS
    Cross-platform developer task runner for Protocol Digital Twin Platform on Windows.

.EXAMPLE
    .\scripts\dev.ps1 setup
    .\scripts\dev.ps1 test-all
    .\scripts\dev.ps1 run-api
    .\scripts\dev.ps1 run-web
#>

param(
    [Parameter(Position=0)]
    [ValidateSet("setup", "build-engine", "test-engine", "test-api", "test-web", "lint", "typecheck", "run-api", "run-web", "test-all", "check-all", "help")]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot

function Write-Heading($text) {
    Write-Host "`n=== $text ===" -ForegroundColor Cyan
}

switch ($Command) {
    "setup" {
        Write-Heading "Setting up Python virtual environment"
        if (!(Test-Path "$RootDir\.venv")) {
            python -m venv "$RootDir\.venv"
        }
        & "$RootDir\.venv\Scripts\python.exe" -m pip install --upgrade pip
        & "$RootDir\.venv\Scripts\python.exe" -m pip install -r "$RootDir\apps\api\requirements-dev.txt"
        & "$RootDir\.venv\Scripts\python.exe" -m pip install -e "$RootDir\packages\contracts\python"
        & "$RootDir\.venv\Scripts\python.exe" -m pip install -e "$RootDir\apps\api"

        Write-Heading "Installing Web dependencies"
        Push-Location "$RootDir\apps\web"
        npm install
        Pop-Location

        Write-Heading "Configuring C++ Engine with CMake"
        cmake -B "$RootDir\build\engine" -S "$RootDir\engine\protocol"
        cmake --build "$RootDir\build\engine" --config Release
        Write-Host "Setup successfully completed!" -ForegroundColor Green
    }

    "build-engine" {
        Write-Heading "Building C++ Engine"
        cmake -B "$RootDir\build\engine" -S "$RootDir\engine\protocol"
        cmake --build "$RootDir\build\engine" --config Release
    }

    "test-engine" {
        Write-Heading "Running C++ Engine Tests"
        ctest --test-dir "$RootDir\build\engine" -C Release --output-on-failure
    }

    "test-api" {
        Write-Heading "Running Python API Tests"
        & "$RootDir\.venv\Scripts\pytest.exe" "$RootDir\apps\api\tests" "$RootDir\tests\integration"
    }

    "test-web" {
        Write-Heading "Running Frontend Vitest Suite"
        Push-Location "$RootDir\apps\web"
        npm run test
        Pop-Location
    }

    "typecheck" {
        Write-Heading "Running TypeScript Type Check"
        Push-Location "$RootDir\apps\web"
        npm run typecheck
        Pop-Location
    }

    "lint" {
        Write-Heading "Running Linters"
        & "$RootDir\.venv\Scripts\ruff.exe" check "$RootDir\apps\api" "$RootDir\packages\contracts\python"
    }

    "run-api" {
        Write-Heading "Starting FastAPI Backend on http://127.0.0.1:8000"
        & "$RootDir\.venv\Scripts\python.exe" -m uvicorn network_twin.main:app --host 127.0.0.1 --port 8000 --reload
    }

    "run-web" {
        Write-Heading "Starting React Workstation on http://localhost:5173"
        Push-Location "$RootDir\apps\web"
        npm run dev
        Pop-Location
    }

    "test-all" {
        Write-Heading "Executing All Quality Gates"
        & $PSCommandPath test-engine
        & $PSCommandPath test-api
        & $PSCommandPath typecheck
        & $PSCommandPath test-web
        Write-Host "`nAll platform tests passed successfully!" -ForegroundColor Green
    }

    "check-all" {
        Write-Heading "Executing All Hygiene and Quality Checks"
        & $PSCommandPath lint
        & $PSCommandPath typecheck
        & $PSCommandPath test-all
        Write-Host "`nAll quality gates passed!" -ForegroundColor Green
    }

    Default {
        Write-Host "Protocol Digital Twin Platform - Developer Runner"
        Write-Host "Available commands:"
        Write-Host "  setup         - Initialize venv, install Python/Node dependencies, and build C++ engine"
        Write-Host "  build-engine  - Build C++20 engine using CMake"
        Write-Host "  test-engine   - Run C++ unit test suite"
        Write-Host "  test-api      - Run Python backend & integration tests"
        Write-Host "  test-web      - Run frontend Vitest test suite"
        Write-Host "  typecheck     - Run strict TypeScript type check"
        Write-Host "  lint          - Run Ruff linter on Python code"
        Write-Host "  run-api       - Start FastAPI development server"
        Write-Host "  run-web       - Start React development server"
        Write-Host "  test-all      - Execute all automated unit & integration test suites"
        Write-Host "  check-all     - Run full quality gates (lint + typecheck + test-all)"
    }
}

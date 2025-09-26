# PowerShell script to run SonarQube analysis on the C# Taint Analysis Demo
# Usage: .\run-sonar-analysis.ps1 -SonarUrl "http://localhost:9000" -SonarToken "your-token"

param(
    [Parameter(Mandatory=$true)]
    [string]$SonarUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$SonarToken,
    
    [string]$ProjectKey = "csharp-taint-analysis-demo",
    [string]$ProjectName = "C# Taint Analysis Demo"
)

Write-Host "🚀 Starting SonarQube Analysis for C# Taint Demo" -ForegroundColor Green
Write-Host "Project: $ProjectName" -ForegroundColor Yellow
Write-Host "SonarQube URL: $SonarUrl" -ForegroundColor Yellow

try {
    # Check if .NET SDK is available
    Write-Host "🔍 Checking .NET SDK..." -ForegroundColor Blue
    dotnet --version
    if ($LASTEXITCODE -ne 0) {
        throw "❌ .NET SDK not found. Please install .NET 8.0 SDK or later."
    }

    # Restore local tools first
    Write-Host "🔧 Restoring .NET local tools..." -ForegroundColor Blue
    dotnet tool restore

    # Check if SonarScanner for .NET is available locally, then globally
    Write-Host "🔍 Checking SonarScanner for .NET..." -ForegroundColor Blue
    $localTool = dotnet tool list | Select-String "dotnet-sonarscanner"
    if (-not $localTool) {
        $globalTool = dotnet tool list --global | Select-String "dotnet-sonarscanner"
        if (-not $globalTool) {
            Write-Host "📦 Installing SonarScanner for .NET globally..." -ForegroundColor Yellow
            dotnet tool install --global dotnet-sonarscanner
        }
    }

    # Clean previous builds
    Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Blue
    dotnet clean

    # Begin SonarQube analysis with enhanced security configuration
    Write-Host "🔬 Beginning SonarQube analysis..." -ForegroundColor Blue
    dotnet sonarscanner begin `
        /k:$ProjectKey `
        /n:$ProjectName `
        /d:sonar.host.url=$SonarUrl `
        /d:sonar.token=$SonarToken `
        /d:sonar.cs.opencover.reportsPaths="coverage.opencover.xml" `
        /d:sonar.exclusions="bin/**,obj/**,.config/**,*.ruleset" `
        /d:sonar.cs.roslyn.bugCategories="Security,Vulnerability" `
        /d:sonar.security.hotspots.includeInOverallRating="true" `
        /d:sonar.security.review.enable="true" `
        /d:sonar.qualitygate.wait="true"

    # Restore packages and build with analysis
    Write-Host "📦 Restoring NuGet packages..." -ForegroundColor Blue
    dotnet restore

    Write-Host "🔨 Building project with code analysis..." -ForegroundColor Blue
    dotnet build --no-restore --verbosity normal

    # End SonarQube analysis
    Write-Host "📊 Completing SonarQube analysis..." -ForegroundColor Blue
    dotnet sonarscanner end /d:sonar.token=$SonarToken

    Write-Host "✅ SonarQube analysis completed successfully!" -ForegroundColor Green
    Write-Host "🌐 View results at: $SonarUrl/dashboard?id=$ProjectKey" -ForegroundColor Cyan
    Write-Host "🌐 Live SonarCloud Results: https://sonarcloud.io/project/overview?id=alexandravaron_sonar-csharp-taint-demo" -ForegroundColor Cyan
    
    # Expected findings summary
    Write-Host ""
    Write-Host "🔍 Expected Security Findings:" -ForegroundColor Magenta
    Write-Host "• SQL Injection (High) - Multiple instances across Controllers → Services → Data layer" -ForegroundColor Red
    Write-Host "• Command Injection (High) - In UserService and ReportGenerator" -ForegroundColor Red
    Write-Host "• Path Traversal (High) - In FileManager utility class" -ForegroundColor Red
    Write-Host "• LDAP Injection (High) - In authentication methods" -ForegroundColor Red
    Write-Host "• SSRF (Medium) - In ReportGenerator template fetching" -ForegroundColor Yellow
    Write-Host "• XXE (Medium) - In XML template processing" -ForegroundColor Yellow
    Write-Host "• XSS (Medium) - In API response data" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "💡 Key Demo Points:" -ForegroundColor Cyan
    Write-Host "• Multi-file taint flows traced from HTTP inputs to sinks" -ForegroundColor White
    Write-Host "• Complex data flow through service and data access layers" -ForegroundColor White
    Write-Host "• Realistic application architecture with layered vulnerabilities" -ForegroundColor White

} catch {
    Write-Host "❌ Error during SonarQube analysis: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

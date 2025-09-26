#!/bin/bash

# Bash script to run SonarQube analysis on the C# Taint Analysis Demo
# Usage: ./run-sonar-analysis.sh <sonar-url> <sonar-token> [project-key] [project-name]

set -e

SONAR_URL=${1:-"http://localhost:9000"}
SONAR_TOKEN=${2:-""}
PROJECT_KEY=${3:-"csharp-taint-analysis-demo"}
PROJECT_NAME=${4:-"C# Taint Analysis Demo"}

if [ -z "$SONAR_TOKEN" ]; then
    echo "❌ Error: SonarQube token is required"
    echo "Usage: ./run-sonar-analysis.sh <sonar-url> <sonar-token> [project-key] [project-name]"
    exit 1
fi

echo "🚀 Starting SonarQube Analysis for C# Taint Demo"
echo "Project: $PROJECT_NAME"
echo "SonarQube URL: $SONAR_URL"

# Check if .NET SDK is available
echo "🔍 Checking .NET SDK..."
if ! command -v dotnet &> /dev/null; then
    echo "❌ .NET SDK not found. Please install .NET 8.0 SDK or later."
    exit 1
fi

dotnet --version

# Restore local tools first
echo "🔧 Restoring .NET local tools..."
dotnet tool restore

# Check if SonarScanner for .NET is available locally, then globally
echo "🔍 Checking SonarScanner for .NET..."
if ! dotnet tool list | grep -q "dotnet-sonarscanner"; then
    if ! dotnet tool list --global | grep -q "dotnet-sonarscanner"; then
        echo "📦 Installing SonarScanner for .NET globally..."
        dotnet tool install --global dotnet-sonarscanner
    fi
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
dotnet clean

# Begin SonarQube analysis with enhanced security configuration
echo "🔬 Beginning SonarQube analysis..."
dotnet sonarscanner begin \
    /k:"$PROJECT_KEY" \
    /n:"$PROJECT_NAME" \
    /d:sonar.host.url="$SONAR_URL" \
    /d:sonar.token="$SONAR_TOKEN" \
    /d:sonar.cs.opencover.reportsPaths="coverage.opencover.xml" \
    /d:sonar.exclusions="bin/**,obj/**,.config/**,*.ruleset" \
    /d:sonar.cs.roslyn.bugCategories="Security,Vulnerability" \
    /d:sonar.security.hotspots.includeInOverallRating="true" \
    /d:sonar.security.review.enable="true" \
    /d:sonar.qualitygate.wait="true"

# Restore packages and build with analysis
echo "📦 Restoring NuGet packages..."
dotnet restore

echo "🔨 Building project with code analysis..."
dotnet build --no-restore --verbosity normal

# End SonarQube analysis
echo "📊 Completing SonarQube analysis..."
dotnet sonarscanner end /d:sonar.token="$SONAR_TOKEN"

echo "✅ SonarQube analysis completed successfully!"
echo "🌐 View results at: $SONAR_URL/dashboard?id=$PROJECT_KEY"

# Expected findings summary
echo ""
echo "🔍 Expected Security Findings:"
echo "• SQL Injection (High) - Multiple instances across Controllers → Services → Data layer"
echo "• Command Injection (High) - In UserService and ReportGenerator" 
echo "• Path Traversal (High) - In FileManager utility class"
echo "• LDAP Injection (High) - In authentication methods"
echo "• SSRF (Medium) - In ReportGenerator template fetching"
echo "• XXE (Medium) - In XML template processing"
echo "• XSS (Medium) - In API response data"
echo ""
echo "💡 Key Demo Points:"
echo "• Multi-file taint flows traced from HTTP inputs to sinks"
echo "• Complex data flow through service and data access layers"
echo "• Realistic application architecture with layered vulnerabilities"

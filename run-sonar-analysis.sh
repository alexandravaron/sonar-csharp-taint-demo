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

# Check if SonarScanner for .NET is available
echo "🔍 Checking SonarScanner for .NET..."
if ! dotnet tool list --global | grep -q "dotnet-sonarscanner"; then
    echo "📦 Installing SonarScanner for .NET..."
    dotnet tool install --global dotnet-sonarscanner
fi

# Begin SonarQube analysis
echo "🔬 Beginning SonarQube analysis..."
dotnet sonarscanner begin \
    /k:"$PROJECT_KEY" \
    /n:"$PROJECT_NAME" \
    /d:sonar.host.url="$SONAR_URL" \
    /d:sonar.token="$SONAR_TOKEN" \
    /d:sonar.cs.opencover.reportsPaths="coverage.opencover.xml" \
    /d:sonar.exclusions="bin/**,obj/**"

# Restore packages and build
echo "📦 Restoring NuGet packages..."
dotnet restore

echo "🔨 Building project..."
dotnet build --no-restore

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

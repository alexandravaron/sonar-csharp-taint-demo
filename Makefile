# Makefile for SonarQube C# Taint Analysis Demo

# Default SonarQube configuration
SONAR_URL ?= http://localhost:9000
SONAR_TOKEN ?= 
PROJECT_KEY ?= csharp-taint-analysis-demo
PROJECT_NAME ?= "C# Taint Analysis Demo"

.PHONY: help install-tools restore build clean sonar-analysis sonar-full demo-setup

help: ## Show this help message
	@echo "🔧 SonarQube C# Taint Analysis Demo - Build Commands"
	@echo ""
	@echo "Usage: make [target] [SONAR_URL=url] [SONAR_TOKEN=token]"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"}; /^[a-zA-Z_-]+:.*##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "Examples:"
	@echo "  make sonar-full SONAR_URL=http://localhost:9000 SONAR_TOKEN=your-token"
	@echo "  make demo-setup"

install-tools: ## Install .NET tools (SonarScanner)
	@echo "🔧 Installing .NET tools..."
	dotnet tool restore || dotnet tool install --global dotnet-sonarscanner

restore: ## Restore NuGet packages
	@echo "📦 Restoring packages..."
	dotnet restore

build: restore ## Build the project
	@echo "🔨 Building project..."
	dotnet build --no-restore

clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	dotnet clean
	rm -rf bin/ obj/

sonar-analysis: clean install-tools ## Run SonarQube analysis (requires SONAR_URL and SONAR_TOKEN)
	@if [ -z "$(SONAR_TOKEN)" ]; then \
		echo "❌ Error: SONAR_TOKEN is required"; \
		echo "Usage: make sonar-analysis SONAR_URL=http://localhost:9000 SONAR_TOKEN=your-token"; \
		exit 1; \
	fi
	@echo "🔬 Starting SonarQube analysis..."
	@echo "SonarQube URL: $(SONAR_URL)"
	@echo "Project: $(PROJECT_NAME)"
	dotnet sonarscanner begin \
		/k:"$(PROJECT_KEY)" \
		/n:"$(PROJECT_NAME)" \
		/d:sonar.host.url="$(SONAR_URL)" \
		/d:sonar.token="$(SONAR_TOKEN)" \
		/d:sonar.cs.roslyn.bugCategories="Security,Vulnerability" \
		/d:sonar.security.hotspots.includeInOverallRating="true" \
		/d:sonar.security.review.enable="true" \
		/d:sonar.qualitygate.wait="true" \
		/d:sonar.exclusions="bin/**,obj/**,.config/**,*.ruleset"
	dotnet restore
	dotnet build --no-restore --verbosity normal
	dotnet sonarscanner end /d:sonar.token="$(SONAR_TOKEN)"
	@echo "✅ SonarQube analysis completed!"
	@echo "🌐 View results at: $(SONAR_URL)/dashboard?id=$(PROJECT_KEY)"

sonar-full: sonar-analysis ## Complete SonarQube analysis with summary
	@echo ""
	@echo "🔍 Expected Security Findings Summary:"
	@echo "• SQL Injection (High) - 8+ instances across Controllers → Services → Data layer"
	@echo "• Command Injection (High) - 5+ instances in UserService and ReportGenerator" 
	@echo "• Path Traversal (High) - 7+ instances in FileManager utility class"
	@echo "• LDAP Injection (High) - 2+ instances in authentication methods"
	@echo "• SSRF (Medium) - 2+ instances in ReportGenerator template fetching"
	@echo "• XXE (Medium) - 1+ instance in XML template processing"
	@echo "• XSS (Medium) - 2+ instances in API response data"

demo-setup: install-tools restore build ## Set up the demo environment
	@echo "🎯 Demo environment setup complete!"
	@echo ""
	@echo "📋 Demo Project Ready:"
	@echo "• 22 files with intentional security vulnerabilities"
	@echo "• Multi-file taint flows spanning Controllers → Services → Data layers"
	@echo "• 7 different vulnerability types demonstrated"
	@echo "• Comprehensive documentation for customer presentations"
	@echo ""
	@echo "🚀 Next steps:"
	@echo "1. Set up SonarQube server"
	@echo "2. Run: make sonar-analysis SONAR_URL=your-url SONAR_TOKEN=your-token"
	@echo "3. Present results to customers using VULNERABILITY_SUMMARY.md"

dev: restore build ## Quick development build
	@echo "👨‍💻 Development build complete!"

check: build ## Check for compilation errors
	@echo "✅ Project compiles successfully - ready for SonarQube analysis!"

info: ## Show project information
	@echo "📊 Project Information:"
	@echo "Name: $(PROJECT_NAME)"
	@echo "Key: $(PROJECT_KEY)" 
	@echo "Framework: .NET 8.0"
	@echo "Type: ASP.NET Core Web API"
	@echo "Purpose: SonarQube Taint Analysis Demonstration"
	@echo "Repository: https://github.com/alexandravaron/sonar-csharp-taint-demo"

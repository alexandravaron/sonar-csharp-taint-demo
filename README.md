# SonarQube C# Taint Analysis Demo

This project demonstrates **taint analysis** vulnerabilities spanning multiple files and layers, specifically designed to showcase SonarQube's security analysis capabilities to customers.

## 🎯 Purpose

This demo application contains intentionally vulnerable code that demonstrates how **untrusted user input** (taint sources) flows through multiple application layers to reach **sensitive operations** (taint sinks), creating security vulnerabilities that SonarQube can detect and trace.

## 🏗️ Architecture

The application follows a typical layered architecture where tainted data flows through:

```
Controllers (Entry Points) → Services (Business Logic) → Data/Utils (Sinks)
```

## 🚨 Vulnerability Categories Demonstrated

### 1. SQL Injection (Multiple Files)

**Flow**: `UserController` → `UserService` → `DataRepository`

- **Entry Point**: User search parameters in REST API endpoints
- **Taint Flow**: Unsanitized input passes through service layer
- **Sink**: Dynamic SQL query construction with string concatenation

**Key Files**:
- `Controllers/UserController.cs` - Search endpoints receiving user input
- `Services/UserService.cs` - Business logic processing tainted data
- `Data/DataRepository.cs` - SQL injection vulnerabilities in multiple methods

**Examples**:
```csharp
// Controller: Taint source
[HttpGet("search")]
public async Task<IActionResult> SearchUsers([FromQuery] string searchTerm)

// Service: Taint propagation
public async Task<IEnumerable<User>> SearchUsersAsync(string searchTerm, string category)

// Repository: Taint sink (SQL Injection)
var query = $"SELECT * FROM Users WHERE Username LIKE '%{searchTerm}%'";
```

### 2. Path Traversal (Multi-File Flow)

**Flow**: `ReportController` → `FileManager`

- **Entry Point**: File names and paths from HTTP requests
- **Taint Flow**: User-controlled paths passed to file operations
- **Sink**: File system operations without path validation

**Key Files**:
- `Controllers/ReportController.cs` - File operation endpoints
- `Utils/FileManager.cs` - Vulnerable file operations

**Examples**:
```csharp
// Controller: Taint source
[HttpGet("download/{fileName}")]
public async Task<IActionResult> DownloadReport(string fileName)

// FileManager: Taint sink (Path Traversal)
var filePath = Path.Combine(_baseDirectory, fileName); // Allows ../../../etc/passwd
```

### 3. LDAP Injection (Service Layer)

**Flow**: `AuthController` → `UserService` → LDAP Operations

- **Entry Point**: Authentication credentials and search filters
- **Taint Flow**: User input embedded in LDAP queries
- **Sink**: DirectorySearcher with unsanitized filters

**Key Files**:
- `Controllers/AuthController.cs` - Authentication endpoints
- `Services/UserService.cs` - LDAP query construction

**Examples**:
```csharp
// Controller: Taint source
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)

// Service: Taint sink (LDAP Injection)
Filter = $"(&(objectClass=user)(sAMAccountName={username}))"
```

### 4. Command Injection (Multiple Layers)

**Flow**: Controllers → Services/Utils → Process Execution

- **Entry Point**: Import sources, report types, template URLs
- **Taint Flow**: User data passed to command construction
- **Sink**: Process.Start() with user-controlled arguments

**Key Files**:
- `Controllers/UserController.cs` - Import functionality
- `Controllers/ReportController.cs` - Report generation
- `Services/UserService.cs` - Import processing
- `Utils/ReportGenerator.cs` - Command execution

### 5. Server-Side Request Forgery (SSRF)

**Flow**: `ReportController` → `ReportGenerator`

- **Entry Point**: Template URLs from HTTP requests
- **Taint Flow**: User-controlled URLs passed to HTTP client
- **Sink**: HttpClient.GetAsync() with unvalidated URLs

### 6. XML External Entity (XXE) Injection

**Flow**: `ReportController` → `ReportGenerator`

- **Entry Point**: XML content from POST requests
- **Taint Flow**: User-provided XML processed without restrictions
- **Sink**: XmlDocument.Load() with DTD processing enabled

### 7. Cross-Site Scripting (XSS)

**Flow**: `UserController` → Direct Response

- **Entry Point**: Display name query parameters
- **Taint Flow**: User input reflected in API responses
- **Sink**: Unescaped data in JSON responses

## 📁 File Structure and Taint Flows

```
Controllers/
├── UserController.cs      # SQL Injection, XSS, Command Injection entry points
├── ReportController.cs    # Path Traversal, SSRF, XXE entry points  
└── AuthController.cs      # LDAP Injection entry points

Services/
├── IUserService.cs        # Service contracts
└── UserService.cs         # Business logic with taint propagation

Data/
├── IDataRepository.cs     # Data access contracts
└── DataRepository.cs      # SQL Injection sinks

Utils/
├── FileManager.cs         # Path Traversal sinks
└── ReportGenerator.cs     # Command Injection, SSRF, XXE sinks

Models/
└── User.cs               # Data transfer objects
```

## 🔍 SonarQube Analysis Points

When analyzing this project with SonarQube, you should see:

### Taint Analysis Results:
1. **Multi-file vulnerability flows** traced from HTTP inputs to database queries
2. **Complex data flow paths** through service layers and utility classes
3. **Multiple vulnerability types** in a realistic application structure
4. **Both vulnerable and safe code** examples for comparison

### Key Detection Features:
- **Source identification**: HTTP parameters, request bodies, route values
- **Sink identification**: SQL queries, file operations, command execution
- **Flow tracking**: Through method calls, object properties, and return values
- **Sanitization detection**: Lack of input validation and output encoding

## 🚀 Running the Demo

### Prerequisites:
- .NET 8.0 SDK
- Visual Studio 2022 or VS Code
- SonarQube Server or SonarCloud account

### Steps:
1. **Clone and build**:
   ```bash
   git clone <repository>
   cd sonar-csharp-demo
   dotnet restore
   dotnet build
   ```

2. **Run SonarQube analysis**:
   ```bash
   dotnet sonarscanner begin /k:"csharp-taint-demo" /d:sonar.host.url="<your-sonar-url>"
   dotnet build
   dotnet sonarscanner end
   ```

3. **View results** in SonarQube dashboard

## 📊 Expected SonarQube Findings

You should see security issues including:
- **High**: SQL Injection vulnerabilities (multiple instances)
- **High**: Command Injection vulnerabilities  
- **High**: Path Traversal vulnerabilities
- **High**: LDAP Injection vulnerabilities
- **Medium**: SSRF vulnerabilities
- **Medium**: XXE vulnerabilities
- **Medium**: XSS vulnerabilities

## ⚠️ Important Notes

- **This code is intentionally vulnerable** - DO NOT use in production
- **All vulnerabilities are for demonstration purposes only**
- **The project focuses on taint flow demonstration**, not functional completeness
- **Some methods are simplified** to clearly show vulnerability patterns

## 🎓 Learning Objectives

This demo helps understand:
1. How taint analysis works across multiple files and layers
2. Different types of security vulnerabilities in web applications
3. The importance of input validation and output encoding
4. How SonarQube traces data flow through complex code paths
5. The relationship between application architecture and security

## 🔧 Customization

You can extend this demo by:
- Adding more vulnerability types (Deserialization, etc.)
- Creating longer taint flow chains
- Adding both vulnerable and secure versions of the same functionality
- Including different frameworks and libraries

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SonarQube Security Rules](https://rules.sonarsource.com/csharp/type/Security%20Hotspot)
- [.NET Security Guidelines](https://docs.microsoft.com/en-us/dotnet/standard/security/)

---

**Remember**: This is a security demonstration tool. All vulnerabilities are intentional and should never be deployed to production environments.

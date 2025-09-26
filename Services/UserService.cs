using System.Diagnostics;
using System.DirectoryServices;
using SonarCSharpDemo.Data;
using SonarCSharpDemo.Models;

namespace SonarCSharpDemo.Services;

public class UserService : IUserService
{
    private readonly IDataRepository _dataRepository;

    public UserService(IDataRepository dataRepository)
    {
        _dataRepository = dataRepository;
    }

    /// <summary>
    /// VULNERABLE: Passes tainted data to data layer without sanitization
    /// Taint flow: Controller -> Service -> DataRepository
    /// </summary>
    public async Task<IEnumerable<User>> SearchUsersAsync(string searchTerm, string category)
    {
        // Tainted data flows through without sanitization
        var users = await _dataRepository.SearchUsersAsync(searchTerm, category);
        
        // Additional processing that might introduce more vulnerabilities
        if (category.ToLower() == "admin")
        {
            // Potential secondary SQL injection through dynamic filtering
            users = await _dataRepository.FilterUsersByRoleAsync(category);
        }
        
        return users;
    }

    /// <summary>
    /// VULNERABLE: Complex taint flow through multiple data access methods
    /// </summary>
    public async Task<IEnumerable<User>> PerformAdvancedSearchAsync(UserSearchRequest request)
    {
        // Multiple tainted inputs flow to different vulnerable methods
        var users = new List<User>();

        // First vulnerable call
        var basicResults = await _dataRepository.SearchUsersAsync(request.SearchTerm, request.Category);
        users.AddRange(basicResults);

        // Second vulnerable call with different tainted input
        if (!string.IsNullOrEmpty(request.SortBy))
        {
            users = (await _dataRepository.GetSortedUsersAsync(request.SortBy)).ToList();
        }

        // Third vulnerable call combining multiple tainted inputs
        var filteredResults = await _dataRepository.ExecuteCustomQueryAsync(
            $"SELECT * FROM Users WHERE Category = '{request.Category}' ORDER BY {request.SortBy}");
        
        return users.Concat(filteredResults);
    }

    /// <summary>
    /// Safe method - shows contrast with vulnerable methods
    /// </summary>
    public async Task<User?> GetUserByIdAsync(int userId)
    {
        // This method is safe as it uses parameterized queries
        return await _dataRepository.GetUserByIdAsync(userId);
    }

    /// <summary>
    /// VULNERABLE: Command Injection
    /// User input flows to system command execution
    /// </summary>
    public async Task<string> ImportUsersFromSourceAsync(string source, string format)
    {
        // VULNERABLE: Direct command execution with user input
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c import_users.exe --source \"{source}\" --format {format}",
                RedirectStandardOutput = true,
                UseShellExecute = false
            }
        };

        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();

        // Also vulnerable data access call
        await _dataRepository.LogImportActionAsync($"Import from {source} in {format} format");

        return output;
    }

    /// <summary>
    /// VULNERABLE: LDAP Injection
    /// User credentials flow to LDAP query without sanitization
    /// </summary>
    public async Task<bool> AuthenticateUserAsync(string username, string password, string domain)
    {
        try
        {
            // VULNERABLE: LDAP injection through unsanitized user input
            using var entry = new DirectoryEntry($"LDAP://{domain}", username, password);
            using var searcher = new DirectorySearcher(entry)
            {
                // VULNERABLE: Direct injection of user input into LDAP filter
                Filter = $"(&(objectClass=user)(sAMAccountName={username}))"
            };

            var result = searcher.FindOne();
            
            // Log the authentication attempt with vulnerable data access
            await _dataRepository.LogAuthenticationAttemptAsync(username, domain, result != null);
            
            return result != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// VULNERABLE: LDAP Injection in directory search
    /// </summary>
    public async Task<IEnumerable<User>> SearchDirectoryUsersAsync(string searchFilter, string domain)
    {
        var users = new List<User>();

        try
        {
            using var entry = new DirectoryEntry($"LDAP://{domain}");
            using var searcher = new DirectorySearcher(entry)
            {
                // VULNERABLE: User input directly embedded in LDAP filter
                Filter = $"(&(objectClass=user){searchFilter})"
            };

            var results = searcher.FindAll();
            foreach (DirectoryEntry userEntry in results)
            {
                users.Add(new User
                {
                    Username = userEntry.Properties["sAMAccountName"].Value?.ToString() ?? "",
                    Email = userEntry.Properties["mail"].Value?.ToString() ?? "",
                    FirstName = userEntry.Properties["givenName"].Value?.ToString() ?? "",
                    LastName = userEntry.Properties["sn"].Value?.ToString() ?? ""
                });
            }

            // Vulnerable logging with tainted data
            await _dataRepository.LogDirectorySearchAsync(searchFilter, domain, users.Count);
        }
        catch (Exception ex)
        {
            // Vulnerable error logging that might expose sensitive data
            await _dataRepository.LogErrorAsync($"Directory search failed: {searchFilter} in {domain} - {ex.Message}");
        }

        return users;
    }

    /// <summary>
    /// VULNERABLE: SQL Injection through password validation
    /// </summary>
    public async Task<bool> ValidatePasswordComplexityAsync(string username, string password)
    {
        // VULNERABLE: Password data flows to SQL injection vulnerable method
        return await _dataRepository.CheckPasswordComplexityAsync(username, password);
    }

    /// <summary>
    /// VULNERABLE: SQL Injection through password history check
    /// </summary>
    public async Task<bool> CheckPasswordHistoryAsync(string username, string password)
    {
        // VULNERABLE: Multiple tainted inputs flow to data layer
        var passwordHistory = await _dataRepository.GetPasswordHistoryAsync(username);
        var hashToCheck = ComputeUnsafeHash(password); // Weak hashing for demo
        
        return await _dataRepository.IsPasswordInHistoryAsync(username, hashToCheck);
    }

    /// <summary>
    /// VULNERABLE: Weak cryptographic function
    /// Shows how tainted data can flow through crypto operations
    /// </summary>
    private string ComputeUnsafeHash(string input)
    {
        // VULNERABLE: Using weak MD5 hash - not a taint issue but shows poor crypto
        using var md5 = System.Security.Cryptography.MD5.Create();
        var hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hash);
    }
}

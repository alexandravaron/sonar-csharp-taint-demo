using Microsoft.Data.SqlClient;
using SonarCSharpDemo.Models;

namespace SonarCSharpDemo.Data;

public class DataRepository : IDataRepository
{
    private readonly string _connectionString;

    public DataRepository(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") 
            ?? "Server=localhost;Database=SonarDemo;Trusted_Connection=true;";
    }

    /// <summary>
    /// VULNERABLE: SQL Injection through string concatenation
    /// This is the main sink for tainted data from the service layer
    /// </summary>
    public async Task<IEnumerable<User>> SearchUsersAsync(string searchTerm, string category)
    {
        var users = new List<User>();
        
        // VULNERABLE: Direct string concatenation in SQL query
        var query = $@"
            SELECT Id, Username, Email, FirstName, LastName, Role, CreatedAt 
            FROM Users 
            WHERE (Username LIKE '%{searchTerm}%' OR Email LIKE '%{searchTerm}%')
            AND Category = '{category}'
            ORDER BY Username";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        await connection.OpenAsync();
        using var reader = await command.ExecuteReaderAsync();
        
        while (await reader.ReadAsync())
        {
            users.Add(MapUserFromReader(reader));
        }

        return users;
    }

    /// <summary>
    /// VULNERABLE: SQL Injection through dynamic WHERE clause
    /// </summary>
    public async Task<IEnumerable<User>> FilterUsersByRoleAsync(string role)
    {
        var users = new List<User>();
        
        // VULNERABLE: User input directly embedded in query
        var query = $"SELECT * FROM Users WHERE Role = '{role}' AND Active = 1";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        await connection.OpenAsync();
        using var reader = await command.ExecuteReaderAsync();
        
        while (await reader.ReadAsync())
        {
            users.Add(MapUserFromReader(reader));
        }

        return users;
    }

    /// <summary>
    /// VULNERABLE: SQL Injection through dynamic ORDER BY
    /// </summary>
    public async Task<IEnumerable<User>> GetSortedUsersAsync(string sortBy)
    {
        var users = new List<User>();
        
        // VULNERABLE: ORDER BY clause injection
        var query = $@"
            SELECT Id, Username, Email, FirstName, LastName, Role, CreatedAt 
            FROM Users 
            ORDER BY {sortBy}"; // Direct injection point

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        await connection.OpenAsync();
        using var reader = await command.ExecuteReaderAsync();
        
        while (await reader.ReadAsync())
        {
            users.Add(MapUserFromReader(reader));
        }

        return users;
    }

    /// <summary>
    /// VULNERABLE: Direct execution of user-controlled SQL
    /// </summary>
    public async Task<IEnumerable<User>> ExecuteCustomQueryAsync(string query)
    {
        var users = new List<User>();
        
        // VULNERABLE: Executing user-provided SQL directly
        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            using var reader = await command.ExecuteReaderAsync();
            
            while (await reader.ReadAsync())
            {
                users.Add(MapUserFromReader(reader));
            }
        }
        catch
        {
            // Silently ignore errors - poor practice
        }

        return users;
    }

    /// <summary>
    /// SAFE: Parameterized query example for contrast
    /// </summary>
    public async Task<User?> GetUserByIdAsync(int userId)
    {
        // SAFE: Using parameterized query
        var query = "SELECT Id, Username, Email, FirstName, LastName, Role, CreatedAt FROM Users WHERE Id = @userId";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        command.Parameters.AddWithValue("@userId", userId);
        
        await connection.OpenAsync();
        using var reader = await command.ExecuteReaderAsync();
        
        if (await reader.ReadAsync())
        {
            return MapUserFromReader(reader);
        }

        return null;
    }

    /// <summary>
    /// VULNERABLE: SQL Injection in logging
    /// </summary>
    public async Task LogImportActionAsync(string message)
    {
        // VULNERABLE: User-controlled data in INSERT statement
        var query = $"INSERT INTO AuditLog (Message, Timestamp) VALUES ('{message}', GETDATE())";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            await command.ExecuteNonQueryAsync();
        }
        catch
        {
            // Silently ignore logging errors
        }
    }

    /// <summary>
    /// VULNERABLE: SQL Injection in authentication logging
    /// </summary>
    public async Task LogAuthenticationAttemptAsync(string username, string domain, bool success)
    {
        // VULNERABLE: Multiple injection points
        var query = $@"
            INSERT INTO AuthLog (Username, Domain, Success, Timestamp) 
            VALUES ('{username}', '{domain}', {(success ? 1 : 0)}, GETDATE())";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            await command.ExecuteNonQueryAsync();
        }
        catch
        {
            // Silently ignore logging errors
        }
    }

    /// <summary>
    /// VULNERABLE: SQL Injection in search logging
    /// </summary>
    public async Task LogDirectorySearchAsync(string searchFilter, string domain, int resultCount)
    {
        // VULNERABLE: User input in logging query
        var query = $@"
            INSERT INTO SearchLog (SearchFilter, Domain, ResultCount, Timestamp) 
            VALUES ('{searchFilter}', '{domain}', {resultCount}, GETDATE())";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            await command.ExecuteNonQueryAsync();
        }
        catch
        {
            // Silently ignore logging errors
        }
    }

    /// <summary>
    /// VULNERABLE: SQL Injection in error logging
    /// </summary>
    public async Task LogErrorAsync(string errorMessage)
    {
        // VULNERABLE: Error messages containing user data
        var query = $"INSERT INTO ErrorLog (Message, Timestamp) VALUES ('{errorMessage}', GETDATE())";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            await command.ExecuteNonQueryAsync();
        }
        catch
        {
            // Recursive logging could occur here
        }
    }

    /// <summary>
    /// VULNERABLE: SQL Injection in password complexity check
    /// </summary>
    public async Task<bool> CheckPasswordComplexityAsync(string username, string password)
    {
        // VULNERABLE: Password data in query
        var query = $@"
            SELECT COUNT(*) FROM PasswordRules 
            WHERE Username = '{username}' 
            AND CHARINDEX('{password}', RestrictedPasswords) > 0";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            var result = await command.ExecuteScalarAsync();
            return Convert.ToInt32(result) == 0; // No restricted patterns found
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// VULNERABLE: SQL Injection in password history retrieval
    /// </summary>
    public async Task<IEnumerable<string>> GetPasswordHistoryAsync(string username)
    {
        var passwords = new List<string>();
        
        // VULNERABLE: Username directly in query
        var query = $"SELECT PasswordHash FROM PasswordHistory WHERE Username = '{username}' ORDER BY CreatedAt DESC";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            using var reader = await command.ExecuteReaderAsync();
            
            while (await reader.ReadAsync())
            {
                passwords.Add(reader.GetString("PasswordHash"));
            }
        }
        catch
        {
            // Return empty list on error
        }

        return passwords;
    }

    /// <summary>
    /// VULNERABLE: SQL Injection in password history check
    /// </summary>
    public async Task<bool> IsPasswordInHistoryAsync(string username, string passwordHash)
    {
        // VULNERABLE: Both parameters directly concatenated
        var query = $@"
            SELECT COUNT(*) FROM PasswordHistory 
            WHERE Username = '{username}' AND PasswordHash = '{passwordHash}'";

        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(query, connection);
        
        try
        {
            await connection.OpenAsync();
            var result = await command.ExecuteScalarAsync();
            return Convert.ToInt32(result) > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Helper method to map SqlDataReader to User object
    /// </summary>
    private User MapUserFromReader(SqlDataReader reader)
    {
        return new User
        {
            Id = reader.GetInt32("Id"),
            Username = reader.GetString("Username"),
            Email = reader.GetString("Email"),
            FirstName = reader.GetString("FirstName"),
            LastName = reader.GetString("LastName"),
            Role = reader.GetString("Role"),
            CreatedAt = reader.GetDateTime("CreatedAt")
        };
    }
}

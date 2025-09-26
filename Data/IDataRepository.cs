using SonarCSharpDemo.Models;

namespace SonarCSharpDemo.Data;

public interface IDataRepository
{
    Task<IEnumerable<User>> SearchUsersAsync(string searchTerm, string category);
    Task<IEnumerable<User>> FilterUsersByRoleAsync(string role);
    Task<IEnumerable<User>> GetSortedUsersAsync(string sortBy);
    Task<IEnumerable<User>> ExecuteCustomQueryAsync(string query);
    Task<User?> GetUserByIdAsync(int userId);
    Task LogImportActionAsync(string message);
    Task LogAuthenticationAttemptAsync(string username, string domain, bool success);
    Task LogDirectorySearchAsync(string searchFilter, string domain, int resultCount);
    Task LogErrorAsync(string errorMessage);
    Task<bool> CheckPasswordComplexityAsync(string username, string password);
    Task<IEnumerable<string>> GetPasswordHistoryAsync(string username);
    Task<bool> IsPasswordInHistoryAsync(string username, string passwordHash);
}

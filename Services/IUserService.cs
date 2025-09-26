using SonarCSharpDemo.Models;

namespace SonarCSharpDemo.Services;

public interface IUserService
{
    Task<IEnumerable<User>> SearchUsersAsync(string searchTerm, string category);
    Task<IEnumerable<User>> PerformAdvancedSearchAsync(UserSearchRequest request);
    Task<User?> GetUserByIdAsync(int userId);
    Task<string> ImportUsersFromSourceAsync(string source, string format);
    Task<bool> AuthenticateUserAsync(string username, string password, string domain);
    Task<IEnumerable<User>> SearchDirectoryUsersAsync(string searchFilter, string domain);
    Task<bool> ValidatePasswordComplexityAsync(string username, string password);
    Task<bool> CheckPasswordHistoryAsync(string username, string password);
}

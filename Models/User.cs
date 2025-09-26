namespace SonarCSharpDemo.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class UserSearchRequest
{
    public string SearchTerm { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string SortBy { get; set; } = string.Empty;
}

public class ReportRequest
{
    public string ReportType { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Template { get; set; } = string.Empty;
}

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
}

using Microsoft.AspNetCore.Mvc;
using SonarCSharpDemo.Models;
using SonarCSharpDemo.Services;

namespace SonarCSharpDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }

    /// <summary>
    /// VULNERABLE: SQL Injection through search parameter
    /// Untrusted input flows from HTTP request -> Service -> Data layer
    /// </summary>
    [HttpGet("search")]
    public async Task<IActionResult> SearchUsers([FromQuery] string searchTerm, [FromQuery] string category = "all")
    {
        // Taint source: User input from query parameter
        var users = await _userService.SearchUsersAsync(searchTerm, category);
        return Ok(users);
    }

    /// <summary>
    /// VULNERABLE: SQL Injection through POST body
    /// Complex taint flow through multiple service methods
    /// </summary>
    [HttpPost("advanced-search")]
    public async Task<IActionResult> AdvancedSearch([FromBody] UserSearchRequest request)
    {
        // Taint source: User input from request body
        var results = await _userService.PerformAdvancedSearchAsync(request);
        return Ok(results);
    }

    /// <summary>
    /// VULNERABLE: XSS through unsanitized output
    /// User input is returned directly in response
    /// </summary>
    [HttpGet("profile/{userId}")]
    public async Task<IActionResult> GetUserProfile(int userId, [FromQuery] string displayName = "")
    {
        var user = await _userService.GetUserByIdAsync(userId);
        if (user == null)
            return NotFound();

        // VULNERABLE: Unsanitized user input reflected in response
        var response = new
        {
            User = user,
            DisplayName = displayName, // Potential XSS if not escaped
            Message = $"Welcome back, {displayName}!" // Direct reflection of user input
        };

        return Ok(response);
    }

    /// <summary>
    /// VULNERABLE: Command Injection through user data processing
    /// </summary>
    [HttpPost("import")]
    public async Task<IActionResult> ImportUsers([FromQuery] string source, [FromQuery] string format)
    {
        // Taint source: User input that will flow to command execution
        var result = await _userService.ImportUsersFromSourceAsync(source, format);
        return Ok(result);
    }
}

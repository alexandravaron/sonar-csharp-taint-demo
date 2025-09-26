using Microsoft.AspNetCore.Mvc;
using SonarCSharpDemo.Models;
using SonarCSharpDemo.Services;

namespace SonarCSharpDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IUserService _userService;

    public AuthController(IUserService userService)
    {
        _userService = userService;
    }

    /// <summary>
    /// VULNERABLE: LDAP Injection
    /// User input flows to LDAP queries
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // Taint source: User credentials from request body
        try
        {
            var isAuthenticated = await _userService.AuthenticateUserAsync(
                request.Username, 
                request.Password, 
                request.Domain);

            if (isAuthenticated)
            {
                return Ok(new { Message = "Authentication successful" });
            }
            else
            {
                return Unauthorized(new { Message = "Invalid credentials" });
            }
        }
        catch (Exception ex)
        {
            return BadRequest($"Authentication error: {ex.Message}");
        }
    }

    /// <summary>
    /// VULNERABLE: LDAP Injection through user search
    /// Complex taint flow through service layer
    /// </summary>
    [HttpGet("users/directory")]
    public async Task<IActionResult> SearchDirectory([FromQuery] string searchFilter, [FromQuery] string domain = "corp")
    {
        // Taint source: User input from query parameters
        try
        {
            var users = await _userService.SearchDirectoryUsersAsync(searchFilter, domain);
            return Ok(users);
        }
        catch (Exception ex)
        {
            return BadRequest($"Directory search error: {ex.Message}");
        }
    }

    /// <summary>
    /// VULNERABLE: Weak password validation with injection potential
    /// User input flows to multiple validation methods
    /// </summary>
    [HttpPost("validate-password")]
    public async Task<IActionResult> ValidatePassword([FromQuery] string username, [FromBody] string password)
    {
        // Taint source: User input from query and body
        try
        {
            var validationResult = await _userService.ValidatePasswordComplexityAsync(username, password);
            var historyCheck = await _userService.CheckPasswordHistoryAsync(username, password);
            
            return Ok(new 
            { 
                IsValid = validationResult && historyCheck,
                Message = $"Password validation completed for user: {username}"
            });
        }
        catch (Exception ex)
        {
            return BadRequest($"Password validation error: {ex.Message}");
        }
    }
}

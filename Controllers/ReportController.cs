using Microsoft.AspNetCore.Mvc;
using SonarCSharpDemo.Models;
using SonarCSharpDemo.Utils;

namespace SonarCSharpDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ReportController : ControllerBase
{
    private readonly FileManager _fileManager;
    private readonly ReportGenerator _reportGenerator;

    public ReportController(FileManager fileManager, ReportGenerator reportGenerator)
    {
        _fileManager = fileManager;
        _reportGenerator = reportGenerator;
    }

    /// <summary>
    /// VULNERABLE: Path Traversal
    /// User input flows to file system operations
    /// </summary>
    [HttpGet("download/{fileName}")]
    public async Task<IActionResult> DownloadReport(string fileName)
    {
        // Taint source: User input from route parameter
        try
        {
            var fileContent = await _fileManager.ReadFileAsync(fileName);
            return File(fileContent, "application/octet-stream", fileName);
        }
        catch (Exception ex)
        {
            return BadRequest($"Error reading file: {ex.Message}");
        }
    }

    /// <summary>
    /// VULNERABLE: Path Traversal and Command Injection
    /// Multiple taint flows in single endpoint
    /// </summary>
    [HttpPost("generate")]
    public async Task<IActionResult> GenerateReport([FromBody] ReportRequest request)
    {
        // Taint source: User input from request body
        try
        {
            // Path traversal vulnerability
            await _fileManager.EnsureDirectoryExistsAsync(request.FileName);
            
            // Command injection vulnerability
            var reportContent = await _reportGenerator.GenerateReportAsync(
                request.ReportType, 
                request.Template);

            // More path traversal
            await _fileManager.WriteFileAsync(request.FileName, reportContent);

            return Ok(new { Message = "Report generated successfully", FileName = request.FileName });
        }
        catch (Exception ex)
        {
            return BadRequest($"Error generating report: {ex.Message}");
        }
    }

    /// <summary>
    /// VULNERABLE: Server-Side Request Forgery (SSRF)
    /// User input flows to HTTP requests
    /// </summary>
    [HttpPost("fetch-template")]
    public async Task<IActionResult> FetchExternalTemplate([FromQuery] string templateUrl)
    {
        // Taint source: User-controlled URL
        try
        {
            var template = await _reportGenerator.FetchTemplateFromUrlAsync(templateUrl);
            return Ok(new { Template = template });
        }
        catch (Exception ex)
        {
            return BadRequest($"Error fetching template: {ex.Message}");
        }
    }

    /// <summary>
    /// VULNERABLE: XML External Entity (XXE) Injection
    /// User input flows to XML processing
    /// </summary>
    [HttpPost("process-xml")]
    public async Task<IActionResult> ProcessXmlReport([FromBody] string xmlContent)
    {
        // Taint source: User-provided XML content
        try
        {
            var result = await _reportGenerator.ProcessXmlTemplateAsync(xmlContent);
            return Ok(result);
        }
        catch (Exception ex)
        {
            return BadRequest($"Error processing XML: {ex.Message}");
        }
    }
}

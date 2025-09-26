using System.Diagnostics;
using System.Net.Http;
using System.Xml;

namespace SonarCSharpDemo.Utils;

public class ReportGenerator
{
    private readonly HttpClient _httpClient;

    public ReportGenerator()
    {
        _httpClient = new HttpClient();
    }

    /// <summary>
    /// VULNERABLE: Command Injection in report generation
    /// User input flows to system command execution
    /// </summary>
    public async Task<string> GenerateReportAsync(string reportType, string template)
    {
        try
        {
            // VULNERABLE: Direct command execution with user input
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/sh",
                    Arguments = $"-c \"generate_report --type {reportType} --template '{template}'\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            // Additional vulnerable command execution
            await ExecuteCustomCommandAsync($"echo 'Report generated: {reportType}' >> /tmp/report.log");

            return output;
        }
        catch (Exception ex)
        {
            return $"Error generating report: {ex.Message}";
        }
    }

    /// <summary>
    /// VULNERABLE: Server-Side Request Forgery (SSRF)
    /// User-controlled URL flows to HTTP request
    /// </summary>
    public async Task<string> FetchTemplateFromUrlAsync(string templateUrl)
    {
        try
        {
            // VULNERABLE: No URL validation - can access internal services
            // Could access localhost, internal IPs, or cloud metadata endpoints
            var response = await _httpClient.GetAsync(templateUrl);
            
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                
                // Additional SSRF vulnerability - making second request based on first response
                if (content.Contains("redirect_url:"))
                {
                    var redirectUrl = ExtractRedirectUrl(content);
                    var redirectResponse = await _httpClient.GetAsync(redirectUrl);
                    return await redirectResponse.Content.ReadAsStringAsync();
                }
                
                return content;
            }
            else
            {
                return $"Failed to fetch template: {response.StatusCode}";
            }
        }
        catch (Exception ex)
        {
            return $"Error fetching template: {ex.Message}";
        }
    }

    /// <summary>
    /// VULNERABLE: XML External Entity (XXE) Injection
    /// User-provided XML processed without security restrictions
    /// </summary>
    public async Task<string> ProcessXmlTemplateAsync(string xmlContent)
    {
        try
        {
            // VULNERABLE: XML processing with external entities enabled
            var xmlDoc = new XmlDocument();
            
            // Enable DTD processing and external entities (DANGEROUS)
            var xmlReaderSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver() // Allows external entity resolution
            };
            
            using var stringReader = new StringReader(xmlContent);
            using var xmlReader = XmlReader.Create(stringReader, xmlReaderSettings);
            
            xmlDoc.Load(xmlReader);
            
            // Process the XML document
            var result = ProcessXmlNodes(xmlDoc.DocumentElement);
            
            await Task.CompletedTask;
            return result;
        }
        catch (Exception ex)
        {
            return $"Error processing XML: {ex.Message}";
        }
    }

    /// <summary>
    /// VULNERABLE: Additional command injection through XML processing
    /// </summary>
    private string ProcessXmlNodes(XmlNode? node)
    {
        if (node == null) return "";
        
        var result = "";
        foreach (XmlNode childNode in node.ChildNodes)
        {
            if (childNode.Name == "command")
            {
                // VULNERABLE: Executing commands from XML content
                var command = childNode.InnerText;
                result += ExecuteCommandUnsafely(command);
            }
            else if (childNode.Name == "include")
            {
                // VULNERABLE: Including files based on XML content (XXE-like)
                var filePath = childNode.Attributes?["src"]?.Value;
                if (!string.IsNullOrEmpty(filePath))
                {
                    try
                    {
                        result += File.ReadAllText(filePath);
                    }
                    catch
                    {
                        result += $"[Could not include file: {filePath}]";
                    }
                }
            }
            else
            {
                result += ProcessXmlNodes(childNode);
            }
        }
        
        return result;
    }

    /// <summary>
    /// VULNERABLE: Unsafe command execution
    /// </summary>
    private string ExecuteCommandUnsafely(string command)
    {
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/sh",
                    Arguments = $"-c \"{command}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            
            return output;
        }
        catch
        {
            return "[Command execution failed]";
        }
    }

    /// <summary>
    /// VULNERABLE: More command injection with different parameter
    /// </summary>
    public async Task ExecuteCustomCommandAsync(string command)
    {
        try
        {
            // VULNERABLE: Direct execution of user-provided command
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }
            };

            process.Start();
            await process.WaitForExitAsync();
        }
        catch
        {
            // Silently ignore errors
        }
    }

    /// <summary>
    /// VULNERABLE: URL extraction that could be exploited
    /// </summary>
    private string ExtractRedirectUrl(string content)
    {
        // Simplistic extraction - vulnerable to injection
        var startIndex = content.IndexOf("redirect_url:") + "redirect_url:".Length;
        var endIndex = content.IndexOf('\n', startIndex);
        
        if (endIndex == -1) endIndex = content.Length;
        
        return content.Substring(startIndex, endIndex - startIndex).Trim();
    }

    /// <summary>
    /// VULNERABLE: File processing with multiple injection points
    /// </summary>
    public async Task<string> ProcessReportFileAsync(string filePath, string processor)
    {
        try
        {
            // VULNERABLE: Path traversal
            var content = await File.ReadAllTextAsync(filePath);
            
            // VULNERABLE: Command injection through processor parameter
            var processCommand = $"{processor} --input \"{filePath}\" --output processed_output.txt";
            
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{processCommand}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            return output;
        }
        catch (Exception ex)
        {
            return $"Error processing file: {ex.Message}";
        }
    }

    /// <summary>
    /// VULNERABLE: Template rendering with potential for template injection
    /// </summary>
    public async Task<string> RenderTemplateAsync(string template, Dictionary<string, string> parameters)
    {
        var result = template;
        
        // VULNERABLE: Direct string replacement without sanitization
        foreach (var param in parameters)
        {
            // This could lead to template injection if the template engine processes special syntax
            result = result.Replace($"{{{param.Key}}}", param.Value);
            
            // Additional vulnerability: evaluating expressions from user input
            if (param.Key.StartsWith("eval_"))
            {
                try
                {
                    // DANGEROUS: Would evaluate user-provided code in real implementation
                    var evalResult = $"[Evaluated: {param.Value}]";
                    result = result.Replace($"{{{param.Key}}}", evalResult);
                }
                catch
                {
                    // Silently ignore evaluation errors
                }
            }
        }
        
        await Task.CompletedTask;
        return result;
    }

    /// <summary>
    /// Dispose resources
    /// </summary>
    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}

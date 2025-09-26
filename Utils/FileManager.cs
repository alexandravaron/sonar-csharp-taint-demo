using System.IO;

namespace SonarCSharpDemo.Utils;

public class FileManager
{
    private readonly string _baseDirectory;

    public FileManager(IConfiguration configuration)
    {
        _baseDirectory = configuration["ReportsPath"] ?? "/var/reports/";
    }

    /// <summary>
    /// VULNERABLE: Path Traversal
    /// User input flows directly to file system operations
    /// </summary>
    public async Task<byte[]> ReadFileAsync(string fileName)
    {
        // VULNERABLE: No path validation - allows ../../../etc/passwd
        var filePath = Path.Combine(_baseDirectory, fileName);
        
        if (File.Exists(filePath))
        {
            return await File.ReadAllBytesAsync(filePath);
        }
        
        throw new FileNotFoundException($"File not found: {fileName}");
    }

    /// <summary>
    /// VULNERABLE: Path Traversal in file writing
    /// </summary>
    public async Task WriteFileAsync(string fileName, string content)
    {
        // VULNERABLE: User-controlled file path
        var filePath = Path.Combine(_baseDirectory, fileName);
        
        // Create directory if it doesn't exist (also vulnerable)
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }
        
        await File.WriteAllTextAsync(filePath, content);
    }

    /// <summary>
    /// VULNERABLE: Directory Traversal
    /// </summary>
    public async Task EnsureDirectoryExistsAsync(string path)
    {
        // VULNERABLE: User can create directories anywhere
        var fullPath = Path.Combine(_baseDirectory, path);
        var directory = Path.GetDirectoryName(fullPath);
        
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }
        
        await Task.CompletedTask;
    }

    /// <summary>
    /// VULNERABLE: Directory listing with path traversal
    /// </summary>
    public async Task<string[]> ListFilesAsync(string directory = "")
    {
        // VULNERABLE: User can list any directory on the system
        var targetDirectory = string.IsNullOrEmpty(directory) 
            ? _baseDirectory 
            : Path.Combine(_baseDirectory, directory);
            
        if (Directory.Exists(targetDirectory))
        {
            return await Task.FromResult(Directory.GetFiles(targetDirectory));
        }
        
        return Array.Empty<string>();
    }

    /// <summary>
    /// VULNERABLE: File deletion with path traversal
    /// </summary>
    public async Task<bool> DeleteFileAsync(string fileName)
    {
        try
        {
            // VULNERABLE: Can delete any file the application has access to
            var filePath = Path.Combine(_baseDirectory, fileName);
            
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
                return true;
            }
        }
        catch
        {
            // Silently ignore errors
        }
        
        await Task.CompletedTask;
        return false;
    }

    /// <summary>
    /// VULNERABLE: Archive extraction with Zip Slip
    /// </summary>
    public async Task<string> ExtractArchiveAsync(string archivePath, string extractTo)
    {
        try
        {
            // VULNERABLE: No validation of archive entry paths
            // This would be vulnerable to Zip Slip attacks in real implementation
            var targetDirectory = Path.Combine(_baseDirectory, extractTo);
            
            // Simulated extraction - in real code this would use ZipFile.ExtractToDirectory
            // which is vulnerable without path validation
            Directory.CreateDirectory(targetDirectory);
            
            return $"Extracted archive {archivePath} to {targetDirectory}";
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to extract archive: {ex.Message}");
        }
    }

    /// <summary>
    /// VULNERABLE: File copy with path traversal on both source and destination
    /// </summary>
    public async Task<bool> CopyFileAsync(string sourceFile, string destinationFile)
    {
        try
        {
            // VULNERABLE: Both paths user-controlled
            var sourcePath = Path.Combine(_baseDirectory, sourceFile);
            var destPath = Path.Combine(_baseDirectory, destinationFile);
            
            if (File.Exists(sourcePath))
            {
                // Create destination directory if needed
                var destDirectory = Path.GetDirectoryName(destPath);
                if (!string.IsNullOrEmpty(destDirectory))
                {
                    Directory.CreateDirectory(destDirectory);
                }
                
                File.Copy(sourcePath, destPath, overwrite: true);
                return true;
            }
        }
        catch
        {
            // Silently ignore errors
        }
        
        await Task.CompletedTask;
        return false;
    }

    /// <summary>
    /// VULNERABLE: Symbolic link creation (on Unix systems)
    /// </summary>
    public async Task<bool> CreateSymbolicLinkAsync(string linkPath, string targetPath)
    {
        try
        {
            // VULNERABLE: Can create symbolic links to arbitrary locations
            var fullLinkPath = Path.Combine(_baseDirectory, linkPath);
            var fullTargetPath = Path.Combine(_baseDirectory, targetPath);
            
            // On Windows, this might require elevated permissions
            // On Unix systems, this could be used for privilege escalation
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                // Simulated - in real code would use File.CreateSymbolicLink()
                await Task.Delay(10); // Simulate async operation
                return true;
            }
        }
        catch
        {
            // Silently ignore errors
        }
        
        return false;
    }
}

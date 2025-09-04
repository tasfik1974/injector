# DLL Injection Script for HD-Player.exe
# Requires administrative privileges

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

function Inject-DLL {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProcessName,
        
        [Parameter(Mandatory=$true)]
        [string]$DllName
    )
    
    # Get desktop path and construct full DLL path
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $dllPath = Join-Path $desktopPath $DllName
    
    # Check if DLL exists
    if (-not (Test-Path $dllPath)) {
        Write-Error "DLL file not found: $dllPath"
        return $false
    }
    
    # Find process by name
    $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if (-not $processes) {
        Write-Error "Process '$ProcessName' not found or not running"
        Write-Host "Please make sure HD-Player.exe is running before executing this script." -ForegroundColor Yellow
        return $false
    }
    
    # If multiple processes found, use the first one
    if ($processes.Count -gt 1) {
        Write-Warning "Multiple HD-Player processes found. Using the first one (PID: $($processes[0].Id))"
    }
    
    $processId = $processes[0].Id
    Write-Host "Target Process: $ProcessName (PID: $processId)" -ForegroundColor Cyan
    Write-Host "DLL Path: $dllPath" -ForegroundColor Cyan
    
    # Convert DLL path to UTF8 bytes
    $dllPathBytes = [System.Text.Encoding]::UTF8.GetBytes($dllPath)
    $size = [uint32]$dllPathBytes.Length + 1
    
    # Process access rights
    $PROCESS_ALL_ACCESS = 0x1F0FFF
    
    try {
        # Open the target process
        $hProcess = [Injector]::OpenProcess($PROCESS_ALL_ACCESS, $false, $processId)
        if ($hProcess -eq [IntPtr]::Zero) {
            Write-Error "Failed to open process. Make sure you're running as Administrator. Error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            return $false
        }
        
        # Allocate memory in the target process
        $allocAddr = [Injector]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, 0x3000, 0x4) # MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        if ($allocAddr -eq [IntPtr]::Zero) {
            Write-Error "Failed to allocate memory in target process. Error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            [Injector]::CloseHandle($hProcess)
            return $false
        }
        
        # Write DLL path to allocated memory
        $bytesWritten = [UIntPtr]::Zero
        $success = [Injector]::WriteProcessMemory($hProcess, $allocAddr, $dllPathBytes, $size, [ref]$bytesWritten)
        if (-not $success -or $bytesWritten -eq [UIntPtr]::Zero) {
            Write-Error "Failed to write to process memory. Error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            [Injector]::CloseHandle($hProcess)
            return $false
        }
        
        # Get address of LoadLibraryA function
        $hKernel32 = [Injector]::GetModuleHandle("kernel32.dll")
        $loadLibraryAddr = [Injector]::GetProcAddress($hKernel32, "LoadLibraryA")
        if ($loadLibraryAddr -eq [IntPtr]::Zero) {
            Write-Error "Failed to get LoadLibraryA address. Error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            [Injector]::CloseHandle($hProcess)
            return $false
        }
        
        # Create remote thread that calls LoadLibraryA with our DLL path
        $hThread = [Injector]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocAddr, 0, [IntPtr]::Zero)
        if ($hThread -eq [IntPtr]::Zero) {
            Write-Error "Failed to create remote thread. Error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            [Injector]::CloseHandle($hProcess)
            return $false
        }
        
        # Wait for the thread to finish
        $result = [Injector]::WaitForSingleObject($hThread, 10000)
        if ($result -eq 0xFFFFFFFF) {
            Write-Warning "Thread wait may have failed or timed out"
        }
        
        # Clean up
        [Injector]::CloseHandle($hThread)
        [Injector]::CloseHandle($hProcess)
        
        Write-Host "DLL injection completed successfully!" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "An error occurred during DLL injection: $($_.Exception.Message)"
        return $false
    }
}

# Display running processes for reference
Write-Host "`nRunning processes:" -ForegroundColor Yellow
Get-Process | Where-Object {$_.Name -like "*hd-player*" -or $_.Name -like "*HD-Player*"} | Format-Table Id, Name, CPU -AutoSize

# Inject DLL into HD-Player.exe
Write-Host "`nAttempting to inject DLL into HD-Player.exe..." -ForegroundColor Yellow
$result = Inject-DLL -ProcessName "HD-Player" -DllName "Neck F8 F9 (Sound F10).dll"

if ($result) {
    Write-Host "Injection successful! The DLL should now be loaded in HD-Player.exe." -ForegroundColor Green
} else {
    Write-Host "Injection failed. Please check the error messages above." -ForegroundColor Red
}

# Pause to see the output
Write-Host "`nPress any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

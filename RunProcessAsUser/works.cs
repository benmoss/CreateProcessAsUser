// https://blogs.msdn.microsoft.com/alejacma/2007/12/20/how-to-call-createprocesswithlogonw-createprocessasuser-in-net/
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CreateProcessSample
{
    class Win32
    {
        #region "CONTS"

        const UInt32 INFINITE = 0xFFFFFFFF;
        const UInt32 WAIT_FAILED = 0xFFFFFFFF;
        private const int HANDLE_FLAG_INHERIT = 1;
        private static uint STARTF_USESHOWWINDOW = 0x00000001;
        private static uint STARTF_USESTDHANDLES = 0x00000100;
        private static short SW_HIDE = 0;
        private static uint CREATE_NEW_CONSOLE = 0x00000010;

        #endregion

        #region "ENUMS"

        [Flags]

        public enum LogonType
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9
        }

        [Flags]
        public enum LogonProvider
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35,
            LOGON32_PROVIDER_WINNT40,
            LOGON32_PROVIDER_WINNT50
        }

        #endregion

        #region "STRUCTS"

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public String lpReserved;
            public String lpDesktop;

            public String lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public uint dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public SafeFileHandle hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessId;
            public Int32 dwThreadId;
        }

        public struct SECURITY_ATTRIBUTES
        {
            public int length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        #endregion

        #region "FUNCTIONS (P/INVOKE)"

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean LogonUser
        (
            String lpszUserName,
            String lpszDomain,
            String lpszPassword,
            LogonType dwLogonType,
            LogonProvider dwLogonProvider,
            out IntPtr phToken
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CreateProcessAsUser
        (
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            Boolean bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        public static extern Boolean CreateProcessWithLogonW
        (
            String lpszUsername,
            String lpszDomain,
            String lpszPassword,
            Int32 dwLogonFlags,
            String applicationName,
            String commandLine,
            Int32 creationFlags,
            IntPtr environment,
            String currentDirectory,
            ref STARTUPINFO sui,
            out PROCESS_INFORMATION processInfo
        );

        [DllImport("kernel32.dll", SetLastError = true)]

        public static extern UInt32 WaitForSingleObject
        (
            IntPtr hHandle,
            UInt32 dwMilliseconds
        );

        [DllImport("kernel32", SetLastError=true)]
        public static extern Boolean CloseHandle (IntPtr handle);

        [DllImport("kernel32.dll")]
        static extern bool CreatePipe(out SafeFileHandle phReadPipe, out SafeFileHandle phWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll")]
        static extern bool SetHandleInformation(SafeFileHandle hObject, int dwMask, uint dwFlags);

        #endregion

        #region "FUNCTIONS"

        public static void CreateProcessAsUserWrapper(string command, string domain, string username, string password)
        {
            // Variables
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            STARTUPINFO startInfo = new STARTUPINFO();
            Boolean bResult = false;
            IntPtr hToken = IntPtr.Zero;
            UInt32 uiResultWait = WAIT_FAILED;
            SafeFileHandle hReadIn, hReadOut, hWriteIn, hWriteOut;

            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
            securityAttributes.bInheritHandle = true;

            CreatePipe(out hReadOut, out hWriteOut, ref securityAttributes, 0);
            SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);

            try
            {
                // Logon user
                bResult = Win32.LogonUser(
                    username,
                    domain,
                    password,
                    Win32.LogonType.LOGON32_LOGON_INTERACTIVE,
                    Win32.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                    out hToken
                );
                if (!bResult) { throw new Exception("Logon error #" + Marshal.GetLastWin32Error()); }

                // Create process
                startInfo.cb = Marshal.SizeOf(startInfo);
                startInfo.dwFlags = STARTF_USESTDHANDLES;
                startInfo.hStdOutput = hWriteOut;

                bResult = Win32.CreateProcessAsUser(
                    hToken,
                    null,
                    command,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    0,
                    IntPtr.Zero,
                    null,
                    ref startInfo,
                    out processInfo
                );

                startInfo.hStdOutput.Close();
                if (!bResult) { throw new Exception("CreateProcessAsUser error #" + Marshal.GetLastWin32Error()); }

                // Wait for process to end
                uiResultWait = WaitForSingleObject(processInfo.hProcess, INFINITE);
                if (uiResultWait == WAIT_FAILED) { throw new Exception("WaitForSingleObject error #" + Marshal.GetLastWin32Error()); }

                const int bufferSize = 0x1000;
                var standardOutput = new StreamReader(new FileStream(hReadOut, FileAccess.Read, bufferSize, false), Console.OutputEncoding, true, bufferSize);
                Console.WriteLine("GOT STDOUT: ``{0}``", standardOutput.ReadToEnd());

            }
            finally
            {
                // Close all handles
                CloseHandle(hToken);
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);
            }
        }
        #endregion
    }
}
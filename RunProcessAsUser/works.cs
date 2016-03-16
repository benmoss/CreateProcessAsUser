// https://blogs.msdn.microsoft.com/alejacma/2007/12/20/how-to-call-createprocesswithlogonw-createprocessasuser-in-net/
using System;
using System.Runtime.InteropServices;

namespace CreateProcessSample
{
    class Win32
    {
        #region "CONTS"

        const UInt32 INFINITE = 0xFFFFFFFF;
        const UInt32 WAIT_FAILED = 0xFFFFFFFF;

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
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
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
            Int32 dwCreationFlags,
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

        #endregion

        #region "FUNCTIONS"

        public static void CreateProcessAsUserWrapper(string strCommand, string strDomain, string strName, string strPassword)
        {
            // Variables
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            STARTUPINFO startInfo = new STARTUPINFO();
            Boolean bResult = false;
            IntPtr hToken = IntPtr.Zero;
            UInt32 uiResultWait = WAIT_FAILED;

            try
            {
                // Logon user
                bResult = Win32.LogonUser(
                    strName,
                    strDomain,
                    strPassword,
                    Win32.LogonType.LOGON32_LOGON_INTERACTIVE,
                    Win32.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                    out hToken
                );
                if (!bResult) { throw new Exception("Logon error #" + Marshal.GetLastWin32Error()); }

                // Create process
                startInfo.cb = Marshal.SizeOf(startInfo);
                startInfo.lpDesktop = "winsta0\\default";

                bResult = Win32.CreateProcessAsUser(
                    hToken,
                    null,
                    strCommand,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    0,
                    IntPtr.Zero,
                    null,
                    ref startInfo,
                    out processInfo
                );

                if (!bResult) { throw new Exception("CreateProcessAsUser error #" + Marshal.GetLastWin32Error()); }

                // Wait for process to end
                uiResultWait = WaitForSingleObject(processInfo.hProcess, INFINITE);
                if (uiResultWait == WAIT_FAILED) { throw new Exception("WaitForSingleObject error #" + Marshal.GetLastWin32Error()); }
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
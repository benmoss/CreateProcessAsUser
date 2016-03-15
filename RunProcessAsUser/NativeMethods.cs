using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RunProcessAsUser
{
    internal partial class NativeMethods
    {
        public static void LaunchChildProcess(NetworkCredential creds, string childProcName)
        {
            var lpStartupInfo = new STARTUPINFO();
            var stdoutParentHandle = (SafeFileHandle)null;
            //var stderrParentHandle = (SafeFileHandle) null;

            //EasyCreatePipe(out stdoutParentHandle, out lpStartupInfo.hStdOutput);
            //lpStartupInfo.dwFlags = 256;
            //EasyCreatePipe(out stderrParentHandle, out lpStartupInfo.hStdOutput);

            var hToken = Utils.LogonAndGetUserPrimaryToken(creds).DangerousGetHandle();
            // Launch the child process interactively
            // with the token of the logged-on user.
            PROCESS_INFORMATION tProcessInfo;

            Console.Out.WriteLine(hToken);
            bool ChildProcStarted = CreateProcessAsUser(
                hToken, // Token of the logged-on user.
                childProcName, // Name of the process to be started.
                null, // Any command line arguments to be passed.
                IntPtr.Zero, // Default Process' attributes.
                IntPtr.Zero, // Default Thread's attributes.
                false, // Does NOT inherit parent's handles.
                0, // No any specific creation flag.
                null, // Default environment path.
                null, // Default current directory.
                ref lpStartupInfo, // Process Startup Info.
                out tProcessInfo // Process information to be returned.
            );

            if (ChildProcStarted)
            {
                // The child process creation is successful!

                // If the child process is created, it can be controlled via the out
                // param "tProcessInfo". For now, as we don't want to do any thing
                // with the child process, closing the child process' handles
                // to prevent the handle leak.
                CloseHandle(tProcessInfo.hThread);
                CloseHandle(tProcessInfo.hProcess);
            }
            else
            {
                // CreateProcessAsUser failed!
                Console.WriteLine("CreateProcessAsUser failed!");
            }

            // Whether child process was created or not, close the token handle
            // and break the loop as processing for current active user has been done.
            CloseHandle(hToken);
        }

        private static void EasyCreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle)
        {
            var lpPipeAttributes = new SecurityAttributes();
            lpPipeAttributes.bInheritHandle = true;
            var safeFileHandle = (SafeFileHandle) null;
            try
            {
                if (!CreatePipe(out safeFileHandle, out childHandle, lpPipeAttributes, 0))
                {
                    throw new Win32Exception();
                }
                if (!DuplicateHandle(
                    Process.GetCurrentProcess().Handle,
                    safeFileHandle,
                    Process.GetCurrentProcess().Handle,
                    out parentHandle, 0, false, 2))
                  throw new Win32Exception();
            }
            finally
            {
                if (safeFileHandle != null && !safeFileHandle.IsInvalid)
                {
                    safeFileHandle.Close();
                }
            }
        }

        #region P/Invoke WTS APIs

        /// <summary>
        /// Struct, Enum and P/Invoke Declarations of WTS APIs.
        /// </summary>
        ///

        private const int WTS_CURRENT_SERVER_HANDLE = 0;

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct WTS_SESSION_INFO
        {
            public UInt32 SessionID;
            public string pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe,
            SecurityAttributes lpPipeAttributes, int nSize);

        [DllImport("WTSAPI32.DLL", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            [MarshalAs(UnmanagedType.U4)] UInt32 Reserved,
            [MarshalAs(UnmanagedType.U4)] UInt32 Version,
            ref IntPtr ppSessionInfo,
            [MarshalAs(UnmanagedType.U4)] ref UInt32 pSessionInfoCount
            );

        [DllImport("WTSAPI32.DLL", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("WTSAPI32.DLL", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool WTSQueryUserToken(UInt32 sessionId, out IntPtr Token);

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           SafeHandle hSourceHandle, IntPtr hTargetProcessHandle, out SafeFileHandle lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        #endregion


        #region P/Invoke CreateProcessAsUser

        /// <summary>
        /// Struct, Enum and P/Invoke Declarations for CreateProcessAsUser.
        /// </summary>
        ///

        [StructLayout(LayoutKind.Sequential)]
        internal class STARTUPINFO
        {
            public IntPtr lpReserved = IntPtr.Zero;
            public IntPtr lpDesktop = IntPtr.Zero;
            public IntPtr lpTitle = IntPtr.Zero;
            public IntPtr lpReserved2 = IntPtr.Zero;
            public SafeFileHandle hStdInput = new SafeFileHandle(IntPtr.Zero, false);
            public SafeFileHandle hStdOutput = new SafeFileHandle(IntPtr.Zero, false);
            public SafeFileHandle hStdError = new SafeFileHandle(IntPtr.Zero, false);
            public int cb;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;

            public STARTUPINFO()
            {
                this.cb = Marshal.SizeOf(this);
            }

            public void Dispose()
            {
                if (this.hStdInput != null && !this.hStdInput.IsInvalid)
                {
                    this.hStdInput.Close();
                    this.hStdInput = (SafeFileHandle) null;
                }
                if (this.hStdOutput != null && !this.hStdOutput.IsInvalid)
                {
                    this.hStdOutput.Close();
                    this.hStdOutput = (SafeFileHandle) null;
                }
                if (this.hStdError == null || this.hStdError.IsInvalid)
                    return;
                this.hStdError.Close();
                this.hStdError = (SafeFileHandle) null;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class PROCESS_INFORMATION
        {
            public IntPtr hProcess = IntPtr.Zero;
            public IntPtr hThread = IntPtr.Zero;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("ADVAPI32.DLL", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            string lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
            );

        #endregion

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean LogonUser(
            String lpszUserName,
            String lpszDomain,
            String lpszPassword,
            LogonType dwLogonType,
            LogonProvider dwLogonProvider,
            out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            SecurityAttributes lpTokenAttributes,
            SecurityImpersonationLevel impersonationLevel,
            TokenType tokenType,
            out IntPtr hNewToken);

        [Flags]
        public enum LogonType
        {
            LOGON32_LOGON_INTERACTIVE       = 2,
            LOGON32_LOGON_NETWORK           = 3,
            LOGON32_LOGON_BATCH             = 4,
            LOGON32_LOGON_SERVICE           = 5,
            LOGON32_LOGON_UNLOCK            = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS   = 9
        }

        [Flags]
        public enum LogonProvider
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35,
            LOGON32_PROVIDER_WINNT40,
            LOGON32_PROVIDER_WINNT50
        }

        public enum SecurityImpersonationLevel
        {
            SecurityAnonymous      = 0,
            SecurityIdentification = 1,
            SecurityImpersonation  = 2,
            SecurityDelegation     = 3
        }

        public enum TokenType
        {
            TokenPrimary       = 1, 
            TokenImpersonation = 2
        } 

        [StructLayout(LayoutKind.Sequential)]
        public class SecurityAttributes
        {
            public Int32 Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;

            public SecurityAttributes()
            {
                this.Length = Marshal.SizeOf(this); 
            }
        }


        public class Constants
        {
            public const Int32  GENERIC_ALL_ACCESS = 0x10000000;
            public const UInt32 INFINITE = 0xFFFFFFFF;
            public const UInt32 WAIT_FAILED = 0xFFFFFFFF;

            public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000u;
            public const uint STANDARD_RIGHTS_READ = 0x00020000u;
            public const uint TOKEN_ASSIGN_PRIMARY = 0x0001u;
            public const uint TOKEN_DUPLICATE = 0x0002u;
            public const uint TOKEN_IMPERSONATE = 0x0004u;
            public const uint TOKEN_QUERY = 0x0008u;
            public const uint TOKEN_QUERY_SOURCE = 0x0010u;
            public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020u;
            public const uint TOKEN_ADJUST_GROUPS = 0x0040u;
            public const uint TOKEN_ADJUST_DEFAULT = 0x0080u;
            public const uint TOKEN_ADJUST_SESSIONID = 0x0100u;
            public const uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
            public const uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID);

            public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

            public const uint ERROR_ACCESS_DENIED = 5u;
            public const uint ERROR_INSUFFICIENT_BUFFER = 122u;
            public const uint ERROR_MORE_DATA = 0x000000EA; }
    }
}

using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace murrayju.ProcessExtensions
{
    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        #region DllImports

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        #endregion

        #region Win32 Structs

        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }

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

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }

        #endregion

        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;

                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;

                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }

            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);

                CloseHandle(hImpersonationToken);
            }

            return bResult;
        }

        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;

            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            try
            {
                var creds = new NetworkCredential("greenhouse", "cat9lives");
                hUserToken = LogonAndGetUserPrimaryToken(creds).DangerousGetHandle();

                //if (!GetSessionUserToken(ref hUserToken))
                //{
                //    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                //}

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                //startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                //startInfo.lpDesktop = "winsta0\\default";

                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                    //throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }

                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                    //throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                }
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }

            return true;
        }

        public static SafeUserTokenHandle LogonAndGetUserPrimaryToken(NetworkCredential credential)
        {
            IntPtr token = IntPtr.Zero;
            IntPtr primaryToken = IntPtr.Zero;

            try
            {
                if (RevertToSelf())
                {
                    if (LogonUser(credential.UserName, ".", credential.Password,
                        LogonType.LOGON32_LOGON_INTERACTIVE,
                        LogonProvider.LOGON32_PROVIDER_DEFAULT,
                        out token))
                    {

                        if (DuplicateTokenEx(
                            token,
                            0x10000000,
                            IntPtr.Zero,
                            (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                            1,
                            ref primaryToken))
                        {
                            return new SafeUserTokenHandle(primaryToken);
                        }
                        else
                        {
                            throw new Win32Exception();
                        }
                    }
                    else
                    {
                        throw new Win32Exception();
                    }
                }
                else
                {
                    throw new Win32Exception();
                }
            }
            finally
            {
                if (token != IntPtr.Zero)
                {
                    CloseHandle(token);
                }
            }
        }


        public sealed class SafeUserTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeUserTokenHandle()
                : base(true)
            {
            }

            public SafeUserTokenHandle(IntPtr existingHandle)
                : base(true)
            {
                base.SetHandle(existingHandle);
            }

            public static explicit operator IntPtr(SafeUserTokenHandle userTokenHandle)
            {
                return userTokenHandle.DangerousGetHandle();
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(this.handle);
            }
        }


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
    }
}

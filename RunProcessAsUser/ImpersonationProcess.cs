﻿using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace RunProcessAsUser
{
    internal class ImpersonationProcess
    {

        //private const string CommandLine = @"C:\createjobobject.exe";
        private NativeMethods.ProcessInformation processInfo;
        private readonly ManualResetEvent exited = new ManualResetEvent(false);


        public IntPtr Handle { get; private set; }
        public event EventHandler Exited;
        public TextReader StandardOutput { get; private set; }
        public TextReader StandardError { get; private set; }
        public TextWriter StandardInput { get; private set; }

        public void WaitForExit()
        {
            WaitForExit(-1);
        }

        public bool WaitForExit(int milliseconds)
        {
            return exited.WaitOne(milliseconds);
        }

        public bool Start(string username, string password, string domain)
        {
            string codeBase = Assembly.GetExecutingAssembly().CodeBase;
            var uri = new UriBuilder(codeBase);
            string path = Uri.UnescapeDataString(uri.Path);
            var assemblyDir =  Path.GetDirectoryName(path);
            var exePath = Path.Combine(assemblyDir, "..", "..", "..", "createjobobject\\bin\\debug\\createjobobject.exe");

            processInfo = new NativeMethods.ProcessInformation();
            var startInfo = new NativeMethods.StartupInfo();
            var success = false;

            SafeFileHandle hToken, hReadOut, hWriteOut, hReadErr, hWriteErr, hReadIn, hWriteIn;

            var securityAttributes = new NativeMethods.SecurityAttributes();
            securityAttributes.bInheritHandle = true;

            success = NativeMethods.CreatePipe(out hReadOut, out hWriteOut, securityAttributes, 0);
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            success = NativeMethods.CreatePipe(out hReadErr, out hWriteErr, securityAttributes, 0);
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            success = NativeMethods.CreatePipe(out hReadIn, out hWriteIn, securityAttributes, 0);
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            success = NativeMethods.SetHandleInformation(hReadOut, NativeMethods.Constants.HANDLE_FLAG_INHERIT, 0);
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            // Logon user
            success = NativeMethods.LogonUser(
                username,
                domain,
                password,
                NativeMethods.LogonType.LOGON32_LOGON_BATCH,
                NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                out hToken
            );
            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            IntPtr unmanagedEnv;
            if (!NativeMethods.CreateEnvironmentBlock(out unmanagedEnv, hToken.DangerousGetHandle(), false))
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new Win32Exception(lastError, "Error calling CreateEnvironmentBlock: " + lastError);
            }

            // Create process
            startInfo.cb = Marshal.SizeOf(startInfo);
            startInfo.dwFlags = NativeMethods.Constants.STARTF_USESTDHANDLES;
            startInfo.hStdOutput = hWriteOut;
            startInfo.hStdError = hWriteErr;
            startInfo.hStdInput = hReadIn;

            success = NativeMethods.CreateProcessAsUser(
                hToken,
                null,
                exePath,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                NativeMethods.CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT,
                unmanagedEnv,
                null,
                ref startInfo,
                out processInfo
            );

            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            Handle = processInfo.hProcess;

            startInfo.hStdOutput.Close();
            startInfo.hStdError.Close();
            startInfo.hStdInput.Close();
            StandardOutput = new StreamReader(new FileStream(hReadOut, FileAccess.Read), Console.OutputEncoding);
            StandardError = new StreamReader(new FileStream(hReadErr, FileAccess.Read), Console.OutputEncoding);
            StandardInput = new StreamWriter(new FileStream(hWriteIn, FileAccess.Write), Console.InputEncoding);

            WaitForExitAsync();

            return success;
        }

        private void WaitForExitAsync()
        {
            var thr = new Thread(() =>
            {
                NativeMethods.WaitForSingleObject(processInfo.hProcess, NativeMethods.Constants.INFINITE);
                if (Exited != null) Exited(this, EventArgs.Empty);
                exited.Set();
            });
            thr.Start();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace pipe_cs
{

    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
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

    public struct SECURITY_ATTRIBUTES
    {
        public int length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    class Program
    {

        [DllImport("kernel32.dll")]
        static extern int CloseHandle(int hObject);
        [DllImport("kernel32.dll")]
        static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
        [DllImport("kernel32.dll")]
        static extern int GetExitCodeProcess(int hProcess, ref int lpExitCode);
        [DllImport("kernel32.dll")]
        static extern bool CreatePipe(out IntPtr phReadPipe, out IntPtr phWritePipe, IntPtr lpPipeAttributes, uint nSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern unsafe bool ReadFile(
        IntPtr hfile,
        void* pBuffer,
        int NumberOfBytesToRead,
        int* pNumberOfBytesRead,
        int pOverlapped
        );
        [DllImport("kernel32.dll")]
        static extern bool CreateProcess(string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetStdHandle(int StdHandle);
        [DllImport("kernel32.dll")]
        static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);
        [DllImport("kernel32.dll")]
        static extern bool SetHandleInformation(IntPtr hObject, int dwMask, uint dwFlags);
        [DllImport("kernel32", SetLastError = true)]
        static extern IntPtr CreateFile(string filename,
        uint desiredAccess,
        uint shareMode,
        IntPtr attributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

        public static unsafe int Read(byte[] buffer, int index, int count, IntPtr hStdOut)
        {
            int n = 0;
            fixed (byte* p = buffer)
            {
                if (!ReadFile(hStdOut, p + index, count, &n, 0))
                    return 0;
            }
            return n;
        }

        private static uint STARTF_USESHOWWINDOW = 0x00000001;
        private static uint STARTF_USESTDHANDLES = 0x00000100;
        private static uint STARTF_FORCEONFEEDBACK = 0x00000040;
        private static uint NORMAL_PRIORITY_CLASS = 0x00000020;
        private static uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        private static uint CREATE_NO_WINDOW = 0x08000000;
        private static uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private static short SW_SHOW = 5;
        private static short SW_HIDE = 0;
        private const int STD_OUTPUT_HANDLE = -11;
        private const int HANDLE_FLAG_INHERIT = 1;
        private static uint GENERIC_READ = 0x80000000;
        private static uint FILE_ATTRIBUTE_READONLY = 0x00000001;
        private static uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const int OPEN_EXISTING = 3;
        private static uint CREATE_NEW_CONSOLE = 0x00000010;
        private static uint STILL_ACTIVE = 0x00000103;

        public static void RunPing()
        {
            STARTUPINFO si;
            SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
            PROCESS_INFORMATION pi;
            IntPtr hReadIn, hReadOut, hWriteIn, hWriteOut;
            IntPtr hStdout;
            IntPtr hInputFile;

            //set the bInheritHandle flag so pipe handles are inherited

            saAttr.bInheritHandle = true;
            saAttr.lpSecurityDescriptor = IntPtr.Zero;
            saAttr.length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            saAttr.lpSecurityDescriptor = IntPtr.Zero;
            //get handle to current stdOut
            //hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
            //create pipe for child process's stdout

            bool bret;

            IntPtr mypointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(STARTUPINFO)));
            Marshal.StructureToPtr(saAttr, mypointer, true);
            bret = CreatePipe(out hReadOut, out hWriteOut, mypointer, 0);
            //ensure the read handle to pipe for stdout is not inherited
            SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);
            //SetHandleInformation(hWriteOut, HANDLE_FLAG_INHERIT, 0);
            ////Create pipe for the child process's STDIN
            //bret = CreatePipe(out hReadIn, out hWriteIn, IntPtr.Zero, 1024);
            bret = CreatePipe(out hReadIn, out hWriteIn, mypointer, 1024);

            ////ensure the write handle to the pipe for stdin is not inherited

            SetHandleInformation(hWriteIn, HANDLE_FLAG_INHERIT, 0);

            si = new STARTUPINFO();
            si.cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(si);
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE; // SW_HIDE; //SW_SHOW
            si.hStdOutput = hWriteOut;
            si.hStdError = hWriteOut;
            si.hStdInput = hWriteIn;

            //Create the child process

            bret = CreateProcess("C:\\WINDOWS\\SYSTEM32\\PING.EXE", //
            "PING.EXE 192.168.0.1", //null, 
            IntPtr.Zero,
            IntPtr.Zero,
            true,
            CREATE_NEW_CONSOLE, //NORMAL_PRIORITY_CLASS | CREATE_BREAKAWAY_FROM_JOB | CREATE_UNICODE_ENVIRONMENT,// | CREATE_NO_WINDOW,
            IntPtr.Zero,
            null,
            ref si,
            out pi);

            if (bret == false)
            {
                int lasterr = Marshal.GetLastWin32Error();
            }

            int ret;
            ret = WaitForSingleObject(pi.hProcess, 100000);
            Console.Write("WaitForSingleObject returned " + ret);
            //ret==258 (0x102) - not signalled, ret==0 ok!
            byte[] buffer = new byte[2048];

            ret = Read(buffer, 0, buffer.Length, hReadOut);
            String outs = Encoding.ASCII.GetString(buffer, 0, ret);
            Console.Write(outs);
        }

    }
}
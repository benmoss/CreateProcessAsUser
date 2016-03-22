using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace createjobobject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

        static void Main(string[] args)
        {
            MakeJobObject();
        }


        public static void MakeJobObject()
        {
            Console.WriteLine("RUNNING");
            var token = CreateJobObject(IntPtr.Zero, "HelloJobObject");

            if (token == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            Console.WriteLine("Token: {0}", token);

        }
    }
}
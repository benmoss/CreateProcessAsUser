using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace RunProcessAsUser
{
    class Program
    {
        static void Main(string[] args)
        {
            //NativeMethods.LaunchChildProcess(new NetworkCredential("greenhouse", "cat9lives"), "dir");
            //murrayju.ProcessExtensions.ProcessExtensions.StartProcessAsCurrentUser(@"C:\Windows\System32\cmd.exe");
            CreateProcessSample.Win32.LaunchCommand2("ping -t 127.0.0.1", ".", "foobar", "foobar");
        }
    }
}

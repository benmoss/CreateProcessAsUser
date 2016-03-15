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
            murrayju.ProcessExtensions.ProcessExtensions.StartProcessAsCurrentUser("C:\\windows\\system32\\calc.exe");
        }
    }
}

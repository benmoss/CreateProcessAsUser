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
            while (true)
            {
                Console.ReadLine();
                CreateProcessSample.Win32.CreateProcessAsUserWrapper("ping 127.0.0.1", ".", "foobar", "foobar");
            }
            //pipe_cs.Program.RunPing();
        }
    }
}

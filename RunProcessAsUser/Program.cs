using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            var process = new ImpersonationProcess();

            process.Start("foobar", "foobar", ".");

            Console.WriteLine("output: {0}", process.StandardOutput.ReadToEnd());

            Console.ReadLine();
        }
    }
}

﻿using System;
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
            CreateProcessSample.Win32.CreateProcessAsUserWrapper("ping -t 127.0.0.1", ".", "foobar", "foobar");
        }
    }
}

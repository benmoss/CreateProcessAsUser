# CreateProcessAsUser

This project attempts to use `CreateProcessAsUser` to run a process as a different user. 
We are exploring this syscall because the syscall used by C#'s `Process` class is `CreateProcessWithLogonW` which 
[does not work when run as the SYSTEM user](https://blogs.msdn.microsoft.com/winsdk/2009/07/14/launching-an-interactive-process-from-windows-service-in-windows-vista-and-later/).

In order to run the `CreateProcessAsUser` syscall, you must grant the current user the privilege to "Replace a process level token". The `SYSTEM` user has this by default.

In order to run this project, create a user named `foobar` with the password `foobar` and add it to the `IIS_IUSRS` group. This will allow it to logon locally.

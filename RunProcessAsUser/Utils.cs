using System;
using System.ComponentModel;
using System.Net;
using Microsoft.Win32.SafeHandles;

namespace RunProcessAsUser
{
    internal static class Utils
    {
        public static SafeUserTokenHandle LogonAndGetUserPrimaryToken(NetworkCredential credential)
        {
            IntPtr token = IntPtr.Zero;
            IntPtr primaryToken = IntPtr.Zero;

            try
            {
                if (NativeMethods.RevertToSelf())
                {
                    if (NativeMethods.LogonUser(credential.UserName, ".", credential.Password,
                        NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE,
                        NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                        out token))
                    {
                        var sa = new NativeMethods.SecurityAttributes();

                        if (NativeMethods.DuplicateTokenEx(
                            token,
                            NativeMethods.Constants.GENERIC_ALL_ACCESS,
                            sa,
                            NativeMethods.SecurityImpersonationLevel.SecurityImpersonation,
                            NativeMethods.TokenType.TokenPrimary,
                            out primaryToken))
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
                    NativeMethods.CloseHandle(token);
                }
            }
        }
    }

    internal sealed class SafeUserTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeUserTokenHandle() : base(true)
        {
        }

        public SafeUserTokenHandle(IntPtr existingHandle) : base(true)
        {
            base.SetHandle(existingHandle);
        }

        public static explicit operator IntPtr(SafeUserTokenHandle userTokenHandle)
        {
            return userTokenHandle.DangerousGetHandle();
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(this.handle);
        }
    }
}


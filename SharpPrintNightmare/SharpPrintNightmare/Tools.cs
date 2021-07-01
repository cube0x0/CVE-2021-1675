using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;


namespace Tools
{
    public class Impersonator
    {
        //Reference https://stackoverflow.com/questions/22544903/impersonate-for-entire-application-lifecycle

        [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
        public class Impersonation : IDisposable
        {
            private readonly SafeTokenHandle _handle;
            private readonly WindowsImpersonationContext _context;

            private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;

            public Impersonation(string domain, string username, string password)
            {
                var ok = LogonUser(username, domain, password,
                               LOGON32_LOGON_NEW_CREDENTIALS, 0, out this._handle);
                if (!ok)
                {
                    var errorCode = Marshal.GetLastWin32Error();
                    throw new ApplicationException(string.Format("Could not impersonate the elevated user.  LogonUser returned error code {0}.", errorCode));
                }

                this._context = WindowsIdentity.Impersonate(this._handle.DangerousGetHandle());
            }

            public void Dispose()
            {
                this._context.Dispose();
                this._handle.Dispose();
            }

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

            public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                private SafeTokenHandle()
                    : base(true) { }

                [DllImport("kernel32.dll")]
                [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
                [SuppressUnmanagedCodeSecurity]
                [return: MarshalAs(UnmanagedType.Bool)]
                private static extern bool CloseHandle(IntPtr handle);

                protected override bool ReleaseHandle()
                {
                    return CloseHandle(handle);
                }
            }
        }
    }

    public class AToken
    {
        // Based on SharpSploit MakeToken
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("Advapi32.dll", SetLastError = true)]
        private static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUserA(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LOGON_TYPE dwLogonType,
            LOGON_PROVIDER dwLogonProvider,
            ref IntPtr phToken);

        [Flags]
        public enum LOGON_TYPE : uint
        {
            LOGON32_LOGON_INTERACTIVE = 2, //will not work for sacrify, still active
            LOGON32_LOGON_NETWORK, //will not work for sacrify, still active
            LOGON32_LOGON_BATCH, //will not work for sacrify, still active
            LOGON32_LOGON_SERVICE, //will not work for sacrify, still active
            LOGON32_LOGON_UNLOCK = 7, //will not work for sacrify, still active
            LOGON32_LOGON_NETWORK_CLEARTEXT, //will not work for sacrify, still active
            LOGON32_LOGON_NEW_CREDENTIALS
        }

        [Flags]
        public enum LOGON_PROVIDER : uint
        {
            LOGON32_PROVIDER_DEFAULT,
            LOGON32_PROVIDER_WINNT35,
            LOGON32_PROVIDER_WINNT40,
            LOGON32_PROVIDER_WINNT50
        }

        public static bool MakeToken(string Username, string Domain, string Password, LOGON_TYPE LogonType = LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS)
        {
            IntPtr hProcessToken = IntPtr.Zero;
            if (!LogonUserA(
                Username, Domain, Password,
                LogonType,
                LOGON_PROVIDER.LOGON32_PROVIDER_WINNT50,
                ref hProcessToken))
            {
                Console.Error.WriteLine("LogonUserA() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            if (!ImpersonateLoggedOnUser(hProcessToken))
            {
                Console.Error.WriteLine("ImpersonateLoggedOnUser() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                CloseHandle(hProcessToken);
                return false;
            }
            return true;
        }

        public static bool RevertFromToken()
        {
            if (!RevertToSelf())
            {
                Console.Error.WriteLine("RevertToSelf() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            return true;
        }
    }
}
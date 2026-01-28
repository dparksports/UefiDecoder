using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UefiDecoder
{
    class Program
    {
        // --- Known GUIDs for Context ---
        static readonly Guid EFI_GLOBAL_VARIABLE = new Guid("8be4df61-93ca-11d2-aa0d-00e098032b8c");
        static readonly Guid EFI_IMAGE_SECURITY_DATABASE = new Guid("d719b2cb-3d3a-4596-a3bc-dad00e67656f");
        
        // --- Attribute Constants ---
        const uint EFI_VARIABLE_NON_VOLATILE = 0x00000001;
        const uint EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002;
        const uint EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004;

        static void Main(string[] args)
        {
            Console.WriteLine("--- Antigravity UEFI Decoder ---\n");

            if (!PrivilegeManager.EnablePrivilege("SeSystemEnvironmentPrivilege"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ACCESS DENIED: Please run this terminal as Administrator.");
                Console.ResetColor();
                return;
            }

            var variables = EnumUefiVariables();
            Console.WriteLine($"Found {variables.Count} variables. Deciphering contents...\n");

            foreach (var v in variables)
            {
                byte[] data = GetUefiVariableEx(v.Name, v.Guid.ToString("B"), out uint attrs);
                if (data == null) continue;

                // --- The "Understanding" Logic ---
                // We decide how to print based on the Name and GUID
                
                if (v.Guid == EFI_IMAGE_SECURITY_DATABASE && (v.Name == "db" || v.Name == "dbx" || v.Name == "KEK" || v.Name == "PK"))
                {
                    PrintHeader(v.Name, v.Guid, data.Length);
                    ParseSignatureList(data);
                }
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
                else if (v.Name == "SecureBoot" || v.Name == "SetupMode" || v.Name == "AuditMode" || v.Name == "DeployedMode")
                {
                    PrintHeader(v.Name, v.Guid, data.Length);
                    ParseBoolean(data);
                }
                // (Optional) Add more custom parsers here
            }

            Console.WriteLine("\nDone.");
        }

        static void PrintHeader(string name, Guid guid, int size)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"[{name}] ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"{guid} ({size} bytes)");
            Console.ResetColor();
        }

        // --- Decoders ---

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
                if (i + 1 < data.Length)
                {
                    ushort id = BitConverter.ToUInt16(data, i);
                    Console.Write($"{id:X4} ");
                }
            }
            Console.WriteLine();
        }

        static void ParseBootOption(byte[] data)
        {
            // EFI_LOAD_OPTION Structure:
            // UINT32 Attributes;
            // UINT16 FilePathListLength;
            // CHAR16 Description[]; <-- Null terminated
            // EFI_DEVICE_PATH_PROTOCOL FilePathList[];
            
            if (data.Length < 6) return;

            // Skip Attributes (4) + PathLength (2) = 6 bytes
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

        static void ParseSignatureList(byte[] data)
        {
            // EFI_SIGNATURE_LIST structure
            int offset = 0;
            int certCount = 0;

            try 
            {
                while (offset < data.Length)
                {
                    if (offset + 28 > data.Length) break; // Safety check

                    // 1. Signature Type GUID (16 bytes)
                    byte[] guidBytes = new byte[16];
                    Array.Copy(data, offset, guidBytes, 0, 16);
                    Guid typeGuid = new Guid(guidBytes);

                    // 2. List Size (4 bytes)
                    int listSize = BitConverter.ToInt32(data, offset + 16);
                    
                    // 3. Header Size (4 bytes)
                    int headerSize = BitConverter.ToInt32(data, offset + 20);

                    // 4. Signature Size (4 bytes)
                    int signatureSize = BitConverter.ToInt32(data, offset + 24);

                    // Parse the Signatures in this list
                    int currentSigOffset = offset + 28 + headerSize; // Skip header
                    int endOfList = offset + listSize;

                    while (currentSigOffset < endOfList)
                    {
                        // EFI_SIGNATURE_DATA
                        // First 16 bytes is Signature Owner GUID
                        // The rest is the data (Certificate)
                        
                        if (currentSigOffset + 16 > data.Length) break;

                        // Check if it's an X509 cert (X509 GUID: a5c059a1-94e4-4138-87ab-5a5cd152628f)
                        // Or just try to parse it as one.
                        
                        int payloadSize = signatureSize - 16;
                        if (payloadSize > 0 && currentSigOffset + 16 + payloadSize <= data.Length)
                        {
                            byte[] certBytes = new byte[payloadSize];
                            Array.Copy(data, currentSigOffset + 16, certBytes, 0, payloadSize);

                            try
                            {
                                var cert = new X509Certificate2(certBytes);
                                certCount++;
                                Console.WriteLine($"    Cert #{certCount}:");
                                Console.WriteLine($"      Subject: {cert.Subject}");
                                Console.WriteLine($"      Issuer:  {cert.Issuer}");
                                Console.WriteLine($"      Expires: {cert.GetExpirationDateString()}");
                            }
                            catch
                            {
                                // Not a parseable cert (might be a SHA256 hash in dbx)
                                Console.WriteLine("    [SHA256 Hash or Unknown Data]");
                            }
                        }
                        currentSigOffset += signatureSize;
                    }
                    offset += listSize;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Error parsing signature list: {ex.Message}");
            }
        }

        // --- Low Level Boilerplate (P/Invoke) ---

        static byte[] GetUefiVariableEx(string name, string guid, out uint attributes)
        {
            attributes = 0;
            uint size = 1024; // Start small
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                int result = NativeMethods.GetFirmwareEnvironmentVariableEx(name, guid, buffer, size, out attributes);
                if (result == 0 && Marshal.GetLastWin32Error() == 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    Marshal.FreeHGlobal(buffer);
                    size = 32768; // Bump up for dbx
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
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecureBootParser
{
    class Program
    {
        // Attribute Constants
        const uint EFI_VARIABLE_NON_VOLATILE = 0x00000001;
        const uint EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002;
        const uint EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004;
        const uint EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x00000010;
        const uint EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020;
        const uint EFI_VARIABLE_APPEND_WRITE = 0x00000040;

        static void Main(string[] args)
        {
            Console.WriteLine("Acquiring SeSystemEnvironmentPrivilege...");
            if (!PrivilegeManager.EnablePrivilege("SeSystemEnvironmentPrivilege"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FAILED: Access Denied. Run as Administrator.");
                return;
            }

            Console.WriteLine("Enumerating all UEFI variables...");
            var variables = EnumUefiVariables();
            
            Console.WriteLine($"Found {variables.Count} variables.\n");

            foreach (var v in variables)
            {
                PrintVariableInfo(v.Name, v.Guid.ToString("B"));
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nDone. Press any key to exit.");
            Console.ReadKey();
        }

        static void PrintVariableInfo(string name, string guidString)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Name: {name}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"Guid: {guidString}");

            uint attributes = 0;
            byte[] data = GetUefiVariableEx(name, guidString, out attributes);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Attributes: ");
            if (data != null)
            {
                var attrs = new List<string>();
                if ((attributes & EFI_VARIABLE_NON_VOLATILE) != 0) attrs.Add("NV");
                if ((attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS) != 0) attrs.Add("BS");
                if ((attributes & EFI_VARIABLE_RUNTIME_ACCESS) != 0) attrs.Add("RT");
                if ((attributes & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) != 0) attrs.Add("AUTH");
                if ((attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) attrs.Add("TIME_AUTH");
                
                Console.WriteLine(string.Join(" | ", attrs) + $" (0x{attributes:X})");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine($"Size: {data.Length} bytes");

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write("Value: ");

                if (IsBooleanVariable(name))
                {
                    PrintBooleanValue(data);
                }
                else if (name.Equals("BootOrder", StringComparison.OrdinalIgnoreCase))
                {
                    PrintBootOrder(data);
                }
                else if (IsBootOption(name))
                {
                    PrintBootOption(data);
                }
                else if (!TryPrintString(data))
                {
                    Console.WriteLine();
                    PrintHexDump(data);
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error reading variable or Empty");
            }
            Console.WriteLine();
        }

        static bool IsBooleanVariable(string name)
        {
            return name.Equals("SecureBoot", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("SetupMode", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("AuditMode", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("DeployedMode", StringComparison.OrdinalIgnoreCase);
        }

        static bool IsBootOption(string name)
        {
            return name.Length == 8 && name.StartsWith("Boot", StringComparison.OrdinalIgnoreCase) && 
                   int.TryParse(name.Substring(4), System.Globalization.NumberStyles.HexNumber, null, out _);
        }

        static void PrintBooleanValue(byte[] data)
        {
            if (data.Length == 1)
            {
                Console.WriteLine(data[0] == 1 ? "Enabled (1)" : "Disabled (0)");
            }
            else
            {
                Console.WriteLine($"INVALID BOOL (Len: {data.Length})");
                PrintHexDump(data);
            }
        }

        static void PrintBootOrder(byte[] data)
        {
            if (data.Length % 2 != 0)
            {
                Console.WriteLine("Invalid BootOrder length");
                PrintHexDump(data);
                return;
            }

            var order = new List<string>();
            for (int i = 0; i < data.Length; i += 2)
            {
                ushort id = BitConverter.ToUInt16(data, i);
                order.Add($"{id:X4}");
            }
            Console.WriteLine(string.Join(", ", order));
        }

        static void PrintBootOption(byte[] data)
        {
            // EFI_LOAD_OPTION: Attributes(4) + FilePathListLength(2) + Description(NullTerminatedString) + ...
            if (data.Length < 6)
            {
                Console.WriteLine("Invalid Boot Option Data");
                PrintHexDump(data);
                return;
            }

            try
            {
                // We just want the description
                // Skip Attributes (4 bytes) and FilePathListLength (2 bytes)
                // The existing code request said: "Skip the Attributes (4 bytes) and FilePathListLength (2 bytes) to extract and display the human-readable Description string"
                
                int index = 6;
                var sb = new StringBuilder();
                while (index < data.Length - 1)
                {
                    char c = BitConverter.ToChar(data, index);
                    if (c == '\0') break;
                    sb.Append(c);
                    index += 2;
                }
                Console.WriteLine(sb.ToString());
            }
            catch
            {
                Console.WriteLine("Error parsing Boot Option");
                PrintHexDump(data);
            }
        }

        static bool TryPrintString(byte[] data)
        {
            // Simple heuristic check
            // 1. Try UTF-16 (Unicode) - specific to UEFI
            // 2. Try ASCII 
            
            // UEFI uses UTF-16 mostly. Let's look for nulls in odd positions for simple text?
            // Or just try to convert and see if it looks readable.
            
            if (data.Length == 0) return true;

            // Check for pure ASCII printable (plus null terminator)
            bool isAscii = true;
            int printableAscii = 0;
            foreach (byte b in data)
            {
                if (b == 0) continue;
                if (b < 32 || b > 126) { isAscii = false; break; } // Not standard printable
                printableAscii++;
            }

            if (isAscii && printableAscii > 0)
            {
                Console.WriteLine(Encoding.ASCII.GetString(data).Trim('\0'));
                return true;
            }

            // Check for UTF-16 (Unicode)
            // Should be even length
            if (data.Length % 2 == 0)
            {
                string s = Encoding.Unicode.GetString(data);
                // Check if string contains mostly printable characters
                int printable = 0;
                bool valid = true;
                foreach (char c in s)
                {
                    if (c == '\0') continue;
                    if (char.IsControl(c) && c != '\t' && c != '\n' && c != '\r') { valid = false; break; }
                    printable++;
                }

                if (valid && printable > 0)
                {
                    Console.WriteLine(s.Trim('\0'));
                    return true;
                }
            }

            return false;
        }

        static void PrintHexDump(byte[] data)
        {
            for (int i = 0; i < data.Length; i += 16)
            {
                Console.Write($"{i:X4}: ");
                // Hex
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < data.Length) Console.Write($"{data[i + j]:X2} ");
                    else Console.Write("   ");
                }
                Console.Write("  ");
                // ASCII
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < data.Length)
                    {
                        byte b = data[i + j];
                        Console.Write((b >= 32 && b <= 126) ? (char)b : '.');
                    }
                }
                Console.WriteLine();
            }
        }

        static byte[] GetUefiVariableEx(string name, string guid, out uint attributes)
        {
            attributes = 0;
            // Grow buffer from 1KB to 64KB (usually enough for metadata/small vars)
            // For listing we might not need massive buffers unless reading dbx
            uint size = 1024;
            while (size <= 1024 * 1024) 
            {
                IntPtr buffer = Marshal.AllocHGlobal((int)size);
                try
                {
                    uint attr = 0;
                    int result = NativeMethods.GetFirmwareEnvironmentVariableEx(name, guid, buffer, size, out attr);
                    int error = Marshal.GetLastWin32Error();

                    if (result > 0)
                    {
                        attributes = attr;
                        byte[] data = new byte[result];
                        Marshal.Copy(buffer, data, 0, result);
                        return data;
                    }

                    if (error == 122) // ERROR_INSUFFICIENT_BUFFER
                    {
                        size *= 2;
                        continue;
                    }
                    
                    return null;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            return null;
        }

        // --- Enumeration Logic ---

        class UefiVar { public string Name; public Guid Guid; }

        static List<UefiVar> EnumUefiVariables()
        {
            var list = new List<UefiVar>();
            int len = 0;
            
            // First call to get length
            NativeMethods.NtEnumerateSystemEnvironmentValuesEx(1, IntPtr.Zero, ref len);
            
            // Allocate proper size
            IntPtr buffer = Marshal.AllocHGlobal(len);
            try
            {
                int status = NativeMethods.NtEnumerateSystemEnvironmentValuesEx(1, buffer, ref len);
                if (status != 0 && status != 0x40000000) // STATUS_SUCCESS or checks
                {
                    // If it fails, we might just be empty or permission denied
                    return list;
                }

                // Walk the buffer
                // Struct is: NextEntryOffset (4), VendorGuid (16), Name (Var)
                IntPtr current = buffer;
                while (true)
                {
                    int nextOffset = Marshal.ReadInt32(current);
                    
                    // Guid is at current + 4
                    byte[] guidBytes = new byte[16];
                    Marshal.Copy(new IntPtr(current.ToInt64() + 4), guidBytes, 0, 16);
                    Guid guid = new Guid(guidBytes);

                    // Name starts at current + 20
                    // It is a null-terminated WCHAR string
                    IntPtr namePtr = new IntPtr(current.ToInt64() + 20);
                    string name = Marshal.PtrToStringUni(namePtr);

                    list.Add(new UefiVar { Name = name, Guid = guid });

                    if (nextOffset == 0) break;
                    current = new IntPtr(current.ToInt64() + nextOffset);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Enumeration error: {ex.Message}");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            
            return list;
        }

    }

    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetFirmwareEnvironmentVariableEx(
            string lpName, 
            string lpGuid, 
            IntPtr pBuffer, 
            uint nSize, 
            out uint pdwAttributes);

        [DllImport("ntdll.dll")]
        public static extern int NtEnumerateSystemEnvironmentValuesEx(
            int InformationClass, // VARIABLE_INFORMATION = 1
            IntPtr Buffer,
            ref int BufferLength
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public long Luid; public uint Attributes; }
    }

    public static class PrivilegeManager
    {
        public static bool EnablePrivilege(string privilegeName)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!NativeMethods.OpenProcessToken(Process.GetCurrentProcess().Handle, NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY, out tokenHandle)) return false;
                NativeMethods.TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;
                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out tp.Luid)) return false;
                if (!NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
                return Marshal.GetLastWin32Error() == 0;
            }
            finally {}
        }
    }
}
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace ARSProtocolHandler
{
    class Program
    {
        static void Main(string[] args)
        {
            var newProvider = new CryptoProvider();
            var oldProvider = new OldCryptoProvider();

            // Encrypting with NEW alg
            var newHash = newProvider.EncryptString("Ars");
            Console.WriteLine(newHash);

            // Encrypting with OLD alg
            var oldHash = oldProvider.EncryptString("Ars");
            // Decrypting OLD hash with OLD alg
            var oldDescript  = oldProvider.DecryptString(oldHash);
            Console.WriteLine("OLD ALGORITHM:");
            Console.WriteLine(oldDescript);
            Console.WriteLine("--------------------");
            Console.WriteLine("NEW ALGORITHM:");
            // Decrypting NEW hash with OLD alg
            var newDescript = oldProvider.DecryptString(newHash);
            Console.WriteLine(newDescript);


        }

        public class OldCryptoProvider
        {
            private const string MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider";

            private const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
            private const uint CRYPT_NEWKEYSET = 0x00000008;
            private const uint PROV_RSA_AES = 24;
            private const uint CALG_SHA = 0x00008004;
            private const uint CALG_AES_256 = 0x00006610;

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptAcquireContext(out IntPtr phProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptCreateHash(IntPtr hProv, uint Algid, IntPtr hKey, uint dwFlags, out IntPtr phHash);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptHashData(IntPtr hHash, byte[] pbData, int dwDataLen, uint dwFlags);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptDeriveKey(IntPtr hProv, uint Algid, IntPtr hBaseData, uint dwFlags, ref IntPtr phKey);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptEncrypt(IntPtr hKey, IntPtr hHash, [MarshalAs(UnmanagedType.Bool)] bool Final, uint dwFlags, byte[] pbData, ref int pdwDataLen, int dwBufLen);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, [MarshalAs(UnmanagedType.Bool)] bool Final, uint dwFlags, byte[] pbData, ref int pdwDataLen);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptDestroyHash(IntPtr hHash);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptDestroyKey(IntPtr hKey);

            [DllImport("advapi32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

            private const string CRYPT_CONTROL_STRING = "pEwdsoPjEPvvmR4UDNlAelTdtP6dPHLCB4hP7"; //any long string
            private const string SIGN_ENCRYPTED_800 = "enc800"; //8.0.0 - use AES-256

            public OldCryptoProvider()
            {
            }

            public string EncryptString(string s)
            {
                return EncryptStringWithPassword(s, CRYPT_CONTROL_STRING);
            }

            public string EncryptStringWithPassword(string s, string password)
            {
                Byte[] Data = Encoding.Unicode.GetBytes(s);
                Byte[] Crypt = null;

                if (!EncryptData(Data, password, out Crypt))
                    return string.Empty;

                return SIGN_ENCRYPTED_800 + BinToHex(Crypt);
            }

            public string DecryptString(string s)
            {
                if (!StringIsEncrypted(s))
                    return string.Empty;

                string hex = s.Substring(SIGN_ENCRYPTED_800.Length);
                if (hex.Length % 2 != 0)
                    return string.Empty;

                Byte[] Crypt = HexToBin(hex);
                Byte[] Data = null;
                if (!DecryptData(Crypt, CRYPT_CONTROL_STRING, out Data))
                    return string.Empty;

                return Encoding.Unicode.GetString(Data);
            }

            public bool EncryptData(Byte[] Data, string Password, out Byte[] Crypt)
            {
                Crypt = null;
                byte[] passwordBytes = Encoding.Unicode.GetBytes(Password);
                IntPtr hProv = IntPtr.Zero;
                IntPtr hHash = IntPtr.Zero;
                IntPtr hKey = IntPtr.Zero;
                try
                {
                    if (!CryptAcquireContext(out hProv, null, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET) ||
                        !CryptCreateHash(hProv, CALG_SHA, IntPtr.Zero, 0, out hHash) ||
                        !CryptHashData(hHash, passwordBytes, Password.Length, 0) ||
                        !CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, ref hKey))
                        return false;

                    int CryptLength = Data.Length;
                    if (!CryptEncrypt(hKey, IntPtr.Zero, true, 0, null, ref CryptLength, 0))
                        return false;

                    Crypt = new Byte[CryptLength];
                    Data.CopyTo(Crypt, 0);
                    CryptLength = Data.Length;
                    if (!CryptEncrypt(hKey, IntPtr.Zero, true, 0, Crypt, ref CryptLength, Crypt.Length))
                    {
                        Crypt = null;
                        return false;
                    }

                    return true;
                }
                finally
                {
                    if (hKey != IntPtr.Zero)
                        CryptDestroyKey(hKey);
                    if (hHash != IntPtr.Zero)
                        CryptDestroyHash(hHash);
                    if (hProv != IntPtr.Zero)
                        CryptReleaseContext(hProv, 0);
                }
            }

            public bool DecryptData(Byte[] Crypt, string Password, out Byte[] Data)
            {
                Data = null;
                byte[] passwordBytes = Encoding.Unicode.GetBytes(Password);
                IntPtr hProv = IntPtr.Zero;
                IntPtr hHash = IntPtr.Zero;
                IntPtr hKey = IntPtr.Zero;
                try
                {
                    if (!CryptAcquireContext(out hProv, null, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET) ||
                        !CryptCreateHash(hProv, CALG_SHA, IntPtr.Zero, 0, out hHash) ||
                        !CryptHashData(hHash, passwordBytes, Password.Length, 0) ||
                        !CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, ref hKey))
                        return false;

                    Data = new Byte[Crypt.Length];
                    Crypt.CopyTo(Data, 0);
                    int dataLength = Crypt.Length;
                    if (!CryptDecrypt(hKey, IntPtr.Zero, true, 0, Data, ref dataLength))
                    {
                        Data = null;
                        return false;
                    }

                    Array.Resize(ref Data, dataLength);
                    return true;
                }
                finally
                {
                    if (hKey != IntPtr.Zero)
                        CryptDestroyKey(hKey);
                    if (hHash != IntPtr.Zero)
                        CryptDestroyHash(hHash);
                    if (hProv != IntPtr.Zero)
                        CryptReleaseContext(hProv, 0);
                }
            }

            public string EncryptStringArray(string[] strings)
            {
                return EncryptString(string.Join("\0", strings));
            }

            public string[] DecryptStringArray(string encString)
            {
                return DecryptString(encString).Split('\0');
            }

            public bool StringIsEncrypted(string s)
            {
                return s.StartsWith(SIGN_ENCRYPTED_800);
            }

            public byte[] HexToBin(string hex)
            {
                Byte[] bin = new Byte[hex.Length / 2];
                for (int n = 0; n < hex.Length; n += 2)
                    bin[n / 2] = Convert.ToByte(hex.Substring(n, 2), 16);
                return bin;
            }

            public string BinToHex(Byte[] bin)
            {
                StringBuilder hex = new StringBuilder(bin.Length * 2);
                foreach (Byte b in bin)
                    hex.AppendFormat("{0:X2}", b);
                return hex.ToString();
            }
        }

        public class CryptoProvider
        {
            private const string CRYPT_CONTROL_STRING = "pEwdsoPjEPvvmR4UDNlAelTdtP6dPHLCB4hP7";
            private const string SIGN_ENCRYPTED_800 = "enc800";

            public CryptoProvider()
            {
            }

            public string EncryptString(string s)
            {
                return EncryptStringWithPassword(s, CRYPT_CONTROL_STRING);
            }

            public string EncryptStringWithPassword(string s, string password)
            {
                byte[] dataToEncrypt = Encoding.Unicode.GetBytes(s);
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.KeySize = 256;
                    aesAlg.BlockSize = 128;
                    aesAlg.Key = DeriveKeyFromPassword(password, aesAlg.KeySize);
                    aesAlg.IV = Encoding.UTF8.GetBytes(SIGN_ENCRYPTED_800.PadRight(16));

                    byte[] encryptedData;
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                csEncrypt.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                            }
                        }
                        encryptedData = msEncrypt.ToArray();
                    }

                    return SIGN_ENCRYPTED_800 + BinToHex(encryptedData);
                }
            }

            public string DecryptString(string s)
            {
                if (!StringIsEncrypted(s))
                    return string.Empty;

                string hex = s.Substring(SIGN_ENCRYPTED_800.Length);
                if (hex.Length % 2 != 0)
                    return string.Empty;

                byte[] encryptedData = HexToBin(hex);
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.KeySize = 256;
                    aesAlg.BlockSize = 128;
                    aesAlg.Key = DeriveKeyFromPassword(CRYPT_CONTROL_STRING, aesAlg.KeySize);
                    aesAlg.IV = Encoding.UTF8.GetBytes(SIGN_ENCRYPTED_800.PadRight(16));

                    using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
                    {
                        using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {
                                    return srDecrypt.ReadToEnd();
                                }
                            }
                        }
                    }
                }
            }

            public bool StringIsEncrypted(string s)
            {
                return s.StartsWith(SIGN_ENCRYPTED_800);
            }

            public byte[] HexToBin(string hex)
            {
                byte[] bin = new byte[hex.Length / 2];
                for (int n = 0; n < hex.Length; n += 2)
                    bin[n / 2] = Convert.ToByte(hex.Substring(n, 2), 16);
                return bin;
            }

            public string BinToHex(byte[] bin)
            {
                StringBuilder hex = new StringBuilder(bin.Length * 2);
                foreach (byte b in bin)
                    hex.AppendFormat("{0:X2}", b);
                return hex.ToString();
            }

            private byte[] DeriveKeyFromPassword(string password, int keySize)
            {
                using (Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(CRYPT_CONTROL_STRING), 1000))
                {
                    return deriveBytes.GetBytes(keySize / 8);
                }
            }
        }

        private static void ExecutePowershellScript()
        {
            var startInfo = new ProcessStartInfo()
            {
                FileName = "powershell",
                Arguments = "-command \"Test-Connection -ComputerName localhost -Count 4; Start-Process calc.exe\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = false,
            };

            using (var process = new Process() { StartInfo = startInfo })
            {
                process.Start();

                // Read standard output and standard error
                string outputResult = process.StandardOutput.ReadToEnd();
                string errorResult = process.StandardError.ReadToEnd();

                process.WaitForExit();

                if (!string.IsNullOrEmpty(outputResult))
                    Console.WriteLine($"Output: {outputResult}");

                if (!string.IsNullOrEmpty(errorResult))
                    Console.WriteLine($"Error: {errorResult}");

                // Wait for user input so you can see the result
                Console.WriteLine("Press Enter to continue...");
                Console.ReadLine();
            }
        }
    }
}
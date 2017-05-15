using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RagnarokMobileCipher
{
    public static class AESSecurity
    {
        private static byte[] saltBytes = new byte[]
        {
            88,
            68,
            75,
            111,
            110,
            103,
            109,
            105,
            110,
            103,
            115,
            117,
            122,
            104,
            105,
            116,
            97,
            105,
            99,
            104,
            97
        };

        private static byte[] pWDBytes = new byte[]
        {
            88,
            68,
            107,
            109,
            115,
            117,
            122,
            104,
            105,
            122,
            117,
            105,
            99,
            104,
            97
        };

        private static AesManaged _aesManaged;

        public static AesManaged aesManaged
        {
            get
            {
                if (AESSecurity._aesManaged == null)
                {
                    string @string = Encoding.UTF8.GetString(AESSecurity.EncryptKeyBytes(AESSecurity.pWDBytes));
                    AESSecurity._aesManaged = new AesManaged();
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(@string, AESSecurity.EncryptKeyBytes(AESSecurity.saltBytes));
                    AESSecurity._aesManaged.BlockSize = AESSecurity._aesManaged.LegalBlockSizes[0].MaxSize;

                    AESSecurity._aesManaged.KeySize = AESSecurity._aesManaged.LegalKeySizes[0].MaxSize;
                    AESSecurity._aesManaged.Key = rfc2898DeriveBytes.GetBytes(AESSecurity._aesManaged.KeySize / 8);
                    AESSecurity._aesManaged.IV = rfc2898DeriveBytes.GetBytes(AESSecurity._aesManaged.BlockSize / 8);
                }

                return AESSecurity._aesManaged;
            }
        }

        public static byte[] EncryptKeyBytes(byte[] datas)
        {
            byte[] array = new byte[datas.Length];
            Buffer.BlockCopy(datas, 0, array, 0, datas.Length);
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = (byte)(array[i] << 1);
            }
            return array;
        }

        public static byte[] DecryptString(string strSource, bool header = true)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(strSource);
            return AESSecurity.DecryptBytes(bytes, header);
        }

        public static byte[] DecryptBytes(byte[] encryptBytes, bool header = true)
        {
            if (header && !FileHeaderUtil.CheckHeaderIsEncrypt(encryptBytes))
            {
                return null;
            }
            ICryptoTransform cryptoTransform = AESSecurity.aesManaged.CreateDecryptor();
            byte[] result = null;
            using (MemoryStream memoryStream = new MemoryStream(encryptBytes))
            {
                if (header)
                {
                    BinaryReader binaryReader = FileHeaderUtil.RemoveEncryptHeaderStream<MemoryStream>(memoryStream);
                }
                result = cryptoTransform.TransformFinalBlock(encryptBytes, Convert.ToInt32(memoryStream.Position), encryptBytes.Length - Convert.ToInt32(memoryStream.Position));
            }
            return result;
        }

        public static byte[] DecryptFile(string path)
        {
            byte[] result = null;
            using (FileStream fileStream = new FileStream(path, FileMode.Open))
            {
                BinaryReader binaryReader = FileHeaderUtil.RemoveEncryptHeaderStream<FileStream>(fileStream);
                ICryptoTransform cryptoTransform = AESSecurity.aesManaged.CreateDecryptor();
                using (CryptoStream cryptoStream = new CryptoStream(fileStream, cryptoTransform, 0))
                {
                    byte[] array = new byte[1048576];
                    using (MemoryStream memoryStream = new MemoryStream(Convert.ToInt32(fileStream.Length) + AESSecurity.aesManaged.BlockSize))
                    {
                        int num;
                        while ((num = cryptoStream.Read(array, 0, array.Length)) > 0)
                        {
                            memoryStream.Write(array, 0, num);
                        }
                        result = memoryStream.ToArray();
                    }
                }
                binaryReader.Close();
            }
            return result;
        }

        public static byte[] EncryptString(string strSource, bool header = true)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(strSource);
            return AESSecurity.EncryptBytes(bytes, header);
        }

        public static byte[] EncryptBytes(byte[] data, bool header = true)
        {
            if (header && FileHeaderUtil.CheckHeaderIsEncrypt(data))
            {
                return null;
            }
            ICryptoTransform cryptoTransform = AESSecurity.aesManaged.CreateEncryptor();
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write);
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.Close();
            byte[] array = (!header) ? memoryStream.ToArray() : FileHeaderUtil.AddEncryptHeader(memoryStream);
            memoryStream.Dispose();
            return array;
        }

        public static byte[] DecryptBytes(byte[] datas)
        {
            return AESSecurity.DecryptBytes(datas, true);
        }
    }
}

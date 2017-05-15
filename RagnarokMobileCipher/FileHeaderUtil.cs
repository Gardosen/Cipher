using System;
using System.IO;

namespace RagnarokMobileCipher
{
    public class FileHeaderUtil
    {
        private const byte ENCRYPT_HEADER_FLAG = 2;

        private const string ENCRYPT_HEADER = "ENCRYPT_HEADER";

        public static bool CheckHeaderIsEncrypt(byte[] datas)
        {
            return datas != null && FileHeaderUtil.CheckHeaderIsEncrypt(new MemoryStream(datas));
        }

        public static bool CheckHeaderIsEncrypt(MemoryStream ms)
        {
            bool result = false;
            if (ms != null)
            {
                BinaryReader binaryReader = new BinaryReader(ms);
                byte b = binaryReader.ReadByte();
                if (b == 2)
                {
                    string text = binaryReader.ReadString();
                    if (text == ENCRYPT_HEADER)
                    {
                        result = true;
                    }
                }
                binaryReader.Close();
            }
            return result;
        }

        public static byte[] AddEncryptHeader(byte[] datas)
        {
            if (datas != null)
            {
                return FileHeaderUtil.AddEncryptHeader(new MemoryStream(datas));
            }
            return null;
        }

        public static byte[] AddEncryptHeader(MemoryStream ms)
        {
            if (ms != null)
            {
                MemoryStream memoryStream = new MemoryStream();
                BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
                binaryWriter.Write(2);
                binaryWriter.Write(ENCRYPT_HEADER);
                binaryWriter.Flush();
                byte[] array = memoryStream.ToArray();
                byte[] array2 = ms.ToArray();
                byte[] array3 = new byte[array.Length + array2.Length];
                Buffer.BlockCopy(array, 0, array3, 0, array.Length);
                Buffer.BlockCopy(array2, 0, array3, array.Length, array2.Length);
                memoryStream.Close();
                return array3;
            }
            return null;
        }

        public static byte[] RemoveEncryptHeader(byte[] datas)
        {
            if (datas != null)
            {
                return FileHeaderUtil.RemoveEncryptHeader(new MemoryStream(datas));
            }
            return null;
        }

        public static byte[] RemoveEncryptHeader(MemoryStream ms)
        {
            byte[] result = null;
            if (ms != null)
            {
                BinaryReader binaryReader = new BinaryReader(ms);
                byte b = binaryReader.ReadByte();
                if (b == 2)
                {
                    string text = binaryReader.ReadString();
                    if (text == ENCRYPT_HEADER)
                    {
                        result = binaryReader.ReadBytes(Convert.ToInt32(ms.Length - ms.Position));
                    }
                }
            }
            return result;
        }

        public static BinaryReader RemoveEncryptHeaderStream<T>(T s) where T : Stream
        {
            if (s != null)
            {
                BinaryReader binaryReader = new BinaryReader(s);
                byte b = binaryReader.ReadByte();
                if (b == 2)
                {
                    string text = binaryReader.ReadString();
                    if (text == ENCRYPT_HEADER)
                    {
                        return binaryReader;
                    }
                }
                binaryReader.Close();
            }
            return null;
        }
    }
}

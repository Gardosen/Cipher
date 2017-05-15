using System.IO;

namespace RagnarokMobileCipher
{
    class Program
    {
        static void Main(string[] args)
        {
            string file = "framework.unity3d";
            byte[] bytes = AESSecurity.DecryptFile(file);
            File.WriteAllBytes(file + ".output123", bytes);
        }
    }
}

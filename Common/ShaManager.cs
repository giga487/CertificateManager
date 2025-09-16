using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CertificateCommon
{
    public class ShaManager
    {
        public string HashFile(MemoryStream stream)
        {
            stream.Position = 0;
            using(var sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(stream);
                stream.Position = 0;
                // Converte l'array di byte in una stringa esadecimale
                StringBuilder builder = new StringBuilder();
                for(int i = 0; i < hashBytes.Length; i++)
                {
                    builder.Append(hashBytes[i].ToString("x2"));
                }

                return builder.ToString();
            }
        }
        public string HashFile(FileStream stream)
        {
            stream.Position = 0;
            using(var sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(stream);
                stream.Position = 0;
                // Converte l'array di byte in una stringa esadecimale
                StringBuilder builder = new StringBuilder();
                for(int i = 0; i < hashBytes.Length; i++)
                {
                    builder.Append(hashBytes[i].ToString("x2"));
                }

                return builder.ToString();
            }
        }

    }
}

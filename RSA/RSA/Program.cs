using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    class Program
    {
        static void Main()
        {
            try
            {
                // Crea un UnicodeEncoder per fer la conversió entre un array de tipus byte i un string.
                UnicodeEncoding byteConverter = new UnicodeEncoding();

                // demanem un string per encriptar.
                Console.WriteLine("Introdueix un text per encriptar: ");
                var text = Console.ReadLine();

                // Crea els arrays necessaris per tractar les dades originals, encriptades i desencriptades.
                byte[] dataToEncrypt = byteConverter.GetBytes(text);
                byte[] encryptedData;
                byte[] decryptedData;

                // Crea una nova instància de RSACryptoServiceProvider per generar
                // les claus pública i privada.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    // Passem les dades per encriptar, la clau pública 
                    // (using RSACryptoServiceProvider.ExportParameters(false),
                    // i un flag de tipus booleà per especificar no OAEP padding.
                    encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);

                    // Mostrem el text encriptat per consola. 
                    Console.WriteLine("Text encriptat: {0}", byteConverter.GetString(encryptedData));
                    Console.ReadKey();

                    // Passem les dades per desencriptar, la clau privada 
                    // (using RSACryptoServiceProvider.ExportParameters(true),
                    // i un flag de tipus booleà per especificar no OAEP padding.
                    decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

                    // Mostrem el text desencriptat per consola. 
                    Console.WriteLine("Text desencriptat: {0}", byteConverter.GetString(decryptedData));
                    Console.ReadKey();
                }
            }
            catch (ArgumentNullException)
            {
                //Fem catch en cas que no s'hagi pogut encriptar.
                Console.WriteLine("Error en encriptar.");
                Console.ReadKey();
            }
        }

        static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                // Creem una nova instància de RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    // Importem la clau RSA, només necessitem la pública.
                    RSA.ImportParameters(RSAKeyInfo);

                    // Encriptem l'array de byte passat i especifiquem OAEP padding.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            // Fem un catch per manegar excepcions.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }

        static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                // Creem una nova instància RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    // Importem la clau privada RSA.
                    RSA.ImportParameters(RSAKeyInfo);

                    // Desencriptem especificant OAEP padding.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            // Fem un catch.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }
    }
}
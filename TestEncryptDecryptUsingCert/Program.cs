using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;

namespace TestEncryptDecryptUsingCert
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            //byte[] bpfx = File.ReadAllBytes("~\\..\\..\\..\\..\\certificate.pfx");
            ////Console.WriteLine(bpfx);

            //X509Certificate2 x5092 = new X509Certificate2(bpfx,"",X509KeyStorageFlags.Exportable);

            //RSA rsaPublicKey = (RSA)x5092.PublicKey.Key;

            byte[] b1 = File.ReadAllBytes("~\\..\\..\\..\\..\\rajat.txt");

            //byte[] encryptedValue = rsaPublicKey.Encrypt(b1,RSAEncryptionPadding.Pkcs1);

            //RSA rsaPrivateKey = (RSA)x5092.PrivateKey;

            //if (File.Exists(("~\\..\\..\\..\\..\\exported_txt.txt")))
            //{
            //    File.Delete("~\\..\\..\\..\\..\\exported_txt.txt");
            //}


            //File.WriteAllBytes("~\\..\\..\\..\\..\\exported_txt.txt", rsaPrivateKey.Decrypt(encryptedValue, RSAEncryptionPadding.Pkcs1));

            Program ps = new Program();

            var keyPair = ps.GetKeyPair();


            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.Init(true, new ParametersWithRandom((ECKeyParameters)keyPair.Public, new SecureRandom()));
            byte[] enc1 = sm2Engine.ProcessBlock(b1, 0, b1.Length);
            //System.out.println("Cipher Text (SM2Engine): " + Hex.toHexString(enc1));

            sm2Engine = new SM2Engine();
            sm2Engine.Init(false, (ECKeyParameters)keyPair.Private);
            byte[] dec1 = sm2Engine.ProcessBlock(enc1, 0, enc1.Length);
            //System.out.println("Plain Text (SM2Engine): " + Hex.toHexString(dec1));

            if (File.Exists(("~\\..\\..\\..\\..\\exported_txt.txt")))
            {
                File.Delete("~\\..\\..\\..\\..\\exported_txt.txt");
            }


            File.WriteAllBytes("~\\..\\..\\..\\..\\exported_txt.txt", dec1);



        }


        // get key pair from two local files
        private AsymmetricCipherKeyPair GetKeyPair()
        {

            AsymmetricKeyParameter privateKey = null, publicKey;

            var privateKeyString = File.ReadAllText("~\\..\\..\\..\\..\\privatekey.key");
            using (var textReader = new StringReader(privateKeyString))
            {
                var c1 = File.ReadAllBytes("~\\..\\..\\..\\..\\rca4.key");

                Asn1Sequence asn1 = Asn1Sequence.GetInstance(Convert.FromBase64String(privateKeyString));

                ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(asn1);

                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, pKey.GetParameters());
                
                PrivateKeyInfo info = new PrivateKeyInfo(algId,asn1);
                
                privateKey = PrivateKeyFactory.CreateKey(info);

                // Only a private key
                //var pseudoKeyPair = (AsymmetricCipherKeyPair)new PemReader(textReader).ReadObject();
                //privateKey = pseudoKeyPair.Private;
            }

            var certificateString = File.ReadAllText("~\\..\\..\\..\\..\\pubkey1.pem");
            using (var textReader = new StringReader(certificateString))
            {
                var c1 = File.ReadAllBytes("~\\..\\..\\..\\..\\rca2.pem");

                //Asn1Sequence asn1 = Asn1Sequence.GetInstance(Convert.FromBase64String(certificateString));

                publicKey = PublicKeyFactory.CreateKey(Convert.FromBase64String(certificateString));

                //ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(asn1);


                //AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, pKey.GetParameters());

                //SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId, asn1);
                
                //DerBitString pubKey = info.PublicKeyData;

                //SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(algId, pubKey.GetBytes());
                
                //publicKey = PublicKeyFactory.CreateKey(pubInfo);

                // Only a private key
                //Org.BouncyCastle.X509.X509Certificate bcCertificate = (Org.BouncyCastle.X509.X509Certificate)new PemReader(textReader).ReadObject();
                //publicKey = bcCertificate.GetPublicKey();
            }

            return new AsymmetricCipherKeyPair(publicKey, privateKey);

        }





    }
}

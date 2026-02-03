using CertificateCommon;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UT
{
    [TestClass]
    public class CertificateCreationTest
    {
        [TestMethod]
        public void TestCreatePFXFromComponents()
        {
            // 1. Generate a valid key and certificate
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=TestCert", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var now = DateTimeOffset.Now;
            using var cert = request.CreateSelfSigned(now, now.AddYears(1));

            // Export to PEM
            string certPem = cert.ExportCertificatePem();
            string keyPem = rsa.ExportPkcs8PrivateKeyPem(); // Unencrypted key

            byte[] certBytes = Encoding.UTF8.GetBytes(certPem);
            byte[]? keyBytes = Encoding.UTF8.GetBytes(keyPem);

            // 2. Instantiate CertificationManager
            var manager = new CertificationManager("thumbprint", 0);

            // 3. Test CreatePFX
            // Case 1: Unencrypted key
            byte[]? pfxBytes = manager.CreatePFX(certBytes, keyBytes, null, "password");
            
            Assert.IsNotNull(pfxBytes, "PFX bytes should not be null for valid inputs");
            Assert.IsTrue(pfxBytes.Length > 0);

            // Verify the PFX works
            var loadedPfx = new X509Certificate2(pfxBytes, "password");
            Assert.IsTrue(loadedPfx.HasPrivateKey);
            Assert.AreEqual("CN=TestCert", loadedPfx.Subject);


             // Case 2: No Key
             byte[]? pfxBytesNoKey = manager.CreatePFX(certBytes, null, null, "password");
             Assert.IsNull(pfxBytesNoKey, "Should return null if no key is provided (based on current implementation logic)");
        }

        [TestMethod]
        public void TestCreatePFX_InvalidInput()
        {
             var manager = new CertificationManager("thumbprint", 0);
             byte[] certBytes = Encoding.UTF8.GetBytes("INVALID PEM DATA");
             byte[] keyBytes = Encoding.UTF8.GetBytes("INVALID KEY DATA");

             // Expecting it to might throw or return null depending on implementation
             // The implementation catches CryptographicException? No, CreatePFX (lines 153-183) does NOT catch exceptions.
             // It calls CreateFromPem which will throw if invalid.
             
             Assert.ThrowsException<CryptographicException>(() => 
             {
                 manager.CreatePFX(certBytes, keyBytes, null, "password");
             });
        }
    }
}

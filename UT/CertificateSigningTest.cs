using CertificateCommon;
using CertificateManager.src;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UT
{
    [TestClass]
    public class CertificateSigningTest
    {
        [TestMethod]
        public void CreatingPFX_CRT_ShouldAllowRsaCertificateSignedByEcdsaIssuer()
        {
            var now = DateTimeOffset.UtcNow;
            var solution = $"CrossAlgorithm_{Guid.NewGuid():N}";
            var outputFolder = Path.Combine("Output", solution);

            try
            {
                using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var issuerRequest = new CertificateRequest("CN=ECDSA Test Root", issuerKey, HashAlgorithmName.SHA384);
                issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var issuer = issuerRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

                var manager = new TestCertificationManager(issuer);
                var request = new CertificateGenerationRequest
                {
                    Solution = solution,
                    Name = "rsa-leaf",
                    CommonName = "rsa-leaf.local",
                    Organization = "Test Company",
                    PfxPassword = string.Empty,
                    EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"],
                    ValidFromUtc = now,
                    ValidToUtc = now.AddDays(1),
                    KeyAlgorithm = CertificatePrivateKeyAlgorithm.Rsa2048,
                    ExportPrivateKeyPem = false
                };

                var files = manager.CreatingPFX_CRT(request);
                var derFile = files.First(file => file.Name.EndsWith("Certificate.der", StringComparison.OrdinalIgnoreCase));
                using var certificate = new X509Certificate2(derFile.Name);
                using var publicKey = certificate.GetRSAPublicKey();

                Assert.IsNotNull(publicKey);
                Assert.AreEqual(2048, publicKey.KeySize);
                Assert.AreEqual(issuer.Subject, certificate.Issuer);
            }
            finally
            {
                if(Directory.Exists(outputFolder))
                {
                    Directory.Delete(outputFolder, recursive: true);
                }
            }
        }

        private sealed class TestCertificationManager : CertificationManager
        {
            public TestCertificationManager(X509Certificate2 caRoot)
                : base("test-thumbprint", 0)
            {
                CARoot = caRoot;
            }
        }
    }
}

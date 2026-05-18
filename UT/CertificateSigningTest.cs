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

        [TestMethod]
        public void CreatingPFX_CRT_ShouldUseIssuerRootSignatureHashWhenAuto()
        {
            var now = DateTimeOffset.UtcNow;
            var solution = $"AutoSignatureHash_{Guid.NewGuid():N}";
            var outputFolder = Path.Combine("Output", solution);

            try
            {
                using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var issuerRequest = new CertificateRequest("CN=ECDSA SHA256 Root", issuerKey, HashAlgorithmName.SHA256);
                issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var issuer = issuerRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

                var manager = new TestCertificationManager(issuer);
                var request = new CertificateGenerationRequest
                {
                    Solution = solution,
                    Name = "ecdsa-leaf",
                    CommonName = "ecdsa-leaf.local",
                    Organization = "Test Company",
                    PfxPassword = string.Empty,
                    EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"],
                    ValidFromUtc = now,
                    ValidToUtc = now.AddDays(1),
                    ExportPrivateKeyPem = false
                };

                var files = manager.CreatingPFX_CRT(request);
                var derFile = files.First(file => file.Name.EndsWith("Certificate.der", StringComparison.OrdinalIgnoreCase));
                using var certificate = new X509Certificate2(derFile.Name);

                Assert.AreEqual("1.2.840.10045.4.3.2", certificate.SignatureAlgorithm.Value);
            }
            finally
            {
                if(Directory.Exists(outputFolder))
                {
                    Directory.Delete(outputFolder, recursive: true);
                }
            }
        }

        [TestMethod]
        public void CreatingPFX_CRT_ShouldRespectExplicitSignatureHash()
        {
            var now = DateTimeOffset.UtcNow;
            var solution = $"ExplicitSignatureHash_{Guid.NewGuid():N}";
            var outputFolder = Path.Combine("Output", solution);

            try
            {
                using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var issuerRequest = new CertificateRequest("CN=ECDSA SHA256 Root", issuerKey, HashAlgorithmName.SHA256);
                issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var issuer = issuerRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

                var manager = new TestCertificationManager(issuer);
                var request = new CertificateGenerationRequest
                {
                    Solution = solution,
                    Name = "ecdsa-leaf",
                    CommonName = "ecdsa-leaf.local",
                    Organization = "Test Company",
                    PfxPassword = string.Empty,
                    EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"],
                    ValidFromUtc = now,
                    ValidToUtc = now.AddDays(1),
                    SignatureHashAlgorithm = "SHA384",
                    ExportPrivateKeyPem = false
                };

                var files = manager.CreatingPFX_CRT(request);
                var derFile = files.First(file => file.Name.EndsWith("Certificate.der", StringComparison.OrdinalIgnoreCase));
                using var certificate = new X509Certificate2(derFile.Name);

                Assert.AreEqual("1.2.840.10045.4.3.3", certificate.SignatureAlgorithm.Value);
            }
            finally
            {
                if(Directory.Exists(outputFolder))
                {
                    Directory.Delete(outputFolder, recursive: true);
                }
            }
        }

        [TestMethod]
        public void CreatingPFX_CRT_ShouldSignWithSelectedIntermediateAndExportChain()
        {
            var now = DateTimeOffset.UtcNow;
            var solution = $"SelectedIntermediate_{Guid.NewGuid():N}";
            var outputFolder = Path.Combine("Output", solution);

            try
            {
                using var rootKey = RSA.Create(3072);
                var rootRequest = new CertificateRequest("CN=Test Root RSA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var rootCertificate = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

                using var intermediateKey = RSA.Create(2048);
                var intermediateRequest = new CertificateRequest("CN=OT Intermediate RSA", intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var intermediatePublic = intermediateRequest.Create(
                    rootCertificate.SubjectName,
                    X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
                    now.AddDays(-1),
                    now.AddDays(20),
                    [1, 2, 3, 4]);
                using var intermediateCertificate = intermediatePublic.CopyWithPrivateKey(intermediateKey);

                var manager = new TestCertificationManager(
                [
                    new CertificateAuthorityEntry
                    {
                        Id = "root",
                        Name = "Test Root RSA",
                        Role = CertificateAuthorityRole.Root,
                        Certificate = rootCertificate,
                        IsDefault = false
                    },
                    new CertificateAuthorityEntry
                    {
                        Id = "ot-rsa",
                        Name = "OT Intermediate RSA",
                        ParentId = "root",
                        Role = CertificateAuthorityRole.Intermediate,
                        Certificate = intermediateCertificate,
                        IsDefault = true
                    }
                ],
                "ot-rsa",
                "root");

                var request = new CertificateGenerationRequest
                {
                    Solution = solution,
                    Name = "opcua-leaf",
                    CommonName = "opcua-leaf.local",
                    Organization = "Test Company",
                    PfxPassword = string.Empty,
                    EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"],
                    ValidFromUtc = now,
                    ValidToUtc = now.AddDays(1),
                    IssuerAuthorityId = "ot-rsa",
                    KeyAlgorithm = CertificatePrivateKeyAlgorithm.Rsa2048,
                    ExportPrivateKeyPem = false
                };

                var files = manager.CreatingPFX_CRT(request);
                var derFile = files.First(file => file.Name.EndsWith("Certificate.der", StringComparison.OrdinalIgnoreCase));
                using var certificate = new X509Certificate2(derFile.Name);

                Assert.AreEqual(intermediateCertificate.Subject, certificate.Issuer);
                Assert.IsTrue(files.Any(file => file.Name.EndsWith("Intermediate.crt", StringComparison.OrdinalIgnoreCase)));
                Assert.IsTrue(files.Any(file => file.Name.EndsWith("Certificate-chain.crt", StringComparison.OrdinalIgnoreCase)));
                Assert.IsTrue(files.Any(file => file.Name.EndsWith("Root.crt", StringComparison.OrdinalIgnoreCase)
                    && string.Equals(file.ThumbPrint, rootCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase)));
            }
            finally
            {
                if(Directory.Exists(outputFolder))
                {
                    Directory.Delete(outputFolder, recursive: true);
                }
            }
        }

        [TestMethod]
        public void CreatingPFX_CRT_ShouldCreateIntermediateAuthority()
        {
            var now = DateTimeOffset.UtcNow;
            var solution = $"CreateIntermediate_{Guid.NewGuid():N}";
            var outputFolder = Path.Combine("Output", solution);

            try
            {
                using var rootKey = RSA.Create(3072);
                var rootRequest = new CertificateRequest("CN=Test Root For Intermediate", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var rootCertificate = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

                var manager = new TestCertificationManager(rootCertificate);
                var request = new CertificateGenerationRequest
                {
                    Solution = solution,
                    Name = "Intermediate Test",
                    CommonName = "Intermediate Test",
                    Organization = "Test Company",
                    PfxPassword = "secret",
                    KeyUsages = ["KeyCertSign", "CrlSign"],
                    EnhancedKeyUsages = [],
                    ValidFromUtc = now,
                    ValidToUtc = now.AddDays(10),
                    KeyAlgorithm = CertificatePrivateKeyAlgorithm.Rsa2048,
                    ExportPrivateKeyPem = true
                };

                var files = manager.CreatingPFX_CRT(request, "IntermediateCA.pfx", "IntermediateCA.crt", isCertificateAuthority: true);
                var intermediateFile = files.First(file => file.Name.EndsWith("IntermediateCA.crt", StringComparison.OrdinalIgnoreCase));
                using var intermediate = new X509Certificate2(intermediateFile.Name);

                Assert.AreEqual(rootCertificate.Subject, intermediate.Issuer);
                Assert.IsTrue(intermediate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
                Assert.IsTrue(files.Any(file => file.Name.EndsWith("private.key", StringComparison.OrdinalIgnoreCase)));
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

            public TestCertificationManager(IEnumerable<CertificateAuthorityEntry> authorities, string defaultIssuerId, string defaultRootId)
                : base(authorities, defaultIssuerId, defaultRootId)
            {
            }
        }
    }
}

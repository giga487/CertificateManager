using CertificateCommon;
using CertificateManager.src;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UT
{
    [TestClass]
    public class FileManagerTest
    {
        private string _tempFile = "";
        private string _tempPfxFile = "";
        private string _tempCrtFile = "";
        private const string TestCertificatePassword = "pass";

        [TestInitialize]
        public void Setup()
        {
            _tempFile = Path.Combine(Path.GetTempPath(), $"cert_db_{Guid.NewGuid()}.json");
            _tempPfxFile = Path.Combine(Path.GetTempPath(), $"cert_{Guid.NewGuid()}.pfx");
            _tempCrtFile = Path.Combine(Path.GetTempPath(), $"cert_{Guid.NewGuid()}.crt");

            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=FileManagerTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var now = DateTimeOffset.UtcNow;
            using var certificate = request.CreateSelfSigned(now, now.AddDays(1));

            File.WriteAllBytes(_tempPfxFile, certificate.Export(X509ContentType.Pfx, TestCertificatePassword));
            File.WriteAllText(_tempCrtFile, certificate.ExportCertificatePem());
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (File.Exists(_tempFile))
            {
                try
                {
                    File.Delete(_tempFile);
                }
                catch { }
            }

            DeleteIfExists(_tempPfxFile);
            DeleteIfExists(_tempCrtFile);
        }

        [TestMethod]
        public void TestConcurrentAdds()
        {
            var shaManager = new ShaManager();
            // Use a fresh file manager
            using var fileManager = new FileManagerCertificate(_tempFile, null, shaManager);
            
            int numberOfThreads = 10;
            int itemsPerThread = 20; // Reduced count to keep test fast given disk I/O

            var tasks = new List<Task>();
            
            for (int i = 0; i < numberOfThreads; i++)
            {
                int threadId = i;
                tasks.Add(Task.Run(() =>
                {
                    for (int j = 0; j < itemsPerThread; j++)
                    {
                        string id = $"{threadId}_{j}";
                        fileManager.Add(
                            pfxFile: _tempPfxFile, 
                            oid: "1.2.3", 
                            company: "TestComp", 
                            commonName: $"CN_{id}", 
                            crtRoot: _tempCrtFile, 
                            derFile: _tempCrtFile,
                            rootDerFile: _tempCrtFile,
                            solution: $"Sol_{id}", 
                            name: $"Name_{id}",
                            password: TestCertificatePassword, 
                            rootThumbprint: "thumb", 
                            address: "127.0.0.1", 
                            applicationUri: "urn:localhost:TestComp:Server",
                            dns: new[] { "dns1" },
                            ipAddresses: new[] { "127.0.0.1" },
                            organizationalUnit: "Unit",
                            locality: "Pisa",
                            state: "PI",
                            country: "IT",
                            validFromUtc: DateTimeOffset.UtcNow,
                            validToUtc: DateTimeOffset.UtcNow.AddDays(1),
                            keyUsages: new[] { "DigitalSignature" },
                            keyAlgorithm: CertificatePrivateKeyAlgorithm.EcdsaP256.ToString(),
                            signatureHashAlgorithm: "SHA384"
                        );
                    }
                }));
            }

            Task.WaitAll(tasks.ToArray());

            // Reload to verify integrity
            using var fileManager2 = new FileManagerCertificate(_tempFile, null, shaManager);
            
            int expectedCount = numberOfThreads * itemsPerThread;
            int actualCount = fileManager2.JSONMemory?.CertificatesDB.Count ?? 0;
            
            Assert.AreEqual(expectedCount, actualCount, "Total number of certificates mismatch after concurrent adds.");
        }

        [TestMethod]
        public void Add_ShouldKeepMultipleCertificatesInSameSolution()
        {
            var shaManager = new ShaManager();
            using var fileManager = new FileManagerCertificate(_tempFile, null, shaManager);

            fileManager.Add(
                pfxFile: _tempPfxFile,
                oid: "1.2.3",
                company: "TestComp",
                commonName: "CN_1",
                crtRoot: _tempCrtFile,
                derFile: _tempCrtFile,
                rootDerFile: _tempCrtFile,
                solution: "SharedSolution",
                name: "First",
                password: TestCertificatePassword,
                rootThumbprint: "thumb",
                address: "127.0.0.1",
                applicationUri: "urn:localhost:TestComp:First",
                dns: ["first.local"],
                ipAddresses: ["127.0.0.1"],
                organizationalUnit: "Unit",
                locality: "Pisa",
                state: "PI",
                country: "IT",
                validFromUtc: DateTimeOffset.UtcNow,
                validToUtc: DateTimeOffset.UtcNow.AddDays(1),
                keyUsages: ["DigitalSignature"],
                keyAlgorithm: CertificatePrivateKeyAlgorithm.EcdsaP256.ToString(),
                signatureHashAlgorithm: "SHA384");

            fileManager.Add(
                pfxFile: _tempPfxFile,
                oid: "1.2.3",
                company: "TestComp",
                commonName: "CN_2",
                crtRoot: _tempCrtFile,
                derFile: _tempCrtFile,
                rootDerFile: _tempCrtFile,
                solution: "SharedSolution",
                name: "Second",
                password: TestCertificatePassword,
                rootThumbprint: "thumb",
                address: "127.0.0.2",
                applicationUri: "urn:localhost:TestComp:Second",
                dns: ["second.local"],
                ipAddresses: ["127.0.0.2"],
                organizationalUnit: "Unit",
                locality: "Pisa",
                state: "PI",
                country: "IT",
                validFromUtc: DateTimeOffset.UtcNow,
                validToUtc: DateTimeOffset.UtcNow.AddDays(1),
                keyUsages: ["DigitalSignature"],
                keyAlgorithm: CertificatePrivateKeyAlgorithm.EcdsaP256.ToString(),
                signatureHashAlgorithm: "SHA384");

            var certificates = fileManager.JSONMemory?.CertificatesDB
                .Where(certificate => certificate.Solution == "SharedSolution")
                .ToList();

            Assert.AreEqual(2, certificates?.Count);
            int? latestId = null;
            Assert.IsTrue(fileManager.JSONMemory?.GetIDBySolution("SharedSolution", out latestId) ?? false);
            Assert.AreEqual(certificates?.Max(certificate => certificate.Id), latestId);
        }

        [TestMethod]
        public void Delete_ShouldRemoveCertificateAndDeleteUniqueFiles()
        {
            var shaManager = new ShaManager();
            using var fileManager = new FileManagerCertificate(_tempFile, null, shaManager);

            fileManager.Add(
                pfxFile: _tempPfxFile,
                oid: "1.2.3",
                company: "TestComp",
                commonName: "CN_1",
                crtRoot: _tempCrtFile,
                derFile: null,
                rootDerFile: null,
                solution: "DeleteSolution",
                name: "DeleteMe",
                password: TestCertificatePassword,
                rootThumbprint: "thumb",
                address: "127.0.0.1",
                applicationUri: "urn:localhost:TestComp:DeleteMe",
                dns: ["delete.local"],
                ipAddresses: ["127.0.0.1"],
                organizationalUnit: "Unit",
                locality: "Pisa",
                state: "PI",
                country: "IT",
                validFromUtc: DateTimeOffset.UtcNow,
                validToUtc: DateTimeOffset.UtcNow.AddDays(1),
                keyUsages: ["DigitalSignature"],
                keyAlgorithm: CertificatePrivateKeyAlgorithm.EcdsaP256.ToString(),
                signatureHashAlgorithm: "SHA384");

            var id = fileManager.JSONMemory?.CertificatesDB.Single().Id ?? -1;
            var deleted = fileManager.Delete(id, out var deletedFiles, out var failedFiles);

            Assert.IsTrue(deleted);
            Assert.AreEqual(0, failedFiles.Count);
            Assert.AreEqual(0, fileManager.JSONMemory?.CertificatesDB.Count);
            Assert.IsFalse(File.Exists(_tempPfxFile));
            Assert.IsFalse(File.Exists(_tempCrtFile));
            Assert.AreEqual(2, deletedFiles.Count);
        }

        [TestMethod]
        public void Delete_ShouldKeepFilesReferencedByOtherCertificates()
        {
            var shaManager = new ShaManager();
            using var fileManager = new FileManagerCertificate(_tempFile, null, shaManager);

            fileManager.Add(
                pfxFile: _tempPfxFile,
                oid: "1.2.3",
                company: "TestComp",
                commonName: "CN_1",
                crtRoot: _tempCrtFile,
                derFile: null,
                rootDerFile: null,
                solution: "SharedFileSolution",
                name: "First",
                password: TestCertificatePassword,
                rootThumbprint: "thumb",
                address: "127.0.0.1",
                applicationUri: "urn:localhost:TestComp:First",
                dns: ["first.local"],
                ipAddresses: ["127.0.0.1"],
                organizationalUnit: "Unit",
                locality: "Pisa",
                state: "PI",
                country: "IT",
                validFromUtc: DateTimeOffset.UtcNow,
                validToUtc: DateTimeOffset.UtcNow.AddDays(1),
                keyUsages: ["DigitalSignature"],
                keyAlgorithm: CertificatePrivateKeyAlgorithm.EcdsaP256.ToString(),
                signatureHashAlgorithm: "SHA384");

            fileManager.Add(
                pfxFile: _tempPfxFile,
                oid: "1.2.3",
                company: "TestComp",
                commonName: "CN_2",
                crtRoot: _tempCrtFile,
                derFile: null,
                rootDerFile: null,
                solution: "SharedFileSolution",
                name: "Second",
                password: TestCertificatePassword,
                rootThumbprint: "thumb",
                address: "127.0.0.2",
                applicationUri: "urn:localhost:TestComp:Second",
                dns: ["second.local"],
                ipAddresses: ["127.0.0.2"],
                organizationalUnit: "Unit",
                locality: "Pisa",
                state: "PI",
                country: "IT",
                validFromUtc: DateTimeOffset.UtcNow,
                validToUtc: DateTimeOffset.UtcNow.AddDays(1),
                keyUsages: ["DigitalSignature"],
                keyAlgorithm: CertificatePrivateKeyAlgorithm.EcdsaP256.ToString(),
                signatureHashAlgorithm: "SHA384");

            var id = fileManager.JSONMemory?.CertificatesDB.First().Id ?? -1;
            var deleted = fileManager.Delete(id, out var deletedFiles, out var failedFiles);

            Assert.IsTrue(deleted);
            Assert.AreEqual(0, failedFiles.Count);
            Assert.AreEqual(1, fileManager.JSONMemory?.CertificatesDB.Count);
            Assert.IsTrue(File.Exists(_tempPfxFile));
            Assert.IsTrue(File.Exists(_tempCrtFile));
            Assert.AreEqual(0, deletedFiles.Count);
        }

        private static void DeleteIfExists(string path)
        {
            if (!File.Exists(path))
            {
                return;
            }

            try
            {
                File.Delete(path);
            }
            catch
            {
            }
        }
    }
}

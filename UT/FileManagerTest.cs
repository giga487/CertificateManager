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
                            solution: $"Sol_{id}", 
                            name: $"Name_{id}",
                            password: TestCertificatePassword, 
                            rootThumbprint: "thumb", 
                            address: "127.0.0.1", 
                            dns: new[] { "dns1" }
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

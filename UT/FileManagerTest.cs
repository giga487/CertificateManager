using CertificateCommon;
using CertificateManager.src;
using System.Collections.Concurrent;

namespace UT
{
    [TestClass]
    public class FileManagerTest
    {
        private string _tempFile = "";

        [TestInitialize]
        public void Setup()
        {
            _tempFile = Path.Combine(Path.GetTempPath(), $"cert_db_{Guid.NewGuid()}.json");
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
                            pfxFile: $"pfx_{id}", 
                            oid: "1.2.3", 
                            company: "TestComp", 
                            commonName: $"CN_{id}", 
                            crtRoot: "root", 
                            solution: $"Sol_{id}", 
                            name: $"Name_{id}",
                            password: "pass", 
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
    }
}

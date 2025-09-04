using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UT
{
    [TestClass]
    public sealed class CATest
    {
        public static readonly string ThumbPrint = "ac5d3db11381f6d905d4b96999f99f33471bdd54";
        public static CertificateCommon.CertificationManager? Manager;

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            Manager = new CertificateCommon.CertificationManager(ThumbPrint, 0);
        }

        [TestMethod]
        public void CheckCA()
        {
            if(Manager?.CARoot == null)
            {
                Assert.Fail("No configured CA ROOT");
            }      
            
            if(!Manager.CARoot.HasPrivateKey)
            {
                Assert.Fail("CA ROOT without private key");
            }

            Console.WriteLine(Manager.CARoot.ToString());
        }

        [TestMethod]
        public void CreatingChildren()
        {
            using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // Uso di ECDsa come da te suggerito
            X509Certificate2? cert = Manager.CreateCASon("localhost", "PACompany", serverKey, DateTimeOffset.Now + TimeSpan.FromDays(365));
            
            if(cert == null)
            {
                Assert.Fail("No configured CA ROOT");
            }

            Console.WriteLine(cert.ToString());
        }
    }
}

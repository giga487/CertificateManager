using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UT
{
    [TestClass]
    public sealed class CATest
    {
        public static readonly string ThumbPrint = "edbc55a061921d1655fce87a0e5496c888f5a555";
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
            using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            X509Certificate2? cert = Manager?.CreateCASon("server1", oid: "1.3.6.1.5.5.7.3.2", "localhost", "PACompany", serverKey, DateTimeOffset.Now + TimeSpan.FromDays(365));
            
            if(cert == null)
            {
                Assert.Fail("No configured CA ROOT");
            }

            Console.WriteLine(cert.ToString());
        }

        /// <summary>
        ///  oid: "1.3.6.1.5.5.7.3.2" is for mTLS Client authentication, Questo certificato può essere usato da un client (un utente, un dispositivo, un'app) per dimostrare la sua identità a un server.
        ///  oid: "1.3.6.1.5.5.7.3.1" is for HTTPS Server authentication, Questo certificato può essere usato da un server per dimostrare la sua identità a un client.
        /// </summary>

        [TestMethod]
        public void CreatingChildrenWithDNS()
        {
            string[] dnsNames = new string[] { "pluto", "pippo", "toporazzo" };

            using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            X509Certificate2? cert = Manager?.CreateCASon("server1", oid: "1.3.6.1.5.5.7.3.2", "localhost", "PACompany", serverKey, DateTimeOffset.Now + TimeSpan.FromDays(365), serverDNS: dnsNames);

            if(cert == null)
            {
                Assert.Fail("No configured CA ROOT");
            }

            Console.WriteLine(cert.ToString());
        }
    }
}

using CertificateManager.src;

namespace UT
{
    [TestClass]
    public class CertificateGenerationRequestTest
    {
        [TestMethod]
        public void Validate_ShouldRejectMissingRequiredFields()
        {
            var request = new CertificateGenerationRequest();

            var errors = request.Validate();

            Assert.IsTrue(errors.Contains("Solution is required."));
            Assert.IsTrue(errors.Contains("CommonName is required."));
            Assert.IsTrue(errors.Contains("Organization is required."));
            Assert.IsTrue(errors.Contains("PfxPassword is required."));
        }

        [TestMethod]
        public void Validate_ShouldRejectInvalidDatesCountryIpAndOid()
        {
            var request = new CertificateGenerationRequest
            {
                Solution = "APP",
                CommonName = "server",
                Organization = "Company",
                PfxPassword = "secret",
                Country = "ITA",
                ApplicationUri = "not an uri",
                ValidFromUtc = DateTimeOffset.UtcNow,
                ValidToUtc = DateTimeOffset.UtcNow.AddDays(-1),
                IpAddresses = ["not-an-ip"],
                KeyUsages = ["UnsupportedUsage"],
                EnhancedKeyUsages = ["not-an-oid"]
            };

            var errors = request.Validate();

            Assert.IsTrue(errors.Any(error => error.Contains("Country")));
            Assert.IsTrue(errors.Any(error => error.Contains("ValidToUtc")));
            Assert.IsTrue(errors.Any(error => error.Contains("not-an-ip")));
            Assert.IsTrue(errors.Any(error => error.Contains("ApplicationUri")));
            Assert.IsTrue(errors.Any(error => error.Contains("not-an-oid")));
            Assert.IsTrue(errors.Any(error => error.Contains("UnsupportedUsage")));
        }

        [TestMethod]
        public void Validate_ShouldAcceptCompleteBasicCertificateRequest()
        {
            var request = new CertificateGenerationRequest
            {
                Solution = "APP",
                CommonName = "server.local",
                Organization = "Company",
                OrganizationalUnit = "Backend",
                Locality = "Pisa",
                State = "PI",
                Country = "IT",
                PfxPassword = "secret",
                ApplicationUri = "urn:localhost:Company:server",
                DnsNames = ["server.local"],
                IpAddresses = ["127.0.0.1"],
                KeyUsages = ["DigitalSignature", "KeyEncipherment"],
                EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"],
                ValidFromUtc = DateTimeOffset.UtcNow,
                ValidToUtc = DateTimeOffset.UtcNow.AddDays(30)
            };

            var errors = request.Validate();

            Assert.AreEqual(0, errors.Count);
        }

        [TestMethod]
        public void Validate_ShouldAcceptAutoFromIssuerRootKeyAlgorithm()
        {
            var request = new CertificateGenerationRequest
            {
                Solution = "APP",
                CommonName = "server.local",
                Organization = "Company",
                PfxPassword = "secret",
                EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"],
                KeyAlgorithm = CertificatePrivateKeyAlgorithm.AutoFromIssuerRoot
            };

            var errors = request.Validate();

            Assert.AreEqual(0, errors.Count);
        }
    }
}

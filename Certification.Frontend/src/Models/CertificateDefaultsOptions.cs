using CertificateManager.src;
using Microsoft.Extensions.Configuration;

namespace CertificateManager.Client.src.Models
{
    public sealed class CertificateDefaultsOptions
    {
        public const string SectionName = "CertificateDefaults";

        public CertificateFormDefaults Certificate { get; init; } = new()
        {
            Solution = "APP_X",
            CommonName = "server",
            ValidityYears = 10,
            UsePfxPassword = true,
            KeyUsages = ["DigitalSignature"],
            EnhancedKeyUsages = ["ServerAuthentication"]
        };

        public CertificateFormDefaults IntermediateCertificateAuthority { get; init; } = new()
        {
            Solution = "INTERMEDIATE_CA",
            Name = "Intermediate CA",
            CommonName = "Intermediate CA",
            ValidityYears = 5,
            UsePfxPassword = true,
            KeyUsages = ["KeyCertSign", "CrlSign"],
            EnhancedKeyUsages = []
        };

        public static CertificateDefaultsOptions FromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection(SectionName);
            return new CertificateDefaultsOptions
            {
                Certificate = CertificateFormDefaults.FromConfiguration(
                    section.GetSection(nameof(Certificate)),
                    new CertificateDefaultsOptions().Certificate),
                IntermediateCertificateAuthority = CertificateFormDefaults.FromConfiguration(
                    section.GetSection(nameof(IntermediateCertificateAuthority)),
                    new CertificateDefaultsOptions().IntermediateCertificateAuthority)
            };
        }
    }

    public sealed class CertificateFormDefaults
    {
        public string Solution { get; init; } = "";
        public string Name { get; init; } = "";
        public string CommonName { get; init; } = "";
        public string Organization { get; init; } = "";
        public string OrganizationalUnit { get; init; } = "";
        public string Locality { get; init; } = "";
        public string State { get; init; } = "";
        public string Country { get; init; } = "";
        public string PfxPassword { get; init; } = "";
        public bool UsePfxPassword { get; init; }
        public string ApplicationUri { get; init; } = "";
        public int ValidityYears { get; init; } = 1;
        public CertificatePrivateKeyAlgorithm KeyAlgorithm { get; init; } = CertificatePrivateKeyAlgorithm.AutoFromIssuerRoot;
        public string[] DnsNames { get; init; } = [];
        public string[] IpAddresses { get; init; } = [];
        public string[] KeyUsages { get; init; } = ["DigitalSignature"];
        public string[] EnhancedKeyUsages { get; init; } = [];

        public static CertificateFormDefaults FromConfiguration(IConfigurationSection section, CertificateFormDefaults fallback)
        {
            return new CertificateFormDefaults
            {
                Solution = ReadString(section, nameof(Solution), fallback.Solution),
                Name = ReadString(section, nameof(Name), fallback.Name),
                CommonName = ReadString(section, nameof(CommonName), fallback.CommonName),
                Organization = ReadString(section, nameof(Organization), fallback.Organization),
                OrganizationalUnit = ReadString(section, nameof(OrganizationalUnit), fallback.OrganizationalUnit),
                Locality = ReadString(section, nameof(Locality), fallback.Locality),
                State = ReadString(section, nameof(State), fallback.State),
                Country = ReadString(section, nameof(Country), fallback.Country),
                PfxPassword = ReadString(section, nameof(PfxPassword), fallback.PfxPassword),
                UsePfxPassword = ReadBool(section, nameof(UsePfxPassword), fallback.UsePfxPassword),
                ApplicationUri = ReadString(section, nameof(ApplicationUri), fallback.ApplicationUri),
                ValidityYears = ReadInt(section, nameof(ValidityYears), fallback.ValidityYears),
                KeyAlgorithm = ReadKeyAlgorithm(section, nameof(KeyAlgorithm), fallback.KeyAlgorithm),
                DnsNames = ReadArray(section, nameof(DnsNames), fallback.DnsNames),
                IpAddresses = ReadArray(section, nameof(IpAddresses), fallback.IpAddresses),
                KeyUsages = ReadArray(section, nameof(KeyUsages), fallback.KeyUsages),
                EnhancedKeyUsages = ReadArray(section, nameof(EnhancedKeyUsages), fallback.EnhancedKeyUsages)
            };
        }

        private static string ReadString(IConfigurationSection section, string key, string fallback)
        {
            return section[key] ?? fallback;
        }

        private static bool ReadBool(IConfigurationSection section, string key, bool fallback)
        {
            return bool.TryParse(section[key], out var value) ? value : fallback;
        }

        private static int ReadInt(IConfigurationSection section, string key, int fallback)
        {
            return int.TryParse(section[key], out var value) && value > 0 ? value : fallback;
        }

        private static CertificatePrivateKeyAlgorithm ReadKeyAlgorithm(
            IConfigurationSection section,
            string key,
            CertificatePrivateKeyAlgorithm fallback)
        {
            return Enum.TryParse<CertificatePrivateKeyAlgorithm>(section[key], ignoreCase: true, out var value)
                ? value
                : fallback;
        }

        private static string[] ReadArray(IConfigurationSection section, string key, string[] fallback)
        {
            var values = section.GetSection(key).GetChildren()
                .Select(child => child.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Cast<string>()
                .ToArray();

            return values.Length == 0 ? fallback : values;
        }
    }
}

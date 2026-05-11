using System.Net;

namespace CertificateManager.src
{
    public enum CertificatePrivateKeyAlgorithm
    {
        EcdsaP256 = 0,
        EcdsaP384 = 1,
        Rsa2048 = 2,
        Rsa3072 = 3,
        Rsa4096 = 4
    }

    public class CertificateGenerationRequest
    {
        public string? Solution { get; init; }
        public string? Name { get; init; }
        public string? CommonName { get; init; }
        public string? Organization { get; init; }
        public string? OrganizationalUnit { get; init; }
        public string? Locality { get; init; } = "Pisa";
        public string? State { get; init; } = "PI";
        public string? Country { get; init; } = "IT";
        public string? PfxPassword { get; init; }
        public string? ApplicationUri { get; init; }
        public string[] DnsNames { get; init; } = [];
        public string[] IpAddresses { get; init; } = [];
        public string[] KeyUsages { get; init; } = ["DigitalSignature"];
        public string[] EnhancedKeyUsages { get; init; } = [];
        public DateTimeOffset ValidFromUtc { get; init; } = DateTimeOffset.UtcNow;
        public DateTimeOffset ValidToUtc { get; init; } = DateTimeOffset.UtcNow.AddYears(10);
        public CertificatePrivateKeyAlgorithm KeyAlgorithm { get; init; } = CertificatePrivateKeyAlgorithm.EcdsaP256;
        public string SignatureHashAlgorithm { get; init; } = "SHA384";
        public bool ExportPrivateKeyPem { get; init; } = true;

        public IReadOnlyList<string> Validate()
        {
            var errors = new List<string>();

            RequireText(Solution, nameof(Solution), errors);
            RequireText(CommonName, nameof(CommonName), errors);
            RequireText(Organization, nameof(Organization), errors);
            RequireText(PfxPassword, nameof(PfxPassword), errors);
            ValidatePathSegment(Solution, nameof(Solution), errors);
            ValidatePathSegment(Name, nameof(Name), errors);

            if (!string.IsNullOrWhiteSpace(Country) && Country.Trim().Length != 2)
            {
                errors.Add("Country must use a two-letter ISO code.");
            }

            if (ValidToUtc <= ValidFromUtc)
            {
                errors.Add("ValidToUtc must be after ValidFromUtc.");
            }

            if (!Enum.IsDefined(KeyAlgorithm))
            {
                errors.Add("Unsupported private key algorithm.");
            }

            foreach (var dnsName in DnsNames.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                if (dnsName.Contains(' '))
                {
                    errors.Add($"DNS name '{dnsName}' cannot contain spaces.");
                }
            }

            if(!string.IsNullOrWhiteSpace(ApplicationUri)
                && !Uri.TryCreate(ApplicationUri.Trim(), UriKind.Absolute, out _))
            {
                errors.Add("ApplicationUri must be an absolute URI.");
            }

            foreach (var ipAddress in IpAddresses.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                if (!IPAddress.TryParse(ipAddress, out _))
                {
                    errors.Add($"IP address '{ipAddress}' is not valid.");
                }
            }

            foreach (var eku in EnhancedKeyUsages.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                if (!IsDottedNumericOid(eku.Trim()))
                {
                    errors.Add($"Enhanced key usage '{eku}' is not a valid OID.");
                    continue;
                }

                try
                {
                    _ = new System.Security.Cryptography.Oid(eku.Trim());
                }
                catch
                {
                    errors.Add($"Enhanced key usage '{eku}' is not a valid OID.");
                }
            }

            foreach (var keyUsage in KeyUsages.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                if (!SupportedKeyUsages.Contains(keyUsage.Trim(), StringComparer.OrdinalIgnoreCase))
                {
                    errors.Add($"Key usage '{keyUsage}' is not supported.");
                }
            }

            return errors;
        }

        public static readonly string[] SupportedKeyUsages =
        [
            "DigitalSignature",
            "NonRepudiation",
            "KeyEncipherment",
            "DataEncipherment",
            "KeyAgreement",
            "KeyCertSign",
            "CrlSign"
        ];

        private static void RequireText(string? value, string fieldName, ICollection<string> errors)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                errors.Add($"{fieldName} is required.");
            }
        }

        private static bool IsDottedNumericOid(string value)
        {
            var parts = value.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return parts.Length >= 2 && parts.All(part => part.All(char.IsDigit));
        }

        private static void ValidatePathSegment(string? value, string fieldName, ICollection<string> errors)
        {
            if(string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            if(value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                errors.Add($"{fieldName} contains invalid file name characters.");
            }
        }
    }
}

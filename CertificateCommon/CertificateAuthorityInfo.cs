namespace CertificateManager.src
{
    public sealed class CertificateAuthorityInfo
    {
        public string? ConfiguredThumbprint { get; init; }
        public string? Subject { get; init; }
        public string? Issuer { get; init; }
        public string? Thumbprint { get; init; }
        public string? SerialNumber { get; init; }
        public DateTime NotBefore { get; init; }
        public DateTime NotAfter { get; init; }
        public int DaysToExpiration { get; init; }
        public bool IsExpired { get; init; }
        public bool HasPrivateKey { get; init; }
        public bool IsCertificateAuthority { get; init; }
        public string? PublicKeyAlgorithm { get; init; }
        public int? PublicKeySize { get; init; }
        public string? SignatureAlgorithm { get; init; }
        public int Version { get; init; }
        public string[] KeyUsages { get; init; } = [];
        public string[] EnhancedKeyUsages { get; init; } = [];
    }
}

using CertificateManager.src;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificateCommon
{
    public class CARootNotFoundException() : Exception("NO CA Root")
    {

    }
    public class CARootWithouthPrivateKeyException(): Exception("CA Root withouth Private Key")
    {

    }

    public class NotCARootConfiguredThumbprintException(): Exception("Not configured CA Root data")
    {
    }

    public class CertificationManager
    {
        private sealed record CertificateStoreSearchLocation(StoreName StoreName, StoreLocation StoreLocation);

        public string? CARootThumbprint { get; private set; }
        public Serilog.ILogger? Logger { get; set; }
        //public byte[] LastSerialNumber { get; set; } = new byte[] { 0, 0, 0, 0 };
        public Int32 LastSerialNumber { get; private set; }
        string _dir { get; init; } = "Output";
        public FileManagerCertificate? FileManager { get; init; }
        private IReadOnlyList<CertificateStoreSearchLocation> CertificateAuthorityStores { get; init; } = DefaultCertificateAuthorityStores;

        public CertificationManager(IConfiguration configuration, Serilog.ILogger logger, FileManagerCertificate fileManager)
        {
            Logger = logger;
            var certificationManagerSection = configuration.GetSection("CertificationManager");
            CARootThumbprint = certificationManagerSection.GetSection("CARootThumbPrint").Value;
            CertificateAuthorityStores = ReadCertificateAuthorityStores(certificationManagerSection);
            CARoot = ResolveCertificateAuthority(CARootThumbprint);
            var outputOptions = CertificateOutputOptions.FromConfiguration(configuration);
            var outputData = outputOptions.PrimaryOutput;
            LastSerialNumber = 0;

            FileManager = fileManager;

            outputOptions.EnsureDirectories();

            _dir = outputData;
        }

        public CertificationManager(string caRootThumbprint, int lastSerialNumber)
        {
            CARootThumbprint = caRootThumbprint;
            CARoot = ResolveCertificateAuthority(CARootThumbprint);
            LastSerialNumber = lastSerialNumber;
        }

        public X509Certificate2? CARoot { get; protected set; } = null;

        private static readonly IReadOnlyList<CertificateStoreSearchLocation> DefaultCertificateAuthorityStores =
        [
            new(StoreName.My, StoreLocation.CurrentUser),
            new(StoreName.Root, StoreLocation.CurrentUser),
            new(StoreName.CertificateAuthority, StoreLocation.CurrentUser),
            new(StoreName.My, StoreLocation.LocalMachine),
            new(StoreName.Root, StoreLocation.LocalMachine),
            new(StoreName.CertificateAuthority, StoreLocation.LocalMachine)
        ];

        public X509Certificate2Collection GetCollection(string? parameter, X509FindType findType, StoreName storeName, StoreLocation storeLocation)
        {
            if(string.IsNullOrEmpty(parameter))
            {
                throw new NotCARootConfiguredThumbprintException();
            }

            using(var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                var searchValue = findType == X509FindType.FindByThumbprint
                    ? NormalizeThumbprint(parameter)
                    : parameter;

                // Cerca il certificato. Il 'true' indica di cercare solo i certificati validi.
                var certCollection = store.Certificates.Find(
                    findType,
                    searchValue,
                    validOnly: false // Cerca anche i certificati scaduti
                );

                if(certCollection.Count == 0 && findType == X509FindType.FindByThumbprint)
                {
                    foreach(var certificate in store.Certificates)
                    {
                        if(string.Equals(NormalizeThumbprint(certificate.Thumbprint), searchValue, StringComparison.OrdinalIgnoreCase))
                        {
                            certCollection.Add(certificate);
                        }
                    }
                }

                return certCollection;
                // Se la collezione contiene almeno un certificato, significa che è stato trovato.
            }
        }

        public CertficateFileInfo ExtractRoot(string certFileName)
        {
            if(CARoot is null)
                throw new CARootNotFoundException();

            File.WriteAllText(certFileName, CARoot.ExportCertificatePem());

            return new CertficateFileInfo(certFileName, CARoot);

        }

        public CertficateFileInfo GetInstallableRoot(string certFileName, string password)
        {
            if(CARoot is null)
                throw new CARootNotFoundException();

            return new CertficateFileInfo(certFileName, CARoot);

        }

        public CertificateAuthorityInfo GetCertificateAuthorityInfo()
        {
            if(CARoot is null)
            {
                throw new CARootNotFoundException();
            }

            var now = DateTime.UtcNow;
            var notAfterUtc = CARoot.NotAfter.ToUniversalTime();

            return new CertificateAuthorityInfo
            {
                ConfiguredThumbprint = CARootThumbprint,
                Subject = CARoot.Subject,
                Issuer = CARoot.Issuer,
                Thumbprint = CARoot.Thumbprint,
                SerialNumber = CARoot.SerialNumber,
                NotBefore = CARoot.NotBefore,
                NotAfter = CARoot.NotAfter,
                DaysToExpiration = (int)Math.Floor((notAfterUtc - now).TotalDays),
                IsExpired = notAfterUtc <= now,
                HasPrivateKey = CARoot.HasPrivateKey,
                IsCertificateAuthority = IsCertificateAuthority(CARoot),
                PublicKeyAlgorithm = CARoot.PublicKey.Oid.FriendlyName ?? CARoot.PublicKey.Oid.Value,
                PublicKeySize = GetPublicKeySize(CARoot),
                SignatureAlgorithm = CARoot.SignatureAlgorithm.FriendlyName ?? CARoot.SignatureAlgorithm.Value,
                Version = CARoot.Version,
                KeyUsages = GetKeyUsageNames(CARoot),
                EnhancedKeyUsages = GetEnhancedKeyUsageNames(CARoot)
            };
        }
        public virtual async Task<byte[]?> ConvertIFormFileToByteArrayAsync(IFormFile file)
        {
            if (file == null)
            {
                Logger?.Warning("Input file is null");
                return null;
            }

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    // 2. Open the read stream from the IFormFile
                    // In a real application, consider adding a size limit here:
                    // using (var fileStream = file.OpenReadStream(maxAllowedSize))
                    using (var fileStream = file.OpenReadStream())
                    {
                        // 3. Asynchronously copy the content from the file stream
                        //    to the memory stream. This is efficient for I/O operations.
                        await fileStream.CopyToAsync(memoryStream);
                    }

                    // 4. Reset the memory stream position to the beginning (0)
                    //    before converting it to an array.
                    memoryStream.Position = 0;

                    // 5. Convert the MemoryStream content to a byte array and return it.
                    return memoryStream.ToArray();
                }
            }
            catch (Exception ex)
            {
                Logger?.Error($"Error converting file to byte array: {ex.Message}");
                return null;
            }
        }

        public async Task<CertificateDetails> GetCertInfoWithPassword(IFormFile serverCrt, IFormFile? serverKey, string? password)
        {
            var serverCrtByteArray = await ConvertIFormFileToByteArrayAsync(serverCrt);
            var serverKeyByteArray = await ConvertIFormFileToByteArrayAsync(serverKey);

            return GetCertInfoWithPassword(serverCrtByteArray, serverKeyByteArray, password);
        }

        public async Task<byte[]?> CreatePFX(IFormFile serverCrt, IFormFile? serverKey, string? secretKeyPassword, string pfxPassword)
        {
            var serverCrtByteArray = await ConvertIFormFileToByteArrayAsync(serverCrt);
            var serverKeyByteArray = await ConvertIFormFileToByteArrayAsync(serverKey);

            return CreatePFX(serverCrtByteArray, serverKeyByteArray, secretKeyPassword, pfxPassword);
        }

        public byte[]? CreatePFX(byte[] serverCrt, byte[]? serverKey, string? secretKeyPassword, string pfxPassword)
        {
            if (serverCrt is null || serverCrt.Length == 0)
            {
                return null;
            }

            string privateKey = "";
            string certPem = Encoding.UTF8.GetString(serverCrt);
            if (serverKey is not null)
                privateKey = Encoding.UTF8.GetString(serverKey);

            X509Certificate2 certificate;

            if (!string.IsNullOrEmpty(secretKeyPassword) && !string.IsNullOrEmpty(privateKey))
            {
                certificate = X509Certificate2.CreateFromEncryptedPem(certPem, privateKey, secretKeyPassword);
            }
            else if (!string.IsNullOrEmpty(privateKey))
            {
                certificate = X509Certificate2.CreateFromPem(certPem, privateKey);
            }
            else
            {
                return null;
            }

            // Create a collection to hold the final PFX certificates
            X509Certificate2Collection collection = new X509Certificate2Collection();

            // Import all certificates found in the PEM (this captures the chain)
            X509Certificate2Collection chainParam = new X509Certificate2Collection();
            try
            {
                chainParam.ImportFromPem(certPem);
            }
            catch (Exception ex)
            {
                Logger?.Warning($"Error parsing chain from PEM: {ex.Message}. Proceeding with single certificate.");
            }

            bool mainCertAdded = false;

            // Merge: Use the certificate with the private key for the matching thumbprint
            foreach (var cert in chainParam)
            {
                if (cert.Thumbprint == certificate.Thumbprint)
                {
                    collection.Add(certificate); // Add the one with Private Key
                    mainCertAdded = true;
                }
                else
                {
                    collection.Add(cert); // Add intermediate/root
                }
            }

            // Fallback: If for some reason the main cert wasn't in the loaded chain (unlikely), add it
            if (!mainCertAdded)
            {
                collection.Add(certificate);
            }

            return collection.Export(X509ContentType.Pfx, pfxPassword);
        }



        public CertificateDetails GetCertInfoWithPassword(byte[] serverCrt, byte[]? serverKey, string? password)
        {
            if(serverCrt is null || serverCrt.Length == 0)
            {
                return new CertificateDetails()
                {
                    Message = "Certificate data is null or empty",
                };
            }

            string privateKey = "";
            string certPem = Encoding.UTF8.GetString(serverCrt);
            if(serverKey is not null)
            privateKey = Encoding.UTF8.GetString(serverKey);

            X509Certificate2 certificate;

            try
            {
                if(!string.IsNullOrEmpty(password) && ! string.IsNullOrEmpty(privateKey))
                {
                    certificate = X509Certificate2.CreateFromEncryptedPem(certPem, privateKey, password);
                }
                else if(!string.IsNullOrEmpty(privateKey))
                {
                    certificate = X509Certificate2.CreateFromPem(certPem, privateKey);
                }
                else
                {
                    certificate = X509Certificate2.CreateFromPem(certPem);
                }

            }

            catch(CryptographicException ex)
            {
                // Throw exception for specific handling (e.g., wrong password, invalid format)
                throw new CryptographicException("Failed to load certificate and key. Check PEM format and password.", ex);
            }

            var responseDto = new PrivateKeyCertificateDetails
            {
                // Populate basic details
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                ValidFrom = certificate.NotBefore,
                ValidUntil = certificate.NotAfter,
                ThumbPrint = certificate.Thumbprint,
                KeyAlgo = certificate.PublicKey.Oid.FriendlyName,
                KeySize = certificate.PublicKey.Key.KeySize,

                HasPrivateKey = certificate.HasPrivateKey,

                CanBeUsedForSigning = GetKeyUsage(certificate).HasFlag(X509KeyUsageFlags.DigitalSignature) || GetKeyUsage(certificate).HasFlag(X509KeyUsageFlags.NonRepudiation),
                CanBeUsedForKeyEncryption = GetKeyUsage(certificate).HasFlag(X509KeyUsageFlags.KeyEncipherment) || GetKeyUsage(certificate).HasFlag(X509KeyUsageFlags.KeyAgreement),

                // Message and FileName (if needed, might be omitted if this is an internal function)
                Message = "Certificate and key loaded successfully.",
                FileName = "Loaded from byte arrays"
            };

            return responseDto;
        }

        private X509KeyUsageFlags GetKeyUsage(X509Certificate2 cert)
        {
            var extension = cert.Extensions["2.5.29.15"] as X509KeyUsageExtension;
            return extension != null ? extension.KeyUsages : X509KeyUsageFlags.None;
        }

        private static bool IsCertificateAuthority(X509Certificate2 cert)
        {
            return cert.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .Any(extension => extension.CertificateAuthority);
        }

        private static int? GetPublicKeySize(X509Certificate2 cert)
        {
            using var rsa = cert.GetRSAPublicKey();
            if(rsa is not null)
            {
                return rsa.KeySize;
            }

            using var ecdsa = cert.GetECDsaPublicKey();
            if(ecdsa is not null)
            {
                return ecdsa.KeySize;
            }

            return null;
        }

        private static string[] GetKeyUsageNames(X509Certificate2 cert)
        {
            var extension = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if(extension is null || extension.KeyUsages == X509KeyUsageFlags.None)
            {
                return [];
            }

            return Enum.GetValues<X509KeyUsageFlags>()
                .Where(flag => flag != X509KeyUsageFlags.None && extension.KeyUsages.HasFlag(flag))
                .Select(flag => flag.ToString())
                .ToArray();
        }

        private static string[] GetEnhancedKeyUsageNames(X509Certificate2 cert)
        {
            var extension = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if(extension is null)
            {
                return [];
            }

            return extension.EnhancedKeyUsages
                .Cast<Oid>()
                .Select(oid => string.IsNullOrWhiteSpace(oid.FriendlyName) ? oid.Value ?? string.Empty : $"{oid.FriendlyName} ({oid.Value})")
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToArray();
        }



        public class CertficateFileInfo
        {
            public string? Name { get; init; }
            public DateTime? Created { get; init; }
            public Int64? Size { get; init; }

            public string? Subject { get; init; }
            public string? SerialNumber { get; init; }
            public string? ThumbPrint { get; init; }
            public bool HasPrivateKey { get; init; }
            public string? KeyAlgorithm { get; init; }
            public string? ApplicationUri { get; init; }

            public CertficateFileInfo()
            {

            }

            public CertficateFileInfo(string file, X509Certificate2 cert, string? keyAlgorithm = null, string? applicationUri = null)
            {
                var fileInfo = new FileInfo(file);
                Name = fileInfo.FullName;
                Created = fileInfo.CreationTime;
                Size = fileInfo.Length;

                Subject = cert.Subject;
                SerialNumber = cert.SerialNumber;
                ThumbPrint = cert.Thumbprint;
                HasPrivateKey = cert.HasPrivateKey;
                KeyAlgorithm = keyAlgorithm;
                ApplicationUri = applicationUri;

            }
        }

        public List<CertficateFileInfo> CreatingPFX_CRT(CertificateGenerationRequest request, string? pfxName = "Certificate.pfx", string? certName = "Certificate.crt")
        {
            var validationErrors = request.Validate();
            if(validationErrors.Count > 0)
            {
                throw new ArgumentException(string.Join(Environment.NewLine, validationErrors));
            }

            List<CertficateFileInfo> fileInfo = new List<CertficateFileInfo>();
            if(CARoot is null)
            {
                throw new CARootNotFoundException();
            }

            var resolvedKeyAlgorithm = ResolvePrivateKeyAlgorithm(request.KeyAlgorithm, CARoot);
            using var serverKey = CreatePrivateKey(resolvedKeyAlgorithm);

            X509Certificate2? x509Son = CreateCertificate(request, serverKey, CARoot, isCertificateAuthority: false);

            if(x509Son is null)
            {
                Logger?.Warning("The certificate creation failed");
                return new List<CertficateFileInfo>();
            }
            else
            {
                Logger?.Information($"Created: {x509Son}");
            }

            // Build path: Output/Solution/Name or Output/Solution if Name is not provided
            string path = string.IsNullOrEmpty(request.Name)
                ? Path.Combine(_dir, request.Solution!)
                : Path.Combine(_dir, request.Solution!, request.Name);

            if(!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            var serverPfx = CopyWithPrivateKey(x509Son!, serverKey);
            if(serverPfx is not null)
            {
                try
                {
                    var pfxPassword = request.PfxPassword ?? string.Empty;
                    string pfxFileName = Path.Join(path, pfxName);
                    File.WriteAllBytes(pfxFileName, serverPfx.Export(X509ContentType.Pfx, pfxPassword));
                    fileInfo.Add(new CertficateFileInfo(pfxFileName, x509Son, resolvedKeyAlgorithm.ToString(), request.ApplicationUri));

                    string certFileName = Path.Join(path, certName);

                    //File.WriteAllBytes(certFileName, x509Son.Export(X509ContentType.Cert));//questa per CER
                    File.WriteAllText(certFileName, x509Son.ExportCertificatePem());//questa per CER
                    fileInfo.Add(new CertficateFileInfo(certFileName, x509Son, resolvedKeyAlgorithm.ToString(), request.ApplicationUri));

                    string derFileName = Path.Join(path, "Certificate.der");
                    File.WriteAllBytes(derFileName, x509Son.Export(X509ContentType.Cert));
                    fileInfo.Add(new CertficateFileInfo(derFileName, x509Son, resolvedKeyAlgorithm.ToString(), request.ApplicationUri));

                    if(request.ExportPrivateKeyPem)
                    {
                        string privateKeyPem = ExportPrivateKeyPem(serverKey);

                        string privateKeyFName = Path.Join(path, "private.key");

                        File.WriteAllText(privateKeyFName, privateKeyPem);
                        Logger?.Information("Private key generated: 'private.key'");
                    }

                    string certFileNameRoot = Path.Join(path, "Root.crt");
                    fileInfo.Add(ExtractRoot(certFileNameRoot));

                    FileManager?.Add(commonName: request.CommonName!, company: request.Organization!, oid: string.Join(",", request.EnhancedKeyUsages),
                        pfxFile: pfxFileName, crtRoot: certFileNameRoot, derFile: derFileName, solution: request.Solution!,
                        name: request.Name, password: pfxPassword, rootThumbprint: CARoot.Thumbprint, address: GetPrimaryEndpoint(request), applicationUri: request.ApplicationUri, dns: request.DnsNames,
                        ipAddresses: request.IpAddresses, organizationalUnit: request.OrganizationalUnit, locality: request.Locality, state: request.State,
                        country: request.Country, validFromUtc: request.ValidFromUtc, validToUtc: request.ValidToUtc, keyUsages: request.KeyUsages, keyAlgorithm: resolvedKeyAlgorithm.ToString(),
                        signatureHashAlgorithm: request.SignatureHashAlgorithm);

                }
                catch(Exception ex)
                {
                    Logger?.Warning($"Creating files making error: {ex.Message}");
                    throw;
                }
            }

            return fileInfo;
        }

        public List<CertficateFileInfo> CreatingPFX_CRT(string? commonName, string? oid, string? serverAddress, string? company, string? exportPWD, DateTimeOffset expiring, string? solutionFolder, string? name = null, string? pfxName = "Certificate.pfx", string? certName = "Certificate.crt", params string[] serverDNS)
        {
            var request = new CertificateGenerationRequest
            {
                CommonName = commonName,
                Organization = company,
                Solution = solutionFolder,
                Name = name,
                PfxPassword = exportPWD,
                DnsNames = BuildLegacyDnsNames(serverAddress, serverDNS),
                IpAddresses = BuildLegacyIpAddresses(serverAddress),
                KeyUsages = ["DigitalSignature"],
                EnhancedKeyUsages = SplitOidList(oid),
                ValidFromUtc = DateTimeOffset.UtcNow,
                ValidToUtc = expiring
            };

            return CreatingPFX_CRT(request, pfxName, certName);
        }

        public bool IsLocalHost(string serverAddress)
        {
            if(string.Compare(serverAddress, "localhost", true) == 0)
            {
                return true;
            }
            return false;
        }

        public IPAddress ManageServerAddress(string serverAddress)
        {
            if(IsLocalHost(serverAddress))
            {
                return IPAddress.Loopback;
            }

            if(string.Compare(serverAddress, "*", true) == 0)
            {
                return IPAddress.Any;
            }

            try
            {
                return IPAddress.Parse(serverAddress);
            }
            catch(Exception ex)
            {
                Logger?.Error("Managing ip address error");
                return IPAddress.Any;
            }
        }

        //new Oid("1.3.6.1.5.5.7.3.1")

        public X509Certificate2? CreateCASon(string? commonName, string? oid, string? serverAddress, string? company, ECDsa privateKey, DateTimeOffset expiring, string? friendlyName = "", params string[] serverDNS)
        {
            return CreateCASon(commonName, oid, serverAddress, company, privateKey, expiring, CARoot, false, friendlyName, serverDNS);
        }

        public X509Certificate2? CreateCASon(string? commonName, string? oid, string? serverAddress, string? company, ECDsa privateKey, DateTimeOffset expiring, X509Certificate2? issuer, bool isCertificateAuthority, string? friendlyName = "", params string[] serverDNS)
        {
            if(issuer is null)
            {
                throw new NotCARootConfiguredThumbprintException();
            }

            if(!issuer.HasPrivateKey)
            {
                throw new CARootWithouthPrivateKeyException();
            }

            var request = new CertificateGenerationRequest
            {
                CommonName = commonName,
                Organization = company,
                Solution = "Legacy",
                PfxPassword = "Legacy",
                DnsNames = BuildLegacyDnsNames(serverAddress, serverDNS),
                IpAddresses = BuildLegacyIpAddresses(serverAddress),
                KeyUsages = ["DigitalSignature"],
                EnhancedKeyUsages = SplitOidList(oid),
                ValidFromUtc = DateTimeOffset.UtcNow,
                ValidToUtc = expiring
            };

            return CreateCertificate(request, privateKey, issuer, isCertificateAuthority, friendlyName);
        }

        private X509Certificate2? CreateCertificate(CertificateGenerationRequest request, AsymmetricAlgorithm privateKey, X509Certificate2 issuer, bool isCertificateAuthority, string? friendlyName = "")
        {
            // Parse OID string - can contain multiple OIDs separated by comma, semicolon, or space
            var oidCollection = new OidCollection();

            foreach (var oidStr in request.EnhancedKeyUsages.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                try
                {
                    var trimmedOid = oidStr.Trim();
                    oidCollection.Add(new Oid(trimmedOid));
                }
                catch
                {
                    // Skip invalid OIDs
                    Logger?.Warning($"Invalid OID: {oidStr}");
                }
            }

            // If no valid OIDs were added, return null
            if (oidCollection.Count == 0 && !isCertificateAuthority)
            {
                Logger?.Warning("No valid OIDs provided");
                return null;
            }

            if(request.ValidToUtc > issuer.NotAfter)
            {
                throw new ArgumentException("Certificate validity cannot exceed issuer validity.");
            }

            var subject = CreateSubject(request);

            var serverRequest = CreateCertificateRequest(subject, privateKey, ResolveHashAlgorithm(request.SignatureHashAlgorithm));

            // Aggiungi le estensioni necessarie per un certificato server
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCertificateAuthority, isCertificateAuthority, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(ResolveKeyUsages(request.KeyUsages), true));
            if(!isCertificateAuthority)
            {
                serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oidCollection, false));
            }
            //var sanBuilder = new SubjectAlternativeNameBuilder();

            var san = new SubjectAlternativeNameBuilder();
            var hasSubjectAlternativeName = false;

            foreach(var ipAddress in request.IpAddresses.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                if(IPAddress.TryParse(ipAddress, out var parsedAddress))
                {
                    san.AddIpAddress(parsedAddress);
                    hasSubjectAlternativeName = true;
                }
            }

            foreach(var serverN in request.DnsNames.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                san.AddDnsName(serverN);
                hasSubjectAlternativeName = true;
            }

            if(!string.IsNullOrWhiteSpace(request.ApplicationUri)
                && Uri.TryCreate(request.ApplicationUri.Trim(), UriKind.Absolute, out var applicationUri))
            {
                san.AddUri(applicationUri);
                hasSubjectAlternativeName = true;
            }

            if(hasSubjectAlternativeName)
            {
                serverRequest.CertificateExtensions.Add(san.Build());
            }

            byte[] serialNumber = BitConverter.GetBytes(++LastSerialNumber);

            try
            {
                var cert = serverRequest.Create(issuer, request.ValidFromUtc, request.ValidToUtc, serialNumber);
                cert.FriendlyName = friendlyName;
                return cert;
            }
            catch(Exception ex)
            {
                Logger?.Error($"NO CA Root well configured: {ex.Message}");
                throw new CARootNotFoundException();
            }
        }

        private static X500DistinguishedName CreateSubject(CertificateGenerationRequest request)
        {
            var parts = new List<string>
            {
                $"CN={EscapeDistinguishedNameValue(request.CommonName!)}",
                $"O={EscapeDistinguishedNameValue(request.Organization!)}"
            };

            AddSubjectPart(parts, "OU", request.OrganizationalUnit);
            AddSubjectPart(parts, "L", request.Locality);
            AddSubjectPart(parts, "S", request.State);
            AddSubjectPart(parts, "C", request.Country);

            return new X500DistinguishedName(string.Join(", ", parts));
        }

        private static AsymmetricAlgorithm CreatePrivateKey(CertificatePrivateKeyAlgorithm algorithm)
        {
            return algorithm switch
            {
                CertificatePrivateKeyAlgorithm.EcdsaP256 => ECDsa.Create(ECCurve.NamedCurves.nistP256),
                CertificatePrivateKeyAlgorithm.EcdsaP384 => ECDsa.Create(ECCurve.NamedCurves.nistP384),
                CertificatePrivateKeyAlgorithm.Rsa2048 => RSA.Create(2048),
                CertificatePrivateKeyAlgorithm.Rsa3072 => RSA.Create(3072),
                CertificatePrivateKeyAlgorithm.Rsa4096 => RSA.Create(4096),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported private key algorithm.")
            };
        }

        private static CertificatePrivateKeyAlgorithm ResolvePrivateKeyAlgorithm(CertificatePrivateKeyAlgorithm requestedAlgorithm, X509Certificate2 issuer)
        {
            if(requestedAlgorithm != CertificatePrivateKeyAlgorithm.AutoFromIssuerRoot)
            {
                return requestedAlgorithm;
            }

            using var ecdsaPublicKey = issuer.GetECDsaPublicKey();
            if(ecdsaPublicKey is not null)
            {
                return ecdsaPublicKey.KeySize <= 256
                    ? CertificatePrivateKeyAlgorithm.EcdsaP256
                    : CertificatePrivateKeyAlgorithm.EcdsaP384;
            }

            using var rsaPublicKey = issuer.GetRSAPublicKey();
            if(rsaPublicKey is not null)
            {
                if(rsaPublicKey.KeySize <= 2048)
                {
                    return CertificatePrivateKeyAlgorithm.Rsa2048;
                }

                return rsaPublicKey.KeySize <= 3072
                    ? CertificatePrivateKeyAlgorithm.Rsa3072
                    : CertificatePrivateKeyAlgorithm.Rsa4096;
            }

            return CertificatePrivateKeyAlgorithm.EcdsaP256;
        }

        private static CertificateRequest CreateCertificateRequest(X500DistinguishedName subject, AsymmetricAlgorithm privateKey, HashAlgorithmName hashAlgorithm)
        {
            return privateKey switch
            {
                ECDsa ecdsa => new CertificateRequest(subject, ecdsa, hashAlgorithm),
                RSA rsa => new CertificateRequest(subject, rsa, hashAlgorithm, RSASignaturePadding.Pkcs1),
                _ => throw new ArgumentException("Unsupported private key algorithm.", nameof(privateKey))
            };
        }

        private static X509Certificate2 CopyWithPrivateKey(X509Certificate2 certificate, AsymmetricAlgorithm privateKey)
        {
            return privateKey switch
            {
                ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
                RSA rsa => certificate.CopyWithPrivateKey(rsa),
                _ => throw new ArgumentException("Unsupported private key algorithm.", nameof(privateKey))
            };
        }

        private static string ExportPrivateKeyPem(AsymmetricAlgorithm privateKey)
        {
            return privateKey switch
            {
                ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKeyPem(),
                RSA rsa => rsa.ExportPkcs8PrivateKeyPem(),
                _ => throw new ArgumentException("Unsupported private key algorithm.", nameof(privateKey))
            };
        }

        private static void AddSubjectPart(List<string> parts, string key, string? value)
        {
            if(!string.IsNullOrWhiteSpace(value))
            {
                parts.Add($"{key}={EscapeDistinguishedNameValue(value)}");
            }
        }

        private static string EscapeDistinguishedNameValue(string value)
        {
            return value.Trim()
                .Replace("\\", "\\\\")
                .Replace(",", "\\,")
                .Replace("+", "\\+")
                .Replace("\"", "\\\"")
                .Replace("<", "\\<")
                .Replace(">", "\\>")
                .Replace(";", "\\;");
        }

        private static HashAlgorithmName ResolveHashAlgorithm(string? algorithm)
        {
            return algorithm?.Trim().ToUpperInvariant() switch
            {
                "SHA256" => HashAlgorithmName.SHA256,
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA384
            };
        }

        private static X509KeyUsageFlags ResolveKeyUsages(IEnumerable<string> keyUsages)
        {
            var flags = X509KeyUsageFlags.None;

            foreach(var keyUsage in keyUsages.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                flags |= keyUsage.Trim().ToUpperInvariant() switch
                {
                    "DIGITALSIGNATURE" => X509KeyUsageFlags.DigitalSignature,
                    "NONREPUDIATION" => X509KeyUsageFlags.NonRepudiation,
                    "KEYENCIPHERMENT" => X509KeyUsageFlags.KeyEncipherment,
                    "DATAENCIPHERMENT" => X509KeyUsageFlags.DataEncipherment,
                    "KEYAGREEMENT" => X509KeyUsageFlags.KeyAgreement,
                    "KEYCERTSIGN" => X509KeyUsageFlags.KeyCertSign,
                    "CRLSIGN" => X509KeyUsageFlags.CrlSign,
                    _ => X509KeyUsageFlags.None
                };
            }

            return flags == X509KeyUsageFlags.None ? X509KeyUsageFlags.DigitalSignature : flags;
        }

        private static string[] SplitOidList(string? oid)
        {
            return string.IsNullOrWhiteSpace(oid)
                ? []
                : oid.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        private static string? TryParseIpAddress(string? value)
        {
            return IPAddress.TryParse(value, out var ipAddress) ? ipAddress.ToString() : null;
        }

        private static string[] BuildLegacyDnsNames(string? serverAddress, string[]? serverDNS)
        {
            var dnsNames = new List<string>(serverDNS ?? []);

            if(!string.IsNullOrWhiteSpace(serverAddress) && !IPAddress.TryParse(serverAddress, out _))
            {
                dnsNames.Add(serverAddress);
            }

            return dnsNames.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static string[] BuildLegacyIpAddresses(string? serverAddress)
        {
            if(IPAddress.TryParse(serverAddress, out var ipAddress))
            {
                return [ipAddress.ToString()];
            }

            if(string.Equals(serverAddress, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                return [IPAddress.Loopback.ToString()];
            }

            return [];
        }

        private static string? GetPrimaryEndpoint(CertificateGenerationRequest request)
        {
            return request.IpAddresses.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))
                ?? request.DnsNames.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
        }

        public X509Certificate2? Get(string? textToSearch, X509FindType type, StoreName storeName, StoreLocation storeLocation)
        {
            var certCollection = GetCollection(textToSearch, type, storeName, storeLocation);

            if(certCollection.Count > 1)
            {
                throw new Exception("More CA ROOT with same Thumbprint");
            }
            else if(certCollection.Count == 1)
            {
                return certCollection.FirstOrDefault() ?? null;
            }

            return null;
        }

        public X509Certificate2? ResolveCertificateAuthority(string? thumbprint)
        {
            if(string.IsNullOrWhiteSpace(thumbprint))
            {
                throw new NotCARootConfiguredThumbprintException();
            }

            var normalizedThumbprint = NormalizeThumbprint(thumbprint);
            var candidates = new List<X509Certificate2>();

            Logger?.Information("Resolving CA root thumbprint {Thumbprint} across {StoreCount} configured certificate stores.",
                normalizedThumbprint,
                CertificateAuthorityStores.Count);

            foreach(var storeToSearch in CertificateAuthorityStores)
            {
                var foundCertificates = GetCollection(
                    normalizedThumbprint,
                    X509FindType.FindByThumbprint,
                    storeToSearch.StoreName,
                    storeToSearch.StoreLocation);

                Logger?.Information("Searched CA root in {StoreLocation}/{StoreName}. Matches={Count}.",
                    storeToSearch.StoreLocation,
                    storeToSearch.StoreName,
                    foundCertificates.Count);

                foreach(var certificate in foundCertificates)
                {
                    candidates.Add(certificate);
                    Logger?.Information("Found CA candidate {Thumbprint} in {StoreLocation}/{StoreName}. HasPrivateKey={HasPrivateKey}",
                        certificate.Thumbprint,
                        storeToSearch.StoreLocation,
                        storeToSearch.StoreName,
                        certificate.HasPrivateKey);
                }
            }

            var candidatesWithPrivateKey = candidates
                .Where(certificate => certificate.HasPrivateKey)
                .GroupBy(certificate => NormalizeThumbprint(certificate.Thumbprint))
                .Select(group => group.First())
                .ToList();

            if(candidatesWithPrivateKey.Count >= 1)
            {
                return candidatesWithPrivateKey[0];
            }

            if(candidates.Count > 1)
            {
                Logger?.Warning("More CA certificates found for the same thumbprint, but none has a private key. Returning the first certificate found.");
            }

            return candidates.FirstOrDefault();
        }

        private static IReadOnlyList<CertificateStoreSearchLocation> ReadCertificateAuthorityStores(IConfigurationSection certificationManagerSection)
        {
            var configuredStores = certificationManagerSection
                .GetSection("CARootStores")
                .GetChildren()
                .Select(ReadCertificateStoreSearchLocation)
                .Where(store => store is not null)
                .Cast<CertificateStoreSearchLocation>()
                .ToList();

            if(configuredStores.Count > 0)
            {
                return configuredStores;
            }

            var storeNameValue = certificationManagerSection.GetSection("CARootStoreName").Value;
            var storeLocationValue = certificationManagerSection.GetSection("CARootStoreLocation").Value;
            if(!string.IsNullOrWhiteSpace(storeNameValue) || !string.IsNullOrWhiteSpace(storeLocationValue))
            {
                return
                [
                    new(
                        ParseEnumOrDefault(storeNameValue, StoreName.My),
                        ParseEnumOrDefault(storeLocationValue, StoreLocation.CurrentUser))
                ];
            }

            return DefaultCertificateAuthorityStores;
        }

        private static CertificateStoreSearchLocation? ReadCertificateStoreSearchLocation(IConfigurationSection section)
        {
            var storeNameValue = section.GetSection("StoreName").Value;
            var storeLocationValue = section.GetSection("StoreLocation").Value;

            if(string.IsNullOrWhiteSpace(storeNameValue) && string.IsNullOrWhiteSpace(storeLocationValue))
            {
                return null;
            }

            return new CertificateStoreSearchLocation(
                ParseEnumOrDefault(storeNameValue, StoreName.My),
                ParseEnumOrDefault(storeLocationValue, StoreLocation.CurrentUser));
        }

        private static TEnum ParseEnumOrDefault<TEnum>(string? value, TEnum defaultValue)
            where TEnum : struct, Enum
        {
            return Enum.TryParse<TEnum>(value, ignoreCase: true, out var parsedValue)
                ? parsedValue
                : defaultValue;
        }

        private static string NormalizeThumbprint(string? thumbprint)
        {
            if(string.IsNullOrWhiteSpace(thumbprint))
            {
                return string.Empty;
            }

            return new string(thumbprint
                .Where(Uri.IsHexDigit)
                .Select(char.ToUpperInvariant)
                .ToArray());
        }

        /// <summary>
        /// Controlla l'esistenza di un certificato in un dato archivio tramite il suo Thumbprint.
        /// </summary>
        public bool CertificateExists(string thumbprint, StoreName storeName, StoreLocation storeLocation)
        {
            return Get(thumbprint, X509FindType.FindByThumbprint, storeName, storeLocation) != null;
        }
    }
}

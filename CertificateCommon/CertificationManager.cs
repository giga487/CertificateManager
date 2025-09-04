using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificateCommon
{
    public class CARootWithouthPrivateKey(): Exception("CA Root withouth Private Key")
    {

    }

    public class NotCARootConfiguredThumbprintException(): Exception("Not configured CA Root data")
    {
    }

    public class CertificationManager
    {
        public string? CARootThumbprint { get; private set; }
        public Serilog.ILogger? Logger { get; set; }
        //public byte[] LastSerialNumber { get; set; } = new byte[] { 0, 0, 0, 0 };
        public Int32 LastSerialNumber { get; private set; }
        string? _dir { get; init; } = "";

        public CertificationManager(IConfiguration configuration, Serilog.ILogger logger)
        {
            Logger = logger;
            CARootThumbprint = configuration.GetSection("CertificationManager").GetSection("CARootThumbPrint").Value;
            CARoot = Get(CARootThumbprint, X509FindType.FindByThumbprint, StoreName.My, StoreLocation.CurrentUser);
            var outputData = configuration.GetSection("CertificationManager").GetSection("Output").Value;
            LastSerialNumber = 0;

            if(!string.IsNullOrEmpty(outputData) && !Directory.Exists(outputData))
            {
                Directory.CreateDirectory(outputData);
                _dir = outputData;
            }         
        }

        public CertificationManager(string caRootThumbprint, int lastSerialNumber)
        {
            CARootThumbprint = caRootThumbprint;
            CARoot = Get(CARootThumbprint, X509FindType.FindByThumbprint, StoreName.My, StoreLocation.CurrentUser);
            LastSerialNumber = lastSerialNumber;
        }

        public X509Certificate2? CARoot { get; protected set; } = null;

        public X509Certificate2Collection GetCollection(string? parameter, X509FindType findType, StoreName storeName, StoreLocation storeLocation)
        {
            if(string.IsNullOrEmpty(parameter))
            {
                throw new NotCARootConfiguredThumbprintException();
            }

            using(var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);

                // Cerca il certificato. Il 'true' indica di cercare solo i certificati validi.
                var certCollection = store.Certificates.Find(
                    findType,
                    parameter,
                    validOnly: false // Cerca anche i certificati scaduti
                );

                return certCollection;
                // Se la collezione contiene almeno un certificato, significa che è stato trovato.
            }
        }

        public void CreatingPFX_CRT(string serverAddress, string company, string exportPWD, DateTimeOffset expiring, string pfxName = "Certificate.pfx", string certName = "Certificate.crt", bool withDNS = false, string[]? DNSs = null)
        {
            using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // Uso di ECDsa come da te suggerito

            X509Certificate2? x509Son = CreateCASon(serverAddress, company, serverKey, expiring);

            if(x509Son is null)
            {
                Logger?.Warning("The certificate creation failed");
                return;
            }



            var serverPfx = x509Son!.CopyWithPrivateKey(serverKey);
            if(!string.IsNullOrEmpty(exportPWD) && serverPfx is not null)
            {
                string pfxFileName = Path.Join(_dir, pfxName);

                File.WriteAllBytes(pfxFileName, serverPfx.Export(X509ContentType.Pfx, exportPWD));
            }

            string certFileName = Path.Join(_dir, certName);
            File.WriteAllBytes(certFileName, x509Son.Export(X509ContentType.Cert));         


        }

        public X509Certificate2? CreateCASon(string serverAddress, string company, ECDsa privateKey, DateTimeOffset expiring, bool withDNS = false, string[]? DNSs = null)
        {
            if(!CARoot?.HasPrivateKey ?? false)
            {
                throw new CARootWithouthPrivateKey();
            }

            var serverRequest = new CertificateRequest(
                $"CN={serverAddress} O={company}",
                privateKey,
                HashAlgorithmName.SHA256);

            // Aggiungi le estensioni necessarie per un certificato server
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            var sanBuilder = new SubjectAlternativeNameBuilder();

            if(withDNS && DNSs is not null)
            {
                sanBuilder.AddDnsName("mioserver.local");
                sanBuilder.AddDnsName("localhost");
            }

            serverRequest.CertificateExtensions.Add(sanBuilder.Build());

            byte[] serialNumber = BitConverter.GetBytes(++LastSerialNumber);

            if(CARoot is not null)
            {
                return serverRequest.Create(CARoot, DateTimeOffset.Now.AddDays(-1), expiring, serialNumber);
            }
            else
            {
                Logger?.Warning("NO CA Root well configured");
                return null;
            }
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

        /// <summary>
        /// Controlla l'esistenza di un certificato in un dato archivio tramite il suo Thumbprint.
        /// </summary>
        public bool CertificateExists(string thumbprint, StoreName storeName, StoreLocation storeLocation)
        {
            return Get(thumbprint, X509FindType.FindByThumbprint, storeName, storeLocation) != null;
        }
    }
}

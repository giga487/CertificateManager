using CertificateManager.src;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Net;
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
        public string? CARootThumbprint { get; private set; }
        public Serilog.ILogger? Logger { get; set; }
        //public byte[] LastSerialNumber { get; set; } = new byte[] { 0, 0, 0, 0 };
        public Int32 LastSerialNumber { get; private set; }
        string _dir { get; init; } = "Output";
        public FileManagerCertificate? FileManager { get; init; }

        public CertificationManager(IConfiguration configuration, Serilog.ILogger logger, FileManagerCertificate fileManager)
        {
            Logger = logger;
            CARootThumbprint = configuration.GetSection("CertificationManager").GetSection("CARootThumbPrint").Value;
            CARoot = Get(CARootThumbprint, X509FindType.FindByThumbprint, StoreName.Root, StoreLocation.CurrentUser);
            var outputData = configuration.GetSection("CertificationManager").GetSection("Output").Value;
            LastSerialNumber = 0;

            FileManager = fileManager;

            if(!string.IsNullOrEmpty(outputData) && !Directory.Exists(outputData))
            {
                Directory.CreateDirectory(outputData);
            }

            _dir = outputData;
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
        public async Task<byte[]?> ConvertIFormFileToByteArrayAsync(IFormFile file)
        {

            try
            {
                using(var memoryStream = new MemoryStream())
                {
                    // 2. Open the read stream from the IFormFile
                    // In a real application, consider adding a size limit here: 
                    // using (var fileStream = file.OpenReadStream(maxAllowedSize))
                    using(var fileStream = file.OpenReadStream())
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
            catch
            {
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
            if(serverCrt is null || serverCrt.Length == 0)
            {
                return null;
            }

            string privateKey = "";
            string certPem = Encoding.UTF8.GetString(serverCrt);
            if(serverKey is not null)
                privateKey = Encoding.UTF8.GetString(serverKey);


            X509Certificate2 certificate;

            if(!string.IsNullOrEmpty(secretKeyPassword) && !string.IsNullOrEmpty(privateKey))
            {
                certificate = X509Certificate2.CreateFromEncryptedPem(certPem, privateKey, secretKeyPassword);
            }
            else if(!string.IsNullOrEmpty(privateKey))
            {
                certificate = X509Certificate2.CreateFromPem(certPem, privateKey);
            }
            else
            {

                return null;
            }

            return certificate.Export(X509ContentType.Pfx, pfxPassword);
            
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



        public class CertficateFileInfo
        {
            public string? Name { get; init; }
            public DateTime? Created { get; init; }
            public Int64? Size { get; init; }

            public string? Subject { get; init; }
            public string? SerialNumber { get; init; }
            public string? ThumbPrint { get; init; }
            public bool HasPrivateKey { get; init; }

            public CertficateFileInfo()
            {

            }

            public CertficateFileInfo(string file, X509Certificate2 cert)
            {
                var fileInfo = new FileInfo(file);
                Name = fileInfo.FullName;
                Created = fileInfo.CreationTime;
                Size = fileInfo.Length;

                Subject = cert.Subject;
                SerialNumber = cert.SerialNumber;
                ThumbPrint = cert.Thumbprint;
                HasPrivateKey = cert.HasPrivateKey;

            }
        }

        public List<CertficateFileInfo> CreatingPFX_CRT(string? commonName, string? oid, string? serverAddress, string? company, string? exportPWD, DateTimeOffset expiring, string? solutionFolder, string? pfxName = "Certificate.pfx", string? certName = "Certificate.crt", params string[] serverDNS)
        {
            List<CertficateFileInfo> fileInfo = new List<CertficateFileInfo>();
            using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // Uso di ECDsa come da te suggerito

            if(CARoot is null)
            {
                throw new CARootNotFoundException();
            }

            X509Certificate2? x509Son = CreateCASon(commonName: commonName, oid: oid, serverAddress, company, serverKey, expiring, serverDNS: serverDNS);

            if(x509Son is null)
            {
                Logger?.Warning("The certificate creation failed");
                return new List<CertficateFileInfo>();
            }
            else
            {
                Logger?.Information($"Created: {x509Son}");
            }

            string path = Path.Combine(_dir, solutionFolder);

            if(!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            var serverPfx = x509Son!.CopyWithPrivateKey(serverKey);
            if(!string.IsNullOrEmpty(exportPWD) && serverPfx is not null)
            {
                try
                {
                    string pfxFileName = Path.Join(path, pfxName);
                    File.WriteAllBytes(pfxFileName, serverPfx.Export(X509ContentType.Pfx, exportPWD));
                    fileInfo.Add(new CertficateFileInfo(pfxFileName, x509Son));

                    string certFileName = Path.Join(path, certName);

                    //File.WriteAllBytes(certFileName, x509Son.Export(X509ContentType.Cert));//questa per CER
                    File.WriteAllText(certFileName, x509Son.ExportCertificatePem());//questa per CER
                    fileInfo.Add(new CertficateFileInfo(certFileName, x509Son));

                    string certFileNameRoot = Path.Join(path, "Root.crt");
                    fileInfo.Add(ExtractRoot(certFileNameRoot));

                    FileManager?.Add(commonName: commonName, company: company, oid: oid,
                        pfxFile: pfxFileName, crtRoot: certFileNameRoot, solution: solutionFolder, 
                        password: exportPWD, rootThumbprint: CARoot.Thumbprint, address: serverAddress, dns: serverDNS);

                }
                catch(Exception ex)
                {
                    Logger?.Warning($"Creating files making error: {ex.Message}");
                    throw;
                }
            }

            return fileInfo;
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
            if(CARoot is null)
            {
                throw new NotCARootConfiguredThumbprintException();
            }

            if(!CARoot?.HasPrivateKey ?? false)
            {
                throw new CARootWithouthPrivateKeyException();
            }

            Oid? oid1 = null;

            try
            {
                oid1 = new Oid(oid);
            }
            catch
            {
                return null;
            }


            var subject = new X500DistinguishedName(
                $"CN={commonName}, O={company}, L=Pisa, S=PI, C=IT");

            var serverRequest = new CertificateRequest(
                subject,
                privateKey,
                HashAlgorithmName.SHA384);

            // Aggiungi le estensioni necessarie per un certificato server
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { oid1 }, false));
            //var sanBuilder = new SubjectAlternativeNameBuilder();

            var san = new SubjectAlternativeNameBuilder();

            List<string>? listOfDnss = serverDNS.ToList();

            IPAddress address = IPAddress.None;

            if(IsLocalHost(serverAddress))
            {
                IPAddress[] localhostAddresses = Dns.GetHostAddresses(serverAddress);

                foreach(var addres in localhostAddresses)
                {
                    if(addres.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        address = addres;
                        break;
                    }
                }
                listOfDnss.Add(serverAddress);
            }
            else
            {
                address = ManageServerAddress(serverAddress);
            }

            san.AddIpAddress(ipAddress: address);

            foreach(var serverN in listOfDnss ?? new List<string>())
            {
                san.AddDnsName(serverN);
            }

            san.Build();

            //if(withDNS && DNSs is not null)
            //{
            //    sanBuilder.AddDnsName("mioserver.local");
            //    sanBuilder.AddDnsName("localhost");
            //}

            serverRequest.CertificateExtensions.Add(san.Build());

            byte[] serialNumber = BitConverter.GetBytes(++LastSerialNumber);

            if(CARoot is not null)
            {
                try
                {
                    var cert = serverRequest.Create(CARoot, DateTimeOffset.Now.AddDays(-1), CARoot.NotAfter, serialNumber);
                    cert.FriendlyName = friendlyName;
                    return cert;
                }
                catch(Exception ex)
                {
                    Logger?.Error($"NO CA Root well configured: {ex.Message}");
                    throw new CARootNotFoundException();
                }
                finally
                {

                }
            }
            else
            {
                Logger?.Warning("NO CA Root well configured");
                throw new CARootNotFoundException();
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

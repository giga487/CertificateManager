using CertificateCommon;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CertificateManager.src
{
    public enum CertificateTypes
    {
        Default = 0,
        CARootWithKey = 1,
        PFX = 2,
        CARootNoKey = 3,
        CRT = 4,
        DER = 5,

    }

    public class CertificateDB
    {
        public DateTime Modified { get; set; } = DateTime.Now;
        public List<Certificate> CertificatesDB { get; set; } = new List<Certificate>();
        
        public int? MaxId
        {
            get
            {
                if(CertificatesDB.Count == 0)
                    return 0;

                return CertificatesDB.Max(x => x.Id);   
            }
        }

        public bool GetIDBySolution(string solutionName, out int? id)
        {
            id = -1;
            var solution = CertificatesDB
                .Where(t => string.Compare(solutionName, t.Solution, true) == 0)
                .OrderByDescending(t => t.Creation)
                .ThenByDescending(t => t.Id)
                .FirstOrDefault();

            if(solution == null)
                return false;


            id = solution.Id;

            return true;

        }

        public bool Get(int id, out Certificate? found)
        {
            found = CertificatesDB.Find(t => t.Id == id);

            if(found is not null)
                return true;

            return false;
        }

        public void Add(string solution, Certificate cert)
        {
            CertificatesDB.Add(cert);

        }

    }

    public class PrivateKeyCertificateDetails : CertificateDetails
    {
        // Indicates whether the certificate contains a private key (Key property is available).
        public bool HasPrivateKey { get; set; }

        // Indicates whether the private key is exportable (can be extracted).
        public bool IsPrivateKeyExportable { get; set; }

        // Indicates whether the certificate can be used for digital signing (from Key Usage extension).
        public bool CanBeUsedForSigning { get; set; }

        // Indicates whether the certificate can be used for key encryption or key agreement (from Key Usage extension).
        public bool CanBeUsedForKeyEncryption { get; set; }

        // Optional: Storage flags used when loading the certificate (important for security).
        public X509KeyStorageFlags StorageFlags { get; set; }
    }

    public class CertificateDetails
    {
        // Il nome del campo sarà preso da Display(Name)
        [Display(Name = "Message")]
        public string Message { get; set; } = "Certificate successfully loaded and processed.";

        [Display(Name = "Name File")]
        public string FileName { get; set; }

        [Display(Name = "Subject")]
        public string Subject { get; set; }

        [Display(Name = "Issuer")]
        public string Issuer { get; set; }

        [JsonPropertyName("validFrom")]
        [Display(Name = "Valido Dal")] // Nome amichevole per la data
        public DateTime ValidFrom { get; set; }

        [JsonPropertyName("validUntil")]
        [Display(Name = "Valido Fino Al")] // Nome amichevole per la data
        public DateTime ValidUntil { get; set; }

        [Display(Name = "THumb Print")]
        public string ThumbPrint { get; set; }

        [Display(Name = "Algorithm Key")]
        public string KeyAlgo { get; set; }

        [Display(Name = "Key Size (bits)")]
        public int KeySize { get; set; }
    }

    public class Certificate
    {
        //public string? ServerAddress { get; init; }
        public string? Password { get; init; }
        public int? Id { get; init; }
        public string? Company { get; init; }
        public string? CN { get; init; }
        public string? OrganizationalUnit { get; init; }
        public string? Locality { get; init; }
        public string? State { get; init; }
        public string? Country { get; init; }
        public string? Solution { get; init; }
        public string? Name { get; init; } // Human-friendly name for certificate organization
        public string? PFXCertificate { get; init; }
        public string? CRTCertificate { get; init; }
        public string? DERCertificate { get; init; }
        public DateTime Creation { get; init; } = DateTime.Now;
        public DateTimeOffset? ValidFromUtc { get; init; }
        public DateTimeOffset? ValidToUtc { get; init; }
        public string? RootThumbPrint { get; set; } = string.Empty;
        public string? Address { get; init; }
        public string? ApplicationUri { get; init; }
        public string[]? DNS { get; init; }
        public string[]? IpAddresses { get; init; }
        public string? Oid { get; init; }
        public string[]? KeyUsages { get; init; }
        public string? KeyAlgorithm { get; init; }
        public string? SignatureHashAlgorithm { get; init; }
    }

    public class CertificateComplete: Certificate
    {

        [JsonIgnore]
        public X509Certificate2? PFX { get; set; }
        [JsonIgnore]
        public X509Certificate2? CRT { get; set; }


        public void LoadCertificate()
        {
            if(CRTCertificate is not null)
                CRT = new X509Certificate2(CRTCertificate);

            if(PFXCertificate is not null)
                PFX = new X509Certificate2(PFXCertificate, Password);
        }
    }

    public class FileManagerCertificate : IDisposable
    {
        public string? _dbCertificates { get; init; }    
        DirectoryInfo? _dir { get; init; }
        Serilog.ILogger? _logger { get; init; }

        private ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();

        public ShaManager ShaManager => _shaManager;
        private ShaManager _shaManager { get; init; }
        public FileManagerCertificate(string jsonAddress, Serilog.ILogger? logger, ShaManager shamanager)
            : this([jsonAddress], logger, shamanager)
        {
        }

        public FileManagerCertificate(IEnumerable<string> jsonAddresses, Serilog.ILogger? logger, ShaManager shamanager)
        {
            _logger = logger;
            _shaManager = shamanager;

            var databasePaths = jsonAddresses
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            _dbCertificates = databasePaths.FirstOrDefault();
            _lastJSonMemory = new CertificateDB();

            if(!string.IsNullOrWhiteSpace(_dbCertificates))
            {
                var databaseDirectory = Path.GetDirectoryName(_dbCertificates);
                if(!string.IsNullOrWhiteSpace(databaseDirectory))
                {
                    Directory.CreateDirectory(databaseDirectory);
                }
            }

            foreach(var databasePath in databasePaths)
            {
                Load(databasePath);
            }
        }

        CertificateDB? _lastJSonMemory { get; set; }
        public CertificateDB? JSONMemory 
        { 
            get
            {
                _lock.EnterReadLock();
                try
                {
                    return _lastJSonMemory;
                }
                finally
                {
                    _lock.ExitReadLock();
                }
            } 
        }

        JsonSerializerOptions _options = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        public string HashFileBy(int id, CertificateTypes type)
        {
            var certs = RetrieveCertificates(id);

            if(certs is null)
            {
                return string.Empty;
            }

            if(File.Exists(certs[type]))
            {
                return _shaManager.HashFile(File.OpenRead(certs[type]));
            }

            return string.Empty;
        }

        public string HashFileBy(string solution, CertificateTypes type)
        {
            _lock.EnterReadLock();
            try
            {
                if(_lastJSonMemory?.GetIDBySolution(solution, out int? id) ?? false)
                {
                    return HashFileBy(id ?? -1, type);
                }
            }
            finally
            {
                _lock.ExitReadLock();
            }

            return string.Empty;
        }

        public Dictionary<CertificateTypes, string>? RetrieveCertificates(int id)
        {
            _lock.EnterReadLock();
            try
            {
                Dictionary<CertificateTypes, string> files = new Dictionary<CertificateTypes, string>();
                var dataFound = _lastJSonMemory?.CertificatesDB.Find(t => t.Id == id);

                if(dataFound is null)
                    return null;


                if(!string.IsNullOrEmpty(dataFound.PFXCertificate))
                {
                    files[CertificateTypes.PFX] = dataFound.PFXCertificate;
                }

                if(!string.IsNullOrEmpty(dataFound.CRTCertificate))
                {
                    files[CertificateTypes.CARootNoKey] = dataFound.CRTCertificate;
                }

                if(!string.IsNullOrEmpty(dataFound.DERCertificate))
                {
                    files[CertificateTypes.DER] = dataFound.DERCertificate;
                }

                return files;
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public void Load()
        {
            Load(_dbCertificates);
        }

        private void Load(string? databasePath)
        {
            if(string.IsNullOrWhiteSpace(databasePath) || !File.Exists(databasePath))
            {
                _logger?.Information("No db data to load");
                return;
            }

            _lock.EnterWriteLock();
            try
            {
                var jsonString = File.ReadAllText(databasePath);
                var loadedMemory = JsonSerializer.Deserialize<CertificateDB>(jsonString, _options);

                foreach(var cert in loadedMemory?.CertificatesDB ?? new List<Certificate>())
                {
                    if(cert is CertificateComplete certCom)
                    {
                        certCom.LoadCertificate();
                    }

                    AddLoadedCertificate(cert);
                }
            }
            catch(Exception ex)
            {
                _logger?.Warning($"Impossibile to load {databasePath} -> {ex.Message}");
            }
            finally
            {
                _lock.ExitWriteLock();
            }

        }

        private void AddLoadedCertificate(Certificate certificate)
        {
            if(_lastJSonMemory is null)
            {
                _lastJSonMemory = new CertificateDB();
            }

            var alreadyLoaded = _lastJSonMemory.CertificatesDB.Any(existing =>
                string.Equals(existing.Solution, certificate.Solution, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.Name, certificate.Name, StringComparison.OrdinalIgnoreCase));

            if(!alreadyLoaded)
            {
                if(_lastJSonMemory.CertificatesDB.Any(existing => existing.Id == certificate.Id))
                {
                    certificate = CloneCertificate(certificate, (_lastJSonMemory.MaxId ?? 0) + 1);
                }

                _lastJSonMemory.CertificatesDB.Add(certificate);
            }
        }

        private static Certificate CloneCertificate(Certificate source, int id)
        {
            return new CertificateComplete
            {
                CRTCertificate = source.CRTCertificate,
                PFXCertificate = source.PFXCertificate,
                DERCertificate = source.DERCertificate,
                CN = source.CN,
                Company = source.Company,
                OrganizationalUnit = source.OrganizationalUnit,
                Locality = source.Locality,
                State = source.State,
                Country = source.Country,
                Solution = source.Solution,
                Name = source.Name,
                Password = source.Password,
                Id = id,
                RootThumbPrint = source.RootThumbPrint,
                Address = source.Address,
                ApplicationUri = source.ApplicationUri,
                DNS = source.DNS,
                IpAddresses = source.IpAddresses,
                Oid = source.Oid,
                KeyUsages = source.KeyUsages,
                Creation = source.Creation,
                ValidFromUtc = source.ValidFromUtc,
                ValidToUtc = source.ValidToUtc,
                KeyAlgorithm = source.KeyAlgorithm,
                SignatureHashAlgorithm = source.SignatureHashAlgorithm
            };
        }

        public void Add(
            string pfxFile,
            string oid,
            string company,
            string commonName,
            string crtRoot,
            string? derFile,
            string solution,
            string? name,
            string password,
            string rootThumbprint,
            string? address,
            string? applicationUri,
            string[] dns,
            string[] ipAddresses,
            string? organizationalUnit,
            string? locality,
            string? state,
            string? country,
            DateTimeOffset validFromUtc,
            DateTimeOffset validToUtc,
            string[] keyUsages,
            string keyAlgorithm,
            string signatureHashAlgorithm)
        {
            _lock.EnterWriteLock();
            try
            {
                var crt = new CertificateComplete
                {
                    CRTCertificate = crtRoot,
                    PFXCertificate = pfxFile,
                    DERCertificate = derFile,
                    CN = commonName,
                    Company = company,
                    OrganizationalUnit = organizationalUnit,
                    Locality = locality,
                    State = state,
                    Country = country,
                    Solution = solution,
                    Name = name,
                    Password = password,
                    Id = (_lastJSonMemory?.MaxId ?? 0) + 1,
                    RootThumbPrint = rootThumbprint,
                    Address = address,
                    ApplicationUri = applicationUri,
                    DNS = dns,
                    IpAddresses = ipAddresses,
                    Oid = oid,
                    KeyUsages = keyUsages,
                    ValidFromUtc = validFromUtc,
                    ValidToUtc = validToUtc,
                    KeyAlgorithm = keyAlgorithm,
                    SignatureHashAlgorithm = signatureHashAlgorithm
                };

                crt.LoadCertificate();

                _lastJSonMemory?.Add(solution, crt);

                SaveInternal();
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        public void Save()
        {
            _lock.EnterWriteLock();
            try
            {
                SaveInternal();
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        private void SaveInternal()
        {
            if(string.IsNullOrEmpty(_dbCertificates))
            {
                return; 
            }

            var jsonString = JsonSerializer.Serialize(_lastJSonMemory, _options);
            File.WriteAllText(_dbCertificates, jsonString);
        }
        
        // RE-WRITING IMPLEMENTATION FOR `Add` and `Save` to handle locks correctly without recursion.
        // See below in logic.

        public void Dispose()
        {
             _lock?.Dispose();
        }
    }
}

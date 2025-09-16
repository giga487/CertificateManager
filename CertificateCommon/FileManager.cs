using CertificateCommon;
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
            var solution = CertificatesDB.Find(t => string.Compare(solutionName, t.Solution, true) == 0);

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
            var found = CertificatesDB.Find(t => string.Compare(t.Solution, solution, true) == 0);

            if(found != null)
            {
                CertificatesDB.Remove(found);
            }

            CertificatesDB.Add(cert);

        }

    }

    public class Certificate
    {
        //public string? ServerAddress { get; init; }
        public string? Password { get; init; }
        public int? Id { get; init; }
        //public string? Company { get; init; }
        //public string? CN { get; init; }
        public string? Solution { get; init; }
        public string? PFXCertificate { get; init; }
        public string? CRTCertificate { get; init; }
        public DateTime Creation { get; init; } = DateTime.Now;
        public string? RootThumbPrint { get; set; } = string.Empty;
        public string? Address { get; init; }
        public string[]? DNS { get; init; }
    }

    public class CertificateComplete: Certificate
    {

        [JsonIgnore]
        public X509Certificate2 PFX { get; set; }
        [JsonIgnore]
        public X509Certificate2 CRT { get; set; }


        public void LoadCertificate()
        {
            CRT = new X509Certificate2(CRTCertificate);
            PFX = new X509Certificate2(PFXCertificate, Password);
        }
    }

    public class FileManagerCertificate
    {
        public string? _dbCertificates { get; init; }    
        DirectoryInfo? _dir { get; init; }
        Serilog.ILogger? _logger { get; init; }

        public ShaManager ShaManager => _shaManager;
        private ShaManager _shaManager { get; init; }
        public FileManagerCertificate(string jsonAddress, Serilog.ILogger? logger, ShaManager shamanager)
        {
            _logger = logger;
            _shaManager = shamanager;

            _dbCertificates = jsonAddress;
            if(File.Exists(jsonAddress))
            {
                Load();
            }
            else
            {
                _lastJSonMemory = new CertificateDB();
            }
        }

        CertificateDB? _lastJSonMemory { get; set; }
        public CertificateDB? JSONMemory => _lastJSonMemory;

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
            if(_lastJSonMemory?.GetIDBySolution(solution, out int? id) ?? false)
            {
                return HashFileBy(id ?? -1, type);
            }

            return string.Empty;
        }

        public Dictionary<CertificateTypes, string>? RetrieveCertificates(int id)
        {
            Dictionary<CertificateTypes, string> files = new Dictionary<CertificateTypes, string>();
            var dataFound = _lastJSonMemory?.CertificatesDB.Find(t => t.Id == id);

            if(dataFound is null)
                return null;


            if(!string.IsNullOrEmpty(dataFound.PFXCertificate))
            {
                files[CertificateTypes.PFX] = dataFound.PFXCertificate;// System.IO.File.OpenRead(dataFound.PFXCertificate);
            }

            if(!string.IsNullOrEmpty(dataFound.CRTCertificate))
            {
                files[CertificateTypes.CARootNoKey] = dataFound.CRTCertificate; // System.IO.File.OpenRead(dataFound.CRTCertificate);
            }

            return files;
        }

        public void Load()
        {
            if(!File.Exists(_dbCertificates))
            {
                _logger?.Information("No db data to load");
                return;
            }

            try
            {
                var jsonString = File.ReadAllText(_dbCertificates);
                _lastJSonMemory = JsonSerializer.Deserialize<CertificateDB>(jsonString, _options);

                foreach(var cert in _lastJSonMemory?.CertificatesDB ?? new List<Certificate>())
                {
                    if(cert is CertificateComplete certCom)
                    {
                        certCom.LoadCertificate();
                    }

                }
            }
            catch(Exception ex)
            {
                _logger?.Warning($"Impossibile to load {_dbCertificates} -> {ex.Message}");
            }

        }

        public void Add(string pfxFile, string crtRoot, string solution, string password, string rootThumbprint, string address, string[] dns)
        {

            CertificateComplete crt = new CertificateComplete()
            {
                CRTCertificate = crtRoot,
                PFXCertificate = pfxFile,
                Solution = solution,
                Password = password,
                Id = _lastJSonMemory?.MaxId + 1,
                RootThumbPrint = rootThumbprint,
                Address = address,
                DNS = dns
            };

            crt.LoadCertificate();

            _lastJSonMemory?.Add(solution, crt);

            Save();
        }

        public void Save()
        {
            if(string.IsNullOrEmpty(_dbCertificates))
            {
                return; 
            }

            var jsonString = JsonSerializer.Serialize(_lastJSonMemory, _options);
            File.WriteAllText(_dbCertificates, jsonString);
        }

    }
}

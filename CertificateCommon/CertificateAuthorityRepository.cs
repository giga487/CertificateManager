using CertificateManager.src;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace CertificateCommon
{
    public enum CertificateAuthorityRole
    {
        Root = 0,
        Intermediate = 1
    }

    public sealed class CertificateAuthorityOptions
    {
        public string? DefaultIssuerId { get; init; }
        public string? DefaultRootId { get; init; }
        public string? IntermediateDirectory { get; init; }
        public CertificateAuthorityDefinition[] Authorities { get; init; } = [];
    }

    public sealed class CertificateAuthorityDefinition
    {
        public string? Id { get; init; }
        public string? Name { get; init; }
        public string? ParentId { get; init; }
        public CertificateAuthorityRole Role { get; init; } = CertificateAuthorityRole.Intermediate;
        public bool IsDefault { get; init; }
        public bool Enabled { get; init; } = true;
        public string? PfxPath { get; init; }
        public string? PfxPassword { get; init; }
        public string? Thumbprint { get; init; }
        public string? StoreName { get; init; }
        public string? StoreLocation { get; init; }
    }

    public sealed class CertificateAuthorityEntry
    {
        public required string Id { get; init; }
        public required string Name { get; init; }
        public string? ParentId { get; init; }
        public CertificateAuthorityRole Role { get; init; }
        public bool IsDefault { get; init; }
        public bool Enabled { get; init; } = true;
        public required X509Certificate2 Certificate { get; init; }
        public string? Source { get; init; }
    }

    public interface ICertificateAuthorityRepository
    {
        IReadOnlyList<CertificateAuthorityEntry> GetAuthorities();
        CertificateAuthorityEntry? GetDefaultIssuer();
        CertificateAuthorityEntry? GetDefaultRoot();
        CertificateAuthorityEntry? GetById(string? id);
        CertificateAuthorityEntry? GetIssuer(string? id);
        CertificateAuthorityEntry? GetRootFor(CertificateAuthorityEntry issuer);
        void AddIntermediate(X509Certificate2 certificate, string? source, string? parentId = null, string? name = null, bool isDefault = true);
        string? SaveIntermediate(X509Certificate2 certificate, string? parentId = null, string? name = null, string? pfxPassword = null);
    }

    public sealed class CertificateAuthorityRepository : ICertificateAuthorityRepository
    {
        private sealed class IntermediateAuthorityManifest
        {
            public List<IntermediateAuthorityDefinition> Authorities { get; set; } = [];
        }

        private sealed class IntermediateAuthorityDefinition
        {
            public string? Id { get; set; }
            public string? Name { get; set; }
            public string? ParentId { get; set; }
            public string? PfxPath { get; set; }
            public string? PfxPassword { get; set; }
            public bool IsDefault { get; set; } = true;
        }

        private readonly IReadOnlyList<CertificateAuthorityEntry> _configuredAuthorities;
        private readonly Dictionary<string, CertificateAuthorityEntry> _runtimeIntermediates = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _sync = new();
        private readonly Serilog.ILogger? _logger;
        private readonly string? _intermediateDirectory;
        private readonly string? _defaultIssuerId;
        private readonly string? _defaultRootId;
        private readonly string _basePath;
        private const X509KeyStorageFlags PfxKeyStorageFlags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;
        private const string IntermediateManifestFileName = "IntermediateAuthorities.json";
        private static readonly JsonSerializerOptions ManifestJsonOptions = new() { WriteIndented = true };

        public CertificateAuthorityRepository(IConfiguration configuration, Serilog.ILogger? logger, string? basePath = null)
        {
            var section = configuration.GetSection("CertificateAuthorities");
            var options = section.Exists()
                ? MergeWithLegacyOptions(section.Get<CertificateAuthorityOptions>() ?? new CertificateAuthorityOptions(), configuration)
                : BuildLegacyOptions(configuration);

            _defaultIssuerId = options.DefaultIssuerId;
            _defaultRootId = options.DefaultRootId;
            _basePath = string.IsNullOrWhiteSpace(basePath) ? Directory.GetCurrentDirectory() : basePath;
            _intermediateDirectory = ResolvePath(options.IntermediateDirectory);
            _logger = logger;
            _logger?.Information("Certificate authority base path: {BasePath}", _basePath);
            if(!string.IsNullOrWhiteSpace(options.IntermediateDirectory))
            {
                _logger?.Information(
                    "Certificate authority intermediate directory configured as {ConfiguredPath}, resolved to {ResolvedPath}. Exists={Exists}",
                    options.IntermediateDirectory,
                    _intermediateDirectory,
                    Directory.Exists(_intermediateDirectory));
            }
            _configuredAuthorities = LoadAuthorities(options, logger, _basePath);
            RefreshIntermediateDirectory();
        }

        public CertificateAuthorityRepository(IEnumerable<CertificateAuthorityEntry> authorities, string? defaultIssuerId = null, string? defaultRootId = null)
        {
            _configuredAuthorities = authorities.Where(authority => authority.Enabled).ToArray();
            _defaultIssuerId = defaultIssuerId;
            _defaultRootId = defaultRootId;
            _basePath = Directory.GetCurrentDirectory();
        }

        public IReadOnlyList<CertificateAuthorityEntry> GetAuthorities()
        {
            RefreshIntermediateDirectory();
            lock(_sync)
            {
                return _configuredAuthorities
                    .Concat(_runtimeIntermediates.Values)
                    .GroupBy(authority => NormalizeThumbprint(authority.Certificate.Thumbprint), StringComparer.OrdinalIgnoreCase)
                    .Select(group => group.First())
                    .ToArray();
            }
        }

        public CertificateAuthorityEntry? GetDefaultIssuer()
        {
            var authorities = GetAuthorities();
            return GetById(_defaultIssuerId)
                ?? authorities.FirstOrDefault(authority => authority.IsDefault && authority.Role == CertificateAuthorityRole.Intermediate && authority.Certificate.HasPrivateKey)
                ?? authorities.FirstOrDefault(authority => authority.IsDefault && authority.Certificate.HasPrivateKey)
                ?? authorities.FirstOrDefault(authority => authority.Role == CertificateAuthorityRole.Intermediate && authority.Certificate.HasPrivateKey)
                ?? authorities.FirstOrDefault(authority => authority.Certificate.HasPrivateKey);
        }

        public CertificateAuthorityEntry? GetDefaultRoot()
        {
            var authorities = GetAuthorities();
            return GetById(_defaultRootId)
                ?? authorities.FirstOrDefault(authority => authority.Role == CertificateAuthorityRole.Root)
                ?? GetDefaultIssuer();
        }

        public CertificateAuthorityEntry? GetById(string? id)
        {
            if(string.IsNullOrWhiteSpace(id))
            {
                return null;
            }

            return GetAuthorities().FirstOrDefault(authority =>
                string.Equals(authority.Id, id, StringComparison.OrdinalIgnoreCase)
                || string.Equals(NormalizeThumbprint(authority.Certificate.Thumbprint), NormalizeThumbprint(id), StringComparison.OrdinalIgnoreCase));
        }

        public CertificateAuthorityEntry? GetIssuer(string? id)
        {
            var issuer = GetById(id) ?? GetDefaultIssuer();

            if(issuer is null || !issuer.Certificate.HasPrivateKey)
            {
                return null;
            }

            return issuer;
        }

        public CertificateAuthorityEntry? GetRootFor(CertificateAuthorityEntry issuer)
        {
            var current = issuer;
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while(!string.IsNullOrWhiteSpace(current.ParentId) && visited.Add(current.Id))
            {
                var parent = GetById(current.ParentId);
                if(parent is null)
                {
                    break;
                }

                current = parent;
            }

            return current.Role == CertificateAuthorityRole.Root ? current : GetDefaultRoot();
        }

        public void AddIntermediate(X509Certificate2 certificate, string? source, string? parentId = null, string? name = null, bool isDefault = true)
        {
            var id = NormalizeThumbprint(certificate.Thumbprint);
            if(string.IsNullOrWhiteSpace(id))
            {
                return;
            }

            var entry = new CertificateAuthorityEntry
            {
                Id = id,
                Name = string.IsNullOrWhiteSpace(name) ? certificate.GetNameInfo(X509NameType.SimpleName, false) : name,
                ParentId = parentId,
                Role = CertificateAuthorityRole.Intermediate,
                IsDefault = isDefault,
                Certificate = certificate,
                Source = source
            };

            lock(_sync)
            {
                _runtimeIntermediates[id] = entry;
            }
        }

        public string? SaveIntermediate(X509Certificate2 certificate, string? parentId = null, string? name = null, string? pfxPassword = null)
        {
            if(string.IsNullOrWhiteSpace(_intermediateDirectory))
            {
                AddIntermediate(certificate, null, parentId, name);
                return null;
            }

            Directory.CreateDirectory(_intermediateDirectory);
            var id = NormalizeThumbprint(certificate.Thumbprint);
            var fileName = $"{SanitizeFileName(string.IsNullOrWhiteSpace(name) ? id : name)}-{id}.pfx";
            var path = Path.GetFullPath(Path.Combine(_intermediateDirectory, fileName));
            _logger?.Information("Saving trusted intermediate authority to {Path}.", path);
            File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, pfxPassword) ?? []);

            _logger?.Information("Reloading trusted intermediate authority from {Path}.", path);
            var persistedCertificate = new X509Certificate2(
                path,
                pfxPassword,
                PfxKeyStorageFlags);

            AddIntermediate(persistedCertificate, path, parentId, name);
            UpsertIntermediateManifest(new IntermediateAuthorityDefinition
            {
                Id = id,
                Name = string.IsNullOrWhiteSpace(name) ? certificate.GetNameInfo(X509NameType.SimpleName, false) : name,
                ParentId = parentId,
                PfxPath = path,
                PfxPassword = pfxPassword,
                IsDefault = true
            });

            return path;
        }

        private void RefreshIntermediateDirectory()
        {
            if(string.IsNullOrWhiteSpace(_intermediateDirectory) || !Directory.Exists(_intermediateDirectory))
            {
                return;
            }

            foreach(var definition in LoadIntermediateManifest().Authorities)
            {
                if(string.IsNullOrWhiteSpace(definition.PfxPath))
                {
                    continue;
                }

                var normalizedPath = ResolvePath(definition.PfxPath, _intermediateDirectory) ?? definition.PfxPath;
                lock(_sync)
                {
                    if(_runtimeIntermediates.Values.Any(authority => string.Equals(authority.Source, normalizedPath, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }
                }

                try
                {
                    _logger?.Information("Loading trusted intermediate authority from manifest. Path={Path}, Exists={Exists}", normalizedPath, File.Exists(normalizedPath));
                    var certificate = LoadPfx(normalizedPath, definition.PfxPassword);

                    if(!certificate.HasPrivateKey)
                    {
                        _logger?.Warning("Intermediate authority {Path} ignored because it has no private key.", normalizedPath);
                        continue;
                    }

                    AddIntermediate(
                        certificate,
                        normalizedPath,
                        string.IsNullOrWhiteSpace(definition.ParentId) ? GetConfiguredDefaultRoot()?.Id : definition.ParentId,
                        string.IsNullOrWhiteSpace(definition.Name) ? Path.GetFileNameWithoutExtension(normalizedPath) : definition.Name,
                        definition.IsDefault);
                }
                catch(Exception ex)
                {
                    _logger?.Warning("Error loading trusted intermediate {Path}: {Message}", normalizedPath, ex.Message);
                }
            }
        }

        private static IReadOnlyList<CertificateAuthorityEntry> LoadAuthorities(CertificateAuthorityOptions options, Serilog.ILogger? logger, string basePath)
        {
            var authorities = new List<CertificateAuthorityEntry>();

            foreach(var definition in options.Authorities.Where(definition => definition.Enabled))
            {
                try
                {
                    var certificate = LoadCertificate(definition, basePath, logger);
                    if(certificate is null)
                    {
                        logger?.Warning("Certificate authority {Id} could not be loaded.", definition.Id ?? definition.Name);
                        continue;
                    }

                    authorities.Add(new CertificateAuthorityEntry
                    {
                        Id = string.IsNullOrWhiteSpace(definition.Id) ? NormalizeThumbprint(certificate.Thumbprint) : definition.Id.Trim(),
                        Name = string.IsNullOrWhiteSpace(definition.Name) ? certificate.GetNameInfo(X509NameType.SimpleName, false) : definition.Name.Trim(),
                        ParentId = definition.ParentId,
                        Role = definition.Role,
                        IsDefault = definition.IsDefault,
                        Enabled = definition.Enabled,
                        Certificate = certificate,
                        Source = GetSource(definition)
                    });
                }
                catch(Exception ex)
                {
                    logger?.Warning("Error loading certificate authority {Id}: {Message}", definition.Id ?? definition.Name, ex.Message);
                }
            }

            return authorities;
        }

        private CertificateAuthorityEntry? GetConfiguredDefaultRoot()
        {
            return _configuredAuthorities.FirstOrDefault(authority => string.Equals(authority.Id, _defaultRootId, StringComparison.OrdinalIgnoreCase))
                ?? _configuredAuthorities.FirstOrDefault(authority => authority.Role == CertificateAuthorityRole.Root);
        }

        private static X509Certificate2? LoadCertificate(CertificateAuthorityDefinition definition, string basePath, Serilog.ILogger? logger)
        {
            if(!string.IsNullOrWhiteSpace(definition.PfxPath))
            {
                var resolvedPath = ResolvePath(definition.PfxPath, basePath)!;
                logger?.Information(
                    "Loading certificate authority {Id} from PFX. ConfiguredPath={ConfiguredPath}, ResolvedPath={ResolvedPath}, Exists={Exists}",
                    definition.Id ?? definition.Name,
                    definition.PfxPath,
                    resolvedPath,
                    File.Exists(resolvedPath));

                return LoadPfx(resolvedPath, definition.PfxPassword);
            }

            if(!string.IsNullOrWhiteSpace(definition.Thumbprint))
            {
                var storeName = ParseEnumOrDefault(definition.StoreName, StoreName.My);
                var storeLocation = ParseEnumOrDefault(definition.StoreLocation, StoreLocation.CurrentUser);
                logger?.Information(
                    "Loading certificate authority {Id} from certificate store {StoreLocation}/{StoreName} using thumbprint {Thumbprint}.",
                    definition.Id ?? definition.Name,
                    storeLocation,
                    storeName,
                    definition.Thumbprint);
                using var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                var normalizedThumbprint = NormalizeThumbprint(definition.Thumbprint);
                var found = store.Certificates
                    .Find(X509FindType.FindByThumbprint, normalizedThumbprint, validOnly: false)
                    .Cast<X509Certificate2>()
                    .FirstOrDefault(certificate => string.Equals(NormalizeThumbprint(certificate.Thumbprint), normalizedThumbprint, StringComparison.OrdinalIgnoreCase));

                return found;
            }

            return null;
        }

        private static X509Certificate2 LoadPfx(string path, string? password)
        {
            var passwords = new[] { password, string.Empty, null }
                .Distinct()
                .ToArray();

            Exception? lastException = null;
            foreach(var candidatePassword in passwords)
            {
                try
                {
                    return new X509Certificate2(
                        path,
                        candidatePassword,
                        PfxKeyStorageFlags);
                }
                catch(Exception ex)
                {
                    lastException = ex;
                }
            }

            throw lastException ?? new InvalidOperationException($"Unable to load PFX '{path}'.");
        }

        private static CertificateAuthorityOptions BuildLegacyOptions(IConfiguration configuration)
        {
            var section = configuration.GetSection("CertificationManager");
            var thumbprint = section.GetSection("CARootThumbPrint").Value;
            var stores = section.GetSection("CARootStores")
                .GetChildren()
                .Select(store => new CertificateAuthorityDefinition
                {
                    Id = "legacy-root",
                    Name = "Legacy CA Root",
                    Role = CertificateAuthorityRole.Root,
                    IsDefault = true,
                    Thumbprint = thumbprint,
                    StoreName = store.GetSection("StoreName").Value,
                    StoreLocation = store.GetSection("StoreLocation").Value
                })
                .ToArray();

            if(stores.Length == 0)
            {
                stores =
                [
                    new CertificateAuthorityDefinition
                    {
                        Id = "legacy-root",
                        Name = "Legacy CA Root",
                        Role = CertificateAuthorityRole.Root,
                        IsDefault = true,
                        Thumbprint = thumbprint,
                        StoreName = section.GetSection("CARootStoreName").Value,
                        StoreLocation = section.GetSection("CARootStoreLocation").Value
                    }
                ];
            }

            return new CertificateAuthorityOptions
            {
                DefaultIssuerId = "legacy-root",
                DefaultRootId = "legacy-root",
                Authorities = stores
            };
        }

        private static CertificateAuthorityOptions MergeWithLegacyOptions(CertificateAuthorityOptions options, IConfiguration configuration)
        {
            var legacyOptions = BuildLegacyOptions(configuration);
            var configuredAuthorities = options.Authorities.Length > 0
                ? options.Authorities
                : legacyOptions.Authorities;

            return new CertificateAuthorityOptions
            {
                DefaultIssuerId = string.IsNullOrWhiteSpace(options.DefaultIssuerId) ? legacyOptions.DefaultIssuerId : options.DefaultIssuerId,
                DefaultRootId = string.IsNullOrWhiteSpace(options.DefaultRootId) ? legacyOptions.DefaultRootId : options.DefaultRootId,
                IntermediateDirectory = options.IntermediateDirectory,
                Authorities = configuredAuthorities
            };
        }

        private static string? GetSource(CertificateAuthorityDefinition definition)
        {
            if(!string.IsNullOrWhiteSpace(definition.PfxPath))
            {
                return definition.PfxPath;
            }

            if(!string.IsNullOrWhiteSpace(definition.Thumbprint))
            {
                return $"{definition.StoreLocation ?? StoreLocation.CurrentUser.ToString()}/{definition.StoreName ?? StoreName.My.ToString()}";
            }

            return null;
        }

        private static TEnum ParseEnumOrDefault<TEnum>(string? value, TEnum defaultValue)
            where TEnum : struct
        {
            return Enum.TryParse<TEnum>(value, ignoreCase: true, out var parsed)
                ? parsed
                : defaultValue;
        }

        private static string NormalizeThumbprint(string? thumbprint)
        {
            return string.IsNullOrWhiteSpace(thumbprint)
                ? string.Empty
                : new string(thumbprint.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        }

        private static string SanitizeFileName(string? value)
        {
            var fallback = string.IsNullOrWhiteSpace(value) ? "intermediate" : value.Trim();
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitized = new string(fallback.Select(character => invalidChars.Contains(character) ? '-' : character).ToArray());
            return string.IsNullOrWhiteSpace(sanitized) ? "intermediate" : sanitized;
        }

        private string? ResolvePath(string? path)
        {
            return ResolvePath(path, _basePath);
        }

        private static string? ResolvePath(string? path, string basePath)
        {
            if(string.IsNullOrWhiteSpace(path))
            {
                return path;
            }

            return Path.IsPathRooted(path)
                ? Path.GetFullPath(path)
                : Path.GetFullPath(path, basePath);
        }

        private string GetIntermediateManifestPath()
        {
            return Path.Combine(_intermediateDirectory!, IntermediateManifestFileName);
        }

        private IntermediateAuthorityManifest LoadIntermediateManifest()
        {
            if(string.IsNullOrWhiteSpace(_intermediateDirectory))
            {
                return new IntermediateAuthorityManifest();
            }

            var manifestPath = GetIntermediateManifestPath();
            if(!File.Exists(manifestPath))
            {
                return new IntermediateAuthorityManifest();
            }

            try
            {
                var json = File.ReadAllText(manifestPath);
                return JsonSerializer.Deserialize<IntermediateAuthorityManifest>(json, ManifestJsonOptions)
                    ?? new IntermediateAuthorityManifest();
            }
            catch(Exception ex)
            {
                _logger?.Warning("Error loading intermediate authority manifest {Path}: {Message}", manifestPath, ex.Message);
                return new IntermediateAuthorityManifest();
            }
        }

        private void SaveIntermediateManifest(IntermediateAuthorityManifest manifest)
        {
            Directory.CreateDirectory(_intermediateDirectory!);
            var manifestPath = GetIntermediateManifestPath();
            File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, ManifestJsonOptions));
        }

        private void UpsertIntermediateManifest(IntermediateAuthorityDefinition definition)
        {
            var manifest = LoadIntermediateManifest();
            manifest.Authorities.RemoveAll(authority =>
                string.Equals(authority.Id, definition.Id, StringComparison.OrdinalIgnoreCase)
                || string.Equals(ResolvePath(authority.PfxPath, _intermediateDirectory!), definition.PfxPath, StringComparison.OrdinalIgnoreCase));
            manifest.Authorities.Add(definition);
            SaveIntermediateManifest(manifest);
        }
    }
}

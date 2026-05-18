using CertificateManager.src;
using CertificateCommon;
using Microsoft.AspNetCore.Mvc;

namespace Certification.Backend.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class CertificateController : ControllerBase
	{
		private CertificateCommon.CertificationManager CertificationManager { get; init; }
		private Serilog.ILogger? Logger { get; init; }

		public CertificateController(CertificateCommon.CertificationManager certificationManager, Serilog.ILogger? logger)
		{
			CertificationManager = certificationManager;
			Logger = logger;
		}

		[HttpGet("Sha")]
		public IActionResult GetSHA(string solutionName, CertificateTypes type)
		{
			try
			{
				string value = CertificationManager.FileManager?.HashFileBy(solutionName, type) ?? "";
				return Ok(value);
			}
			catch(Exception ex)
			{
				Logger?.Warning($"Error making certificate: {ex.Message}");
				return BadRequest(ex.Message);
			}
		}

		[HttpGet("Get")]
		public IActionResult GetCertificate(int id)
		{
			if(CertificationManager.FileManager?.JSONMemory?.Get(id, out var certificate) ?? false)
			{
				return Ok(certificate);
			}

			return BadRequest($"No certificate with ID: {id}");
		}

		[HttpPost("CeritificationInfo")]
		public async Task<IActionResult> LoadCertificate([FromForm] IFormFile file)
		{
			return Ok(await CertificationManager.GetCertInfoWithPassword(file, null, ""));
		}

		[HttpPost("CeritificationInfoWithKey")]
		public async Task<IActionResult> LoadCertificateWithKey([FromForm] IFormFile file, [FromForm] IFormFile? key = null)
		{
			return Ok(await CertificationManager.GetCertInfoWithPassword(file, key, ""));
		}

		[HttpPost("CeritificationInfoWithSecuredKey")]
		public async Task<IActionResult> LoadCertificateWithKey([FromForm] IFormFile file, [FromForm] IFormFile? key, string password)
		{
			return Ok(await CertificationManager.GetCertInfoWithPassword(file, key, password));
		}

		[HttpPost("MakeCertificate")]
		public IActionResult MakeCertificate([FromBody] CertificateGenerationRequest certificate)
		{
			try
			{
				var result = CertificationManager.CreatingPFX_CRT(certificate);
				return Ok(result);
			}
			catch(Exception ex)
			{
				Logger?.Warning($"Error making certificate with dns: {ex.Message}");
				return BadRequest(ex.Message);
			}
		}

		[HttpPost("MakeIntermediateCertificate")]
		public IActionResult MakeIntermediateCertificate([FromBody] CertificateGenerationRequest certificate)
		{
			try
			{
				var request = new CertificateGenerationRequest
				{
					Solution = certificate.Solution,
					Name = certificate.Name,
					CommonName = certificate.CommonName,
					Organization = certificate.Organization,
					OrganizationalUnit = certificate.OrganizationalUnit,
					Locality = certificate.Locality,
					State = certificate.State,
					Country = certificate.Country,
					PfxPassword = certificate.PfxPassword,
					ApplicationUri = certificate.ApplicationUri,
					DnsNames = [],
					IpAddresses = [],
					KeyUsages = ["KeyCertSign", "CrlSign"],
					EnhancedKeyUsages = [],
					ValidFromUtc = certificate.ValidFromUtc,
					ValidToUtc = certificate.ValidToUtc,
					IssuerAuthorityId = certificate.IssuerAuthorityId,
					KeyAlgorithm = certificate.KeyAlgorithm,
					SignatureHashAlgorithm = certificate.SignatureHashAlgorithm,
					ExportPrivateKeyPem = certificate.ExportPrivateKeyPem
				};
				var result = CertificationManager.CreatingPFX_CRT(request, "IntermediateCA.pfx", "IntermediateCA.crt", isCertificateAuthority: true);
				return Ok(result);
			}
			catch(Exception ex)
			{
				Logger?.Warning($"Error making intermediate certificate: {ex.Message}");
				return BadRequest(ex.Message);
			}
		}

		[HttpGet("ID")]
		public IActionResult IDBySolution(string solution)
		{
			if(CertificationManager.FileManager?.JSONMemory?.GetIDBySolution(solution, out int? id) ?? false)
			{
				return Ok(id);
			}

			return Ok(-1);
		}

		[HttpGet("Info")]
		public IActionResult Info()
		{
			return Ok(CertificationManager.FileManager?.JSONMemory);
		}

		[HttpDelete("{id:int}")]
		public IActionResult Delete(int id)
		{
			if(CertificationManager.FileManager is null)
			{
				return Problem("Certificate file manager is not available.");
			}

			if(!CertificationManager.FileManager.Delete(id, out var deletedFiles, out var failedFiles))
			{
				return NotFound($"No certificate with ID: {id}");
			}

			if(failedFiles.Count > 0)
			{
				Logger?.Warning("Deleted certificate {CertificateId}, but failed to delete files: {FailedFiles}", id, failedFiles);
			}

			return Ok(new
			{
				Id = id,
				DeletedFiles = deletedFiles,
				FailedFiles = failedFiles
			});
		}

		[HttpGet("CARootInfo")]
		public IActionResult CARootInfo(string? authorityId = null)
		{
			try
			{
				return Ok(string.IsNullOrWhiteSpace(authorityId)
					? CertificationManager.GetCertificateAuthorityInfo()
					: CertificationManager.GetCertificateAuthorityInfo(authorityId));
			}
			catch(CARootNotFoundException ex)
			{
				Logger?.Warning($"CA root info unavailable: {ex.Message}");
				return NotFound(ex.Message);
			}
		}

		[HttpGet("CARoots")]
		public IActionResult CARoots()
		{
			return Ok(CertificationManager.GetCertificateAuthoritiesInfo());
		}

		[HttpGet("downloadCARoot")]
		public IActionResult DownloadCARoot(string? authorityId = null)
		{
			var authority = string.IsNullOrWhiteSpace(authorityId)
				? CertificationManager.CertificateAuthorities.GetDefaultRoot() ?? CertificationManager.CertificateAuthorities.GetDefaultIssuer()
				: CertificationManager.CertificateAuthorities.GetById(authorityId);

			var certificate = authority?.Certificate ?? CertificationManager.CARoot;
			if(certificate is null)
			{
				return NotFound("No CA Root configured");
			}

			var data = System.Text.Encoding.UTF8.GetBytes(certificate.ExportCertificatePem());
			var fileName = string.IsNullOrWhiteSpace(authority?.Name)
				? "CA-Root.crt"
				: $"{authority.Name}.crt";
			return File(data, "application/octet-stream", fileName);
		}

		[HttpPost("CreatePFXFromCRT")]
		public async Task<IActionResult> CreatePFX([FromForm] IFormFile crtFile, [FromForm] IFormFile key, [FromForm] string? password, [FromForm] string pfxPassword)
		{
			try
			{
				byte[] certificateData = await CertificationManager.CreatePFX(crtFile, key, password, pfxPassword) ?? [];

				if(certificateData.Length == 0)
				{
					return BadRequest("Failed to generate PFX. The result was empty. Check if the private key matches the certificate.");
				}

				return File(certificateData, "application/x-pkcs12", "Certificate.pfx");
			}
			catch(Exception ex)
			{
				Logger?.Warning($"Error creating PFX from CRT: {ex.Message}");
				return BadRequest($"Error creating PFX: {ex.Message}");
			}
		}

		[HttpGet("downloadPFX")]
		public IActionResult DownloadFilePFX(int id, bool includeIntermediates = true, bool includeRoot = false)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null || !result.TryGetValue(CertificateTypes.PFX, out var filePath))
			{
				return NotFound($"No PFX certificate with ID: {id}");
			}

			if((includeIntermediates || includeRoot)
				&& CertificationManager.FileManager?.JSONMemory?.Get(id, out var certificate) == true
				&& certificate is not null)
			{
				try
				{
					var pfxBytes = BuildPfxWithChain(filePath, certificate, result, includeIntermediates, includeRoot);
					return File(pfxBytes, "application/x-pkcs12", "Certificate-with-chain.pfx");
				}
				catch(Exception ex)
				{
					Logger?.Warning($"Error creating PFX with chain for certificate ID {id}: {ex}");
					return BadRequest($"Error creating PFX with chain: {ex.Message}");
				}
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);

			string sha = CertificationManager.FileManager!.ShaManager.HashFile(file);
			file.Position = 0;
			Logger?.Warning($"Sha {filePath}: {sha}");

			return File(file, "application/x-pkcs12", "Certificate.pfx");
		}

		[HttpGet("downloadCRT")]
		public IActionResult DownloadFileRootCRT(int id)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null || !result.TryGetValue(CertificateTypes.CARootNoKey, out var filePath))
			{
				return NotFound($"No root CRT certificate with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);

			string sha = CertificationManager.FileManager!.ShaManager.HashFile(file);
			file.Position = 0;
			Logger?.Warning($"Sha {filePath}: {sha}");

			return File(file, "application/x-x509-ca-cert", "Root.crt");
		}

		[HttpGet("downloadRootDER")]
		public IActionResult DownloadFileRootDER(int id)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null || !result.TryGetValue(CertificateTypes.CARootDER, out var filePath))
			{
				return NotFound($"No root DER certificate with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);

			string sha = CertificationManager.FileManager!.ShaManager.HashFile(file);
			file.Position = 0;
			Logger?.Warning($"Sha {filePath}: {sha}");

			return File(file, "application/pkix-cert", "Root.der");
		}

		[HttpGet("downloadIntermediateCRT")]
		public IActionResult DownloadFileIntermediateCRT(int id)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null || !result.TryGetValue(CertificateTypes.IntermediateNoKey, out var filePath))
			{
				return NotFound($"No intermediate certificate with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
			return File(file, "application/x-x509-ca-cert", "Intermediate.crt");
		}

		[HttpGet("downloadCertificatePEM")]
		public IActionResult DownloadCertificatePEM(int id, bool includeIntermediates = false, bool includeRoot = false)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null)
			{
				return NotFound($"No certificate with ID: {id}");
			}

			if(includeIntermediates || includeRoot)
			{
				var chainPem = BuildPemChain(result, includeLeaf: true, includeIntermediates, includeRoot);
				if(string.IsNullOrWhiteSpace(chainPem))
				{
					return NotFound($"No certificate PEM with ID: {id}");
				}

				return File(System.Text.Encoding.UTF8.GetBytes(chainPem), "application/x-pem-file", "Certificate-with-chain.crt");
			}

			if(!result.TryGetValue(CertificateTypes.CRT, out var filePath))
			{
				filePath = ResolveRelatedPath(result, "Certificate.crt");
			}

			if(string.IsNullOrWhiteSpace(filePath) || !System.IO.File.Exists(filePath))
			{
				return NotFound($"No certificate PEM with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
			return File(file, "application/x-pem-file", "Certificate.crt");
		}

		[HttpGet("downloadChainCRT")]
		public IActionResult DownloadFileChainCRT(int id, bool includeLeaf = true, bool includeIntermediates = true, bool includeRoot = false)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null)
			{
				return NotFound($"No certificate with ID: {id}");
			}

			var chainPem = BuildPemChain(result, includeLeaf, includeIntermediates, includeRoot);
			if(string.IsNullOrWhiteSpace(chainPem))
			{
				return NotFound($"No certificate chain material with ID: {id}");
			}

			return File(System.Text.Encoding.UTF8.GetBytes(chainPem), "application/x-x509-ca-cert", "Certificate-chain.crt");
		}

		[HttpGet("downloadPrivateKeyPEM")]
		public IActionResult DownloadPrivateKeyPEM(int id)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null)
			{
				return NotFound($"No certificate with ID: {id}");
			}

			if(!result.TryGetValue(CertificateTypes.PrivateKeyPem, out var filePath))
			{
				filePath = ResolveRelatedPath(result, "private.key");
			}

			if(string.IsNullOrWhiteSpace(filePath) || !System.IO.File.Exists(filePath))
			{
				return NotFound($"No private key PEM with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);
			return File(file, "application/x-pem-file", "private.key");
		}

		[HttpGet("downloadDER")]
		public IActionResult DownloadFileCertificateDER(int id)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null || !result.TryGetValue(CertificateTypes.DER, out var filePath))
			{
				return NotFound($"No DER certificate with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);

			string sha = CertificationManager.FileManager!.ShaManager.HashFile(file);
			file.Position = 0;
			Logger?.Warning($"Sha {filePath}: {sha}");

			return File(file, "application/pkix-cert", "Certificate.der");
		}

		private static string? ResolveRelatedPath(Dictionary<CertificateTypes, string> certificateFiles, string fileName)
		{
			var relatedPath = certificateFiles.Values.FirstOrDefault(path => !string.IsNullOrWhiteSpace(path));
			var directory = string.IsNullOrWhiteSpace(relatedPath)
				? null
				: Path.GetDirectoryName(relatedPath);

			return string.IsNullOrWhiteSpace(directory)
				? null
				: Path.Combine(directory, fileName);
		}

		private static byte[] BuildPfxWithChain(
			string pfxPath,
			Certificate certificate,
			Dictionary<CertificateTypes, string> certificateFiles,
			bool includeIntermediates,
			bool includeRoot)
		{
			var password = certificate.Password ?? string.Empty;
			var flags = System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
				| System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.EphemeralKeySet;

			var collection = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection
			{
				LoadLeafCertificateWithPrivateKey(pfxPath, password, flags, certificateFiles)
			};

			if(includeIntermediates)
			{
				AddCertificateFromFile(collection, certificateFiles, CertificateTypes.IntermediateNoKey);
			}

			if(includeRoot)
			{
				AddCertificateFromFile(collection, certificateFiles, CertificateTypes.CARootNoKey);
			}

			try
			{
				return collection.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, password) ?? [];
			}
			catch(Exception ex)
			{
				throw new InvalidOperationException($"Unable to export PFX with chain from '{pfxPath}'.", ex);
			}
		}

		private static System.Security.Cryptography.X509Certificates.X509Certificate2Collection LoadPfxCollection(
			string pfxPath,
			string password,
			System.Security.Cryptography.X509Certificates.X509KeyStorageFlags flags)
		{
			var collection = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();

			try
			{
				collection.Import(pfxPath, password, flags);
			}
			catch(Exception importException)
			{
				try
				{
					collection.Add(new System.Security.Cryptography.X509Certificates.X509Certificate2(pfxPath, password, flags));
				}
				catch(Exception loadException)
				{
					throw new InvalidOperationException($"Unable to load PFX '{pfxPath}'. Check that the file exists and the stored password is correct.", loadException);
				}

				if(collection.Count == 0)
				{
					throw new InvalidOperationException($"Unable to import PFX '{pfxPath}'.", importException);
				}
			}

			if(!collection.Cast<System.Security.Cryptography.X509Certificates.X509Certificate2>().Any(certificate => certificate.HasPrivateKey))
			{
				AddCertificateIfMissing(collection, new System.Security.Cryptography.X509Certificates.X509Certificate2(pfxPath, password, flags));
			}

			return collection;
		}

		private static System.Security.Cryptography.X509Certificates.X509Certificate2 LoadLeafCertificateWithPrivateKey(
			string pfxPath,
			string password,
			System.Security.Cryptography.X509Certificates.X509KeyStorageFlags flags,
			Dictionary<CertificateTypes, string> certificateFiles)
		{
			var pfxCertificates = LoadPfxCollection(pfxPath, password, flags);
			var leafThumbprint = GetCertificateThumbprint(certificateFiles, CertificateTypes.CRT);
			var candidates = pfxCertificates
				.Cast<System.Security.Cryptography.X509Certificates.X509Certificate2>()
				.Where(certificate => certificate.HasPrivateKey)
				.ToList();

			var leaf = !string.IsNullOrWhiteSpace(leafThumbprint)
				? candidates.FirstOrDefault(certificate => string.Equals(certificate.Thumbprint, leafThumbprint, StringComparison.OrdinalIgnoreCase))
				: null;

			leaf ??= candidates.FirstOrDefault();
			if(leaf is null)
			{
				throw new InvalidOperationException($"PFX '{pfxPath}' does not contain a certificate with private key.");
			}

			return new System.Security.Cryptography.X509Certificates.X509Certificate2(
				leaf.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, password),
				password,
				flags);
		}

		private static string? GetCertificateThumbprint(
			Dictionary<CertificateTypes, string> certificateFiles,
			CertificateTypes certificateType)
		{
			if(!certificateFiles.TryGetValue(certificateType, out var path)
				|| string.IsNullOrWhiteSpace(path)
				|| !System.IO.File.Exists(path))
			{
				return null;
			}

			using var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(path);
			return certificate.Thumbprint;
		}

		private static string BuildPemChain(
			Dictionary<CertificateTypes, string> certificateFiles,
			bool includeLeaf,
			bool includeIntermediates,
			bool includeRoot)
		{
			var builder = new System.Text.StringBuilder();

			if(includeLeaf)
			{
				AppendPemFile(builder, certificateFiles, CertificateTypes.CRT);
			}

			if(includeIntermediates)
			{
				AppendPemFile(builder, certificateFiles, CertificateTypes.IntermediateNoKey);
			}

			if(includeRoot)
			{
				AppendPemFile(builder, certificateFiles, CertificateTypes.CARootNoKey);
			}

			return builder.ToString();
		}

		private static void AppendPemFile(
			System.Text.StringBuilder builder,
			Dictionary<CertificateTypes, string> certificateFiles,
			CertificateTypes certificateType)
		{
			if(!certificateFiles.TryGetValue(certificateType, out var path)
				|| string.IsNullOrWhiteSpace(path)
				|| !System.IO.File.Exists(path))
			{
				return;
			}

			builder.AppendLine(System.IO.File.ReadAllText(path).TrimEnd());
		}

		private static void AddCertificateFromFile(
			System.Security.Cryptography.X509Certificates.X509Certificate2Collection collection,
			Dictionary<CertificateTypes, string> certificateFiles,
			CertificateTypes certificateType)
		{
			if(!certificateFiles.TryGetValue(certificateType, out var path)
				|| string.IsNullOrWhiteSpace(path)
				|| !System.IO.File.Exists(path))
			{
				return;
			}

			AddCertificateIfMissing(collection, new System.Security.Cryptography.X509Certificates.X509Certificate2(path));
		}

		private static void AddCertificateIfMissing(
			System.Security.Cryptography.X509Certificates.X509Certificate2Collection collection,
			System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
		{
			if(collection.Cast<System.Security.Cryptography.X509Certificates.X509Certificate2>()
				.Any(existing => string.Equals(existing.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)))
			{
				certificate.Dispose();
				return;
			}

			collection.Add(certificate);
		}
	}
}

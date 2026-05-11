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

		[HttpGet("CARootInfo")]
		public IActionResult CARootInfo()
		{
			try
			{
				return Ok(CertificationManager.GetCertificateAuthorityInfo());
			}
			catch(CARootNotFoundException ex)
			{
				Logger?.Warning($"CA root info unavailable: {ex.Message}");
				return NotFound(ex.Message);
			}
		}

		[HttpGet("downloadCARoot")]
		public IActionResult DownloadCARoot()
		{
			if(CertificationManager.CARoot is null)
			{
				return NotFound("No CA Root configured");
			}

			var data = System.Text.Encoding.UTF8.GetBytes(CertificationManager.CARoot.ExportCertificatePem());
			return File(data, "application/octet-stream", "FCNXTCA.crt");
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

				return File(certificateData, "application/x-x509-ca-cert", "Certificate.pfx");
			}
			catch(Exception ex)
			{
				Logger?.Warning($"Error creating PFX from CRT: {ex.Message}");
				return BadRequest($"Error creating PFX: {ex.Message}");
			}
		}

		[HttpGet("downloadPFX")]
		public IActionResult DownloadFilePFX(int id)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null || !result.TryGetValue(CertificateTypes.PFX, out var filePath))
			{
				return NotFound($"No PFX certificate with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);

			string sha = CertificationManager.FileManager!.ShaManager.HashFile(file);
			file.Position = 0;
			Logger?.Warning($"Sha {filePath}: {sha}");

			return File(file, "application/octet-stream", "Certificate.pfx");
		}

		[HttpGet("downloadCRT")]
		public IActionResult DownloadFileCRT(int id)
		{
			var result = CertificationManager.FileManager?.RetrieveCertificates(id);
			if(result is null || !result.TryGetValue(CertificateTypes.CARootNoKey, out var filePath))
			{
				return NotFound($"No CRT certificate with ID: {id}");
			}

			var file = new FileStream(filePath, FileMode.Open, FileAccess.Read);

			string sha = CertificationManager.FileManager!.ShaManager.HashFile(file);
			file.Position = 0;
			Logger?.Warning($"Sha {filePath}: {sha}");

			return File(file, "application/octet-stream", "FCNXTCA.crt");
		}

		[HttpGet("downloadDER")]
		public IActionResult DownloadFileDER(int id)
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
	}
}

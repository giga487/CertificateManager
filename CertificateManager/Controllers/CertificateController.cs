using CertificateManager.src;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;

namespace CertificateManager.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CertificateController : ControllerBase
    {
        private CertificateCommon.CertificationManager? _certificationManager { get; init; }
        private Serilog.ILogger? _logger { get; init; }
        public CertificateController(CertificateCommon.CertificationManager certificationManager, Serilog.ILogger? logger)
        {
            _certificationManager = certificationManager;
            _logger = logger;
        }


        [HttpGet("Sha")]
        public IActionResult GetSHA(string solutionName, CertificateTypes type)
        {
            try
            {
                string value = _certificationManager?.FileManager?.HashFileBy(solutionName, type) ?? "";
                return Ok(value);
            }
            catch(Exception ex)
            {
                _logger?.Warning($"Error making certificate: {ex.Message}");
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("Get")]
        public IActionResult GetCertificate(int id)
        {
            if(_certificationManager?.FileManager?.JSONMemory?.Get(id, out var certificate) ?? false)
            {
                return Ok(certificate);
            }

            return BadRequest($"No certificate with ID: {id}");
            
        }

        [HttpPost("MakeCertificate")]
        public IActionResult MakeCertificate([FromBody] Certificate certificate)
        {
            try
            {
                var result = _certificationManager?.CreatingPFX_CRT(
                    serverAddress: certificate.Address,
                    company: certificate.Company,
                    commonName: certificate.CN,
                    exportPWD: certificate.Password,
                    expiring: DateTimeOffset.Now + TimeSpan.FromDays(3650),
                    solutionFolder: certificate.Solution,
                    serverDNS: certificate.DNS);

                return Ok(result);
            }
            catch(Exception ex)
            {
                _logger?.Warning($"Error making certificate with dns: {ex.Message}");
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("ID")]
        public IActionResult IDBySolution(string solution)
        {
            if(_certificationManager?.FileManager?.JSONMemory?.GetIDBySolution(solution, out int? id) ?? false)
            {
                return Ok(id);
            }

            return Ok(-1);
        }

        [HttpGet("Info")]
        public IActionResult Info()
        { 
            return Ok(_certificationManager?.FileManager?.JSONMemory);
        }


        [HttpGet("downloadPFX")]
        public IActionResult DownloadFilePFX(int id)
        {

            var result = _certificationManager?.FileManager?.RetrieveCertificates(id) ?? default;

            //var file = System.IO.File.OpenRead(result[CertificateTypes.PFX]);
            var file = new FileStream(result[CertificateTypes.PFX], FileMode.Open, FileAccess.Read);

            string sha = _certificationManager.FileManager.ShaManager.HashFile(file);
            _logger?.Warning($"Sha {result[CertificateTypes.PFX]}: {sha}");

            return File(file, "application/octet-stream", "Certificate.pfx");
        }

        [HttpGet("downloadCRT")]
        public IActionResult DownloadFileCRT(int id)
        {

            var result = _certificationManager?.FileManager?.RetrieveCertificates(id) ?? default;
            var file = new FileStream(result[CertificateTypes.CARootNoKey], FileMode.Open, FileAccess.Read);

            string sha = _certificationManager.FileManager.ShaManager.HashFile(file);
            _logger?.Warning($"Sha {result[CertificateTypes.CARootNoKey]}: {sha}");

            return File(file, "application/octet-stream", "FCNXTCA.crt");
        }
    }
}

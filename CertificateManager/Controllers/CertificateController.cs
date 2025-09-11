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
        public CertificateController(CertificateCommon.CertificationManager certificationManager)
        {
            _certificationManager = certificationManager;
        }

        [HttpGet("Make")]
        public IActionResult GetCertificates(string cn, string address, string company, string solutionName, string password)
        {
            try
            {
                var result = _certificationManager?.CreatingPFX_CRT("server1", 
                    serverAddress: address,
                    company: company, 
                    exportPWD: password,
                    expiring: DateTimeOffset.Now + TimeSpan.FromDays(3650),
                    solutionFolder: solutionName);

                return Ok(result);
            }
            catch
            {
                return BadRequest();
            }
        }

        [HttpGet("Info")]
        public IActionResult Info()
        { 
            return Ok(_certificationManager?.FileManager?.LastDB);
        }


        [HttpGet("downloadPFX")]
        public IActionResult DownloadFilePFX(int id)
        {

            var result = _certificationManager?.FileManager?.RetrieveCertificates(id) ?? default;

            //var file = System.IO.File.OpenRead(result[CertificateTypes.PFX]);
            var file = new FileStream(result[CertificateTypes.CARootNoKey], FileMode.Open, FileAccess.Read);

            return new FileStreamResult(file, "application/octet-stream")
            {
                FileDownloadName = "Certificate.pfx"
            };
        }

        [HttpGet("downloadCRT")]
        public IActionResult DownloadFileCRT(int id)
        {

            var result = _certificationManager?.FileManager?.RetrieveCertificates(id) ?? default;
            var file = new FileStream(result[CertificateTypes.CARootNoKey], FileMode.Open, FileAccess.Read);

            return File(file, "application/octet-stream", "FCNXTCA.crt");
        }
    }
}

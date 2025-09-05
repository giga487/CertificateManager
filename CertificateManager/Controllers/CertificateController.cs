using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

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
        public IActionResult GetCertificates(string cn, string address, string company, string solutionName)
        {
            try
            {
                var result = _certificationManager?.CreatingPFX_CRT("server1", 
                    serverAddress: address,
                    company: company, 
                    exportPWD: ".1q2w3e!",
                    expiring: DateTimeOffset.Now + TimeSpan.FromDays(3650),
                    solutionFolder: solutionName);
                return Ok(result);
            }
            catch
            {
                return BadRequest();
            }
        }
    }
}

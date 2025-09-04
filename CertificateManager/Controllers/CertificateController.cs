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
        public IActionResult GetCertificates(string address)
        {
            try
            {
                _certificationManager?.CreatingPFX_CRT(address, "FINCANTIERI NEXTECH", ".1q2w3e!", DateTimeOffset.Now + TimeSpan.FromDays(3650));
                return Ok();
            }
            catch
            {
                return BadRequest();
            }
        }
    }
}

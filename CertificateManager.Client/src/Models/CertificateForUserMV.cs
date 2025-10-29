using CertificateManager.src;
using Common.src.Architecture.Interface;
using CommonBlazor.HttpClient;
using Microsoft.JSInterop;
using Microsoft.VisualBasic;
using System.ComponentModel;
using static CertificateCommon.CertificationManager;

namespace CertificateManager.Client.src.Models
{
    public class CreateForCertificateMV : IViewModel, IAsyncDisposable
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;

        CancellationTokenSource? _source { get; init; } = new CancellationTokenSource();
        Serilog.ILogger _logger { get; init; }
        private HttpClientFactoryCommon? _factory { get; init; }
        IJSRuntime _jsRuntime { get; init; }

        public CreateForCertificateMV(HttpClientFactoryCommon factory, Serilog.ILogger logger, IJSRuntime runtime)
        {
            _factory = factory;

            _logger = logger;
            _jsRuntime = runtime;
        }

        public void OnStateChange(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public async ValueTask DisposeAsync()
        {
            _source?.Cancel();

            await Task.CompletedTask;

            _source?.Dispose();
        }

        public int CreatedCRTId { get; set; } = 0;

        public async Task GetId(string solution)
        {
            int? result = await _factory!.GetAsync<int>($"api/Certificate/ID?solution={solution}");

            CreatedCRTId = result ?? -1;
        }

        public async Task<Certificate?> GetCertificateID(int id)
        {
            return await _factory!.GetAsync<Certificate>($"api/Certificate/Get?id={id}") ?? default;
        }



        public async Task<List<CertficateFileInfo>?> Make(string company, string address, string oid, string solutionName, string cn, string password, params string[] dnsss)
        {
            List<CertficateFileInfo> result = new List<CertficateFileInfo>();

            Certificate newCert = new Certificate()
            {
                Solution = solutionName,
                Address = address,
                CN = cn,
                Company = company,
                DNS = dnsss.ToArray(),
                Password = password,
                Oid = oid
            };

            try
            {
                result = await _factory?.PostAsync<List<CertficateFileInfo>, Certificate>($"api/Certificate/MakeCertificate", newCert) ?? default;

                await GetId(solutionName);
            }
            catch(OperationCanceledException ex)
            {
                _logger?.Warning($"Error making {ex.Message}");

            }

            return result;
        }


        public async void DownloadPFX(int? id, string solution)
        {
            _logger?.Information($"PFX: {id}");

            try
            {
                await _factory?.Download($"api/Certificate/downloadPFX?id={id}", runtime: _jsRuntime, prefix: solution);

            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadCRT(int? id, string solution)
        {
            _logger?.Information($"CRT: {id}");
            try
            {

                await _factory?.Download($"api/Certificate/downloadCRT?id={id}", runtime: _jsRuntime, prefix: solution);
                
            }
            catch(OperationCanceledException ex)
            {

            }
        }

    }
}

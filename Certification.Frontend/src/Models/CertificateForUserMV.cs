using CertificateManager.src;
using Common.src.Architecture.Interface;
using CommonBlazor.HttpClient;
using Microsoft.JSInterop;
using Microsoft.VisualBasic;
using System.ComponentModel;
using System.Net.Http.Json;
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
        public string? LastError { get; private set; }

        public async Task GetId(string solution)
        {
            int? result = await _factory!.GetAsync<int>($"api/Certificate/ID?solution={solution}");

            CreatedCRTId = result ?? -1;
        }

        public async Task<Certificate?> GetCertificateID(int id)
        {
            return await _factory!.GetAsync<Certificate>($"api/Certificate/Get?id={id}") ?? default;
        }

        public async Task<List<CertificateAuthorityInfo>> GetCertificateAuthorities()
        {
            return await _factory!.GetAsync<List<CertificateAuthorityInfo>>("api/Certificate/CARoots") ?? [];
        }



        public async Task<List<CertficateFileInfo>?> Make(CertificateGenerationRequest newCert)
        {
            List<CertficateFileInfo> result = new List<CertficateFileInfo>();

            try
            {
                result = await _factory?.PostAsync<List<CertficateFileInfo>, CertificateGenerationRequest>($"api/Certificate/MakeCertificate", newCert) ?? default;

                await GetId(newCert.Solution ?? string.Empty);
            }
            catch(OperationCanceledException ex)
            {
                _logger?.Warning($"Error making {ex.Message}");

            }

            return result;
        }

        public async Task<List<CertficateFileInfo>?> MakeIntermediate(CertificateGenerationRequest newCert)
        {
            LastError = null;

            try
            {
                var client = _factory?.GetClient();
                if(client is null)
                {
                    LastError = "HTTP client is not available.";
                    return null;
                }

                var response = await client.PostAsJsonAsync("api/Certificate/MakeIntermediateCertificate", newCert);
                if(!response.IsSuccessStatusCode)
                {
                    LastError = await response.Content.ReadAsStringAsync();
                    if(string.IsNullOrWhiteSpace(LastError))
                    {
                        LastError = $"Backend returned {(int)response.StatusCode} {response.ReasonPhrase}.";
                    }

                    _logger?.Warning($"Error making intermediate {LastError}");
                    return null;
                }

                var result = await response.Content.ReadFromJsonAsync<List<CertficateFileInfo>>();

                await GetId(newCert.Solution ?? string.Empty);
                return result;
            }
            catch(OperationCanceledException ex)
            {
                LastError = $"Intermediate creation cancelled: {ex.Message}";
                _logger?.Warning(LastError);
            }
            catch(Exception ex)
            {
                LastError = $"Intermediate creation failed: {ex.Message}";
                _logger?.Warning(LastError);
            }

            return null;
        }


        public async void DownloadPFX(int? id, string solution)
        {
            _logger?.Information($"PFX: {id}");

            try
            {
                await _factory?.Download($"api/Certificate/downloadPFX?id={id}", runtime: _jsRuntime, prefix: solution, fallbackFileName: "Certificate.pfx");

            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadRootCRT(int? id, string solution)
        {
            _logger?.Information($"Root CRT: {id}");
            try
            {
                await _factory?.Download($"api/Certificate/downloadCRT?id={id}", runtime: _jsRuntime, prefix: solution, fallbackFileName: "Root.crt");
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadRootDER(int? id, string solution)
        {
            _logger?.Information($"Root DER: {id}");
            try
            {
                await _factory?.Download($"api/Certificate/downloadRootDER?id={id}", runtime: _jsRuntime, prefix: solution, fallbackFileName: "Root.der");
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadDER(int? id, string solution)
        {
            _logger?.Information($"Certificate DER: {id}");
            try
            {
                await _factory?.Download($"api/Certificate/downloadDER?id={id}", runtime: _jsRuntime, prefix: solution, fallbackFileName: "Certificate.der");
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadCertificatePEM(int? id, string solution, bool includeIntermediates = false, bool includeRoot = false)
        {
            _logger?.Information($"Certificate PEM: {id}");
            try
            {
                var query = $"api/Certificate/downloadCertificatePEM?id={id}&includeIntermediates={includeIntermediates.ToString().ToLowerInvariant()}&includeRoot={includeRoot.ToString().ToLowerInvariant()}";
                await _factory?.Download(query, runtime: _jsRuntime, prefix: solution, fallbackFileName: includeIntermediates || includeRoot ? "Certificate-with-chain.crt" : "Certificate.crt");
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadPrivateKeyPEM(int? id, string solution)
        {
            _logger?.Information($"Private key PEM: {id}");
            try
            {
                await _factory?.Download($"api/Certificate/downloadPrivateKeyPEM?id={id}", runtime: _jsRuntime, prefix: solution, fallbackFileName: "private.key");
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadIntermediateCRT(int? id, string solution)
        {
            _logger?.Information($"Intermediate CRT: {id}");
            try
            {
                await _factory?.Download($"api/Certificate/downloadIntermediateCRT?id={id}", runtime: _jsRuntime, prefix: solution, fallbackFileName: "Intermediate.crt");
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadChainCRT(int? id, string solution)
        {
            _logger?.Information($"Certificate chain CRT: {id}");
            try
            {
                await _factory?.Download($"api/Certificate/downloadChainCRT?id={id}", runtime: _jsRuntime, prefix: solution, fallbackFileName: "Certificate-chain.crt");
            }
            catch(OperationCanceledException ex)
            {

            }
        }

    }
}

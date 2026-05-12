using CertificateManager.src;
using Common.src.Architecture.Interface;
using CommonBlazor.HttpClient;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using Microsoft.VisualBasic;
using System.ComponentModel;
using static CertificateCommon.CertificationManager;

namespace CertificateManager.Client.src.Models
{
    public class CertificateOvervieVM : IViewModel
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;
        private HttpClientFactoryCommon? _factory { get; init; }
        CancellationTokenSource? _source { get; init; } = new CancellationTokenSource();
        Serilog.ILogger _logger { get; init; }

        IJSRuntime _jsRuntime { get; init; }
        NavigationManager _manager { get; init; }

        public CertificateOvervieVM(HttpClientFactoryCommon factory, Serilog.ILogger logger, IJSRuntime runtime, NavigationManager manager)
        {
            _factory = factory;

            _logger = logger;
            _jsRuntime = runtime;
            _manager = manager;
            Polling();
        }
        public async Task Make(string company, string address, string solutionName, string cn, string password, params string[] dnsss)
        {
            List<CertficateFileInfo> result = new List<CertficateFileInfo>();

            CertificateGenerationRequest newCert = new CertificateGenerationRequest()
            {
                Solution = solutionName,
                CommonName = cn,
                Organization = company,
                DnsNames = dnsss.ToArray(),
                IpAddresses = [],
                KeyUsages = ["DigitalSignature"],
                PfxPassword = password,
                EnhancedKeyUsages = ["1.3.6.1.5.5.7.3.1"]
            };

            try
            {
                result = await _factory?.PostAsync<List<CertficateFileInfo>, CertificateGenerationRequest>($"api/Certificate/MakeCertificate", newCert) ?? default;
            }
            catch(OperationCanceledException ex)
            {
                _logger?.Warning($"Error making {ex.Message}");

            }
        }
        public CertificateDB? Certificates { get; private set; } = null;
        public bool IsLoading { get; private set; } = true;

        Task? _pollingTask;
        public void Polling()
        {
            _pollingTask = Task.Run(async () =>
                {
                try
                {
                    while(!_source?.Token.IsCancellationRequested ?? true)
                    {
                        var result = await _factory?.GetAsync<CertificateDB>("api/Certificate/info");

                        Certificates = result;
                        IsLoading = false;
                        OnStateChange("Info received");

                        await Task.Delay(6000);
                    }
                }
                catch(OperationCanceledException ex)
                {

                }
                catch(Exception ex)
                {
                    IsLoading = false;
                    OnStateChange("Info failed");
                    _logger?.Information($"{ex.Message}");
                }
            });
        }


        public void OnStateChange(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public async ValueTask DisposeAsync()
        {
            _source?.Cancel();

            if(_pollingTask is not null)
            {
                await _pollingTask;
            }

            _source?.Dispose();
        }

        public async void DownloadPFX(int? id)
        {
            _logger?.Information($"PFX: {id}");

            try
            {
                if(Certificates?.Get(id ?? 0, out var found) ?? false)
                {
                    await _factory?.Download($"api/Certificate/downloadPFX?id={id}", runtime: _jsRuntime, prefix: found.Solution);
                }


            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void Regenerate(int? id)
        {
            _manager.NavigateTo($"/certificateGenerator/ID={id}");
        }


        public async void DownloadRootCRT(int? id)
        {
            _logger?.Information($"Root CRT: {id}");
            try
            {
                if(Certificates?.Get(id ?? 0, out var found) ?? false)
                {
                    await _factory?.Download($"api/Certificate/downloadCRT?id={id}", runtime: _jsRuntime, prefix: found.Solution, fallbackFileName: "Root.crt");
                }
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadRootDER(int? id)
        {
            _logger?.Information($"Root DER: {id}");
            try
            {
                if(Certificates?.Get(id ?? 0, out var found) ?? false)
                {
                    await _factory?.Download($"api/Certificate/downloadRootDER?id={id}", runtime: _jsRuntime, prefix: found.Solution, fallbackFileName: "Root.der");
                }
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadDER(int? id)
        {
            _logger?.Information($"Certificate DER: {id}");
            try
            {
                if(Certificates?.Get(id ?? 0, out var found) ?? false)
                {
                    await _factory?.Download($"api/Certificate/downloadDER?id={id}", runtime: _jsRuntime, prefix: found.Solution, fallbackFileName: "Certificate.der");
                }
            }
            catch(OperationCanceledException ex)
            {

            }
        }
    }
}

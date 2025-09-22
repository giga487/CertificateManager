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
    public class CertificateOvervieVM : IViewModel, IAsyncDisposable
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

            try
            {
                if(dnsss.Length > 0)
                {
                    result = await _factory?.PostAsync<List<CertficateFileInfo>, string[]>($"api/Certificate/MakeDNS?address={address}&company={company}&solutionname={solutionName}&cn={cn}&password={password}", dnsss);

                }
                else
                    result = await _factory?.GetAsync<List<CertficateFileInfo>>($"api/Certificate/Make?address={address}&company={company}&solutionname={solutionName}&cn={cn}&password={password}");

            }
            catch(OperationCanceledException ex)
            {
                _logger?.Warning($"Error making {ex.Message}");

            }
        }
        public CertificateDB? Certificates { get; private set; } = null;

        Task? _pollingTask;
        public void Polling()
        {
            _ = Task.Run(async () =>
                {
                try
                {
                    while(!_source?.Token.IsCancellationRequested ?? true)
                    {
                        var result = await _factory?.GetAsync<CertificateDB>("api/Certificate/info");

                        if(result is not null)
                        {
                            Certificates = result;

                            OnStateChange("Info received");
                        }

                        await Task.Delay(6000);
                    }
                }
                catch(OperationCanceledException ex)
                {

                }
                catch(Exception ex)
                {
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

            await _pollingTask;

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


        public async void DownloadCRT(int? id)
        {
            _logger?.Information($"CRT: {id}");
            try
            {
                if(Certificates?.Get(id ?? 0, out var found) ?? false)
                {
                    await _factory?.Download($"api/Certificate/downloadCRT?id={id}", runtime: _jsRuntime, prefix: found.Solution);
                }
            }
            catch(OperationCanceledException ex)
            {

            }
        }
    }
}

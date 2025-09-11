using CertificateManager.src;
using Common.src.Architecture.Interface;
using CommonBlazor.HttpClient;
using Microsoft.JSInterop;
using Microsoft.VisualBasic;
using System.ComponentModel;

namespace CertificateManager.Client.src
{
    public class CertificateGeneratorMV : IViewModel, IAsyncDisposable
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;
        private HttpClientFactoryCommon? _factory { get; init; }
        CancellationTokenSource? _source { get; init; } = new CancellationTokenSource();
        Serilog.ILogger _logger { get; init; }

        IJSRuntime _jsRuntime { get; init; }

        public CertificateGeneratorMV(HttpClientFactoryCommon factory, Serilog.ILogger logger, IJSRuntime runtime)
        {
            _factory = factory;

            _logger = logger;
            _jsRuntime = runtime;

            Polling();
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

                        await Task.Delay(60000);
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
                await _factory?.Download($"api/Certificate/downloadPFX?id={id}", runtime: _jsRuntime);
            }
            catch(OperationCanceledException ex)
            {

            }
        }

        public async void DownloadCRT(int? id)
        {
            _logger?.Information($"CRT: {id}");
            try
            {
                await _factory?.Download($"api/Certificate/downloadCRT?id={id}", runtime: _jsRuntime);
            }
            catch(OperationCanceledException ex)
            {

            }
        }
    }
}

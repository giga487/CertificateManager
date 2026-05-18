using CertificateManager.src;
using Common.src.Architecture.Interface;
using CommonBlazor.HttpClient;
using Microsoft.JSInterop;
using System.ComponentModel;

namespace CertificateManager.Client.src.Models
{
    public sealed class CARootInfoVM : IViewModel
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;

        private readonly HttpClientFactoryCommon _factory;
        private readonly IJSRuntime _jsRuntime;
        private readonly Serilog.ILogger _logger;

        public CARootInfoVM(HttpClientFactoryCommon factory, IJSRuntime jsRuntime, Serilog.ILogger logger)
        {
            _factory = factory;
            _jsRuntime = jsRuntime;
            _logger = logger;
        }

        public CertificateAuthorityInfo? Info { get; private set; }
        public List<CertificateAuthorityInfo> Authorities { get; private set; } = [];
        public bool IsLoading { get; private set; } = true;
        public string? ErrorMessage { get; private set; }

        public async Task Load()
        {
            IsLoading = true;
            ErrorMessage = null;
            OnStateChange(nameof(IsLoading));

            try
            {
                Authorities = await _factory.GetAsync<List<CertificateAuthorityInfo>>("api/Certificate/CARoots") ?? [];
                Info = Authorities.FirstOrDefault(authority => authority.IsDefault)
                    ?? Authorities.FirstOrDefault();
                if(Authorities.Count == 0)
                {
                    ErrorMessage = "CA Root not found or not configured.";
                }
            }
            catch(Exception ex)
            {
                ErrorMessage = ex.Message;
                _logger.Warning($"Error loading CA Root info: {ex.Message}");
            }
            finally
            {
                IsLoading = false;
                OnStateChange(nameof(Info));
            }
        }

        public async Task Download()
        {
            await _factory.Download("api/Certificate/downloadCARoot", _jsRuntime, "CA-Root-");
        }

        public async Task Download(string? authorityId)
        {
            var query = string.IsNullOrWhiteSpace(authorityId)
                ? "api/Certificate/downloadCARoot"
                : $"api/Certificate/downloadCARoot?authorityId={Uri.EscapeDataString(authorityId)}";
            await _factory.Download(query, _jsRuntime, "CA-");
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }

        public void OnStateChange(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}

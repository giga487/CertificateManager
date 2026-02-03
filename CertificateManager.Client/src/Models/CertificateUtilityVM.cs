using CertificateManager.src;
using Common.src.Architecture.Interface;
using CommonBlazor.HttpClient;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.JSInterop;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static CertificateCommon.CertificationManager;

namespace CertificateManager.Client.src.Models
{
    public class CertificateUtilityVM : IViewModel, IAsyncDisposable
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;
        Serilog.ILogger _logger { get; init; }
        private HttpClientFactoryCommon? _factory { get; init; }

        IJSRuntime? _jsRuntime { get; init; }
        public CertificateDetails? LoadedCertificate { get; set; }
        public IBrowserFile? SelectedCertificate { get; set; }
        public IBrowserFile? SelectedKey { get; set; }
        public string Password { get; set; }
        public string PfxPassword { get; set; }
        public string? ErrorMessage { get; set; }

        public CertificateUtilityVM(HttpClientFactoryCommon factory, Serilog.ILogger logger, IJSRuntime runtime)
        {
            _factory = factory;
            _logger = logger;
            _jsRuntime = runtime;
        }
        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }

        public enum CertificateUtilityTabs
        {
            CERT,
            KEY
        }

        private long _maxFileSize { get; init; } = 1024 * 1024 * 5;

        public void OnStateChange(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public async void DownloadPFX()
        {
            ErrorMessage = null;
            OnStateChange("Reset Error");
            try
            {
                if(SelectedCertificate is null || string.IsNullOrEmpty(PfxPassword) || SelectedKey is null)
                {
                    ErrorMessage = "Some input is not valid";
                    _logger?.Warning(ErrorMessage);
                    OnStateChange("Input Error");
                    return;
                }

                using var fileStream = SelectedCertificate.OpenReadStream(_maxFileSize);
                using var fileStreamKey = SelectedKey.OpenReadStream(_maxFileSize);

                using(var content = new MultipartFormDataContent())
                {
                    content.Add(new StreamContent(fileStream), "crtFile", SelectedCertificate.Name);
                    content.Add(new StreamContent(fileStreamKey), "key", SelectedKey.Name);
                    content.Add(new StringContent(Password ?? string.Empty), "password");
                    content.Add(new StringContent(PfxPassword ?? string.Empty), "pfxPassword");

                    var response = await _factory?.PostAsync($"api/Certificate/CreatePFXFromCRT", content) ?? default;

                    if(response is null || !response.IsSuccessStatusCode)
                    {
                        string errorDetails = response != null ? await response.Content.ReadAsStringAsync() : "No response";
                        ErrorMessage = $"Error creating PFX file: {errorDetails}";
                        _logger?.Warning(ErrorMessage);
                        OnStateChange("Server Error");
                        return;
                    }

                    byte[] fileBytes = await response!.Content.ReadAsByteArrayAsync();
                    await _jsRuntime!.InvokeVoidAsync("blazorDownloadFileFromArray", "Certificate.pfx", fileBytes);

                }
            }
            catch(Exception ex)
            {
                ErrorMessage = $"Download PFX cancelled: {ex.Message}";
                _logger?.Warning(ErrorMessage);
                OnStateChange("Exception Error");
            }
        }


        public async Task HandleFileSelectedCRT(InputFileChangeEventArgs e, CertificateUtilityTabs certificateType)
        {
            var file = e.File;

            if(file == null)
            {
                return;
            }

            if(certificateType == CertificateUtilityTabs.KEY)
                SelectedKey = file;
            else if(certificateType == CertificateUtilityTabs.CERT)
                SelectedCertificate = file;

            try
            {
                using(var content = new MultipartFormDataContent())
                {
                    var fileStream = SelectedCertificate.OpenReadStream(_maxFileSize);
                    var fileStreamKey = SelectedKey?.OpenReadStream(_maxFileSize);

                    content.Add(new StreamContent(fileStream), "file", file.Name);

                    if(fileStreamKey is not null)
                        content.Add(new StreamContent(fileStreamKey), "key", file.Name);

                    if(!string.IsNullOrEmpty(Password))
                        content.Add(new StringContent(Password ?? string.Empty), "password");

                    CertificateDetails? details = null;

                    if(fileStreamKey is not null && fileStream is not null && !string.IsNullOrEmpty(Password))
                    {
                        details = await _factory?.PostAsync<PrivateKeyCertificateDetails>($"api/Certificate/CeritificationInfoWithSecuredKey", content) ?? default;
                    }
                    else if(fileStreamKey is not null && fileStream is not null)
                    {
                        details = await _factory?.PostAsync<PrivateKeyCertificateDetails>($"api/Certificate/CeritificationInfoWithKey", content) ?? default;
                    }
                    else if(fileStream is not null)
                    {
                        details = await _factory?.PostAsync<CertificateDetails>($"api/Certificate/CeritificationInfo", content) ?? default;
                    }

                    if(details is not null)
                    {
                        LoadedCertificate = details;
                        OnStateChange("Updated the loaded certificate");
                    }
                }

            }
            catch(Exception ex)
            {
                _logger?.Warning($"Error loading certificate: {ex.Message}");
            }

        }
    }
}

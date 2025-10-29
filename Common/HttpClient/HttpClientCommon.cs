using CertificateCommon;
using Microsoft.JSInterop;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace CommonBlazor.HttpClient
{
    public class HttpClientFactoryCommon
    {
        public static string ClientName => "Client";
        IHttpClientFactory? _httpFactory;
        Serilog.ILogger? _logger;
        ShaManager _shaManager { get; init; }
        public HttpClientFactoryCommon(IHttpClientFactory factory, Serilog.ILogger logger, ShaManager sha)
        {
            _httpFactory = factory;
            _logger = logger;

            _shaManager = sha;

            var client = factory.CreateClient(ClientName);
            _logger = logger.ForContext(Serilog.Core.Constants.SourceContextPropertyName, "Common Http Factory");
            _logger?.Information($"Created the client factory for address: {client?.BaseAddress}");
        }

        public System.Net.Http.HttpClient? GetClient()
        {
            return _httpFactory?.CreateClient(ClientName) ?? null;
        }

        public async Task Download(string address, IJSRuntime runtime, string prefix)
        {

        //< script >
        //    window.downloadFileFromStream = async (fileName, contentStreamReference) => {
        //        const arrayBuffer = await contentStreamReference.arrayBuffer();
        //        const blob = new Blob([arrayBuffer]);
        //        const url = URL.createObjectURL(blob);
        //        const anchorElement = document.createElement('a');
        //        anchorElement.href = url;
        //        anchorElement.download = fileName ?? '';
        //        anchorElement.click();
        //        anchorElement.remove();
        //        URL.revokeObjectURL(url);
        //    };
        //</ script >

            await GetStreamAsync(address, runtime, prefix);
        }


        public async Task GetStreamAsync(string address, IJSRuntime runtime, string beforeName = "")
        {
            var client = _httpFactory?.CreateClient(ClientName);

            CancellationTokenSource source = new CancellationTokenSource();
            if(client is not null)
            {
                try
                {
                    var response = await client.GetAsync(address);

                    if(response.IsSuccessStatusCode)
                    {
                        //var stream = await response.Content.ReadAsStreamAsync();
                        //var fileName = beforeName + response.Content.Headers.ContentDisposition?.FileNameStar ?? "downloaded_file";

                        //using var networkStream = await response.Content.ReadAsStreamAsync();
                        //var memoryStream = new MemoryStream();
                        //await networkStream.CopyToAsync(memoryStream);

                        //string sha = _shaManager.HashFile(memoryStream);
                        //_logger?.Information($"Sha {fileName} {sha}");

                        //memoryStream.Position = 0;
                        //using var streamRef = new DotNetStreamReference(stream: memoryStream);

                        //await runtime.InvokeVoidAsync("downloadFileFromStream", fileName, streamRef);


                        var fileName = beforeName + response.Content.Headers.ContentDisposition?.FileNameStar ?? "downloaded_file";

                        // 1. Leggi lo stream dalla risposta UNA SOLA VOLTA
                        using var networkStream = await response.Content.ReadAsStreamAsync();

                        // 2. Copialo in un MemoryStream per poterlo riutilizzare
                        var memoryStream = new MemoryStream();
                        await networkStream.CopyToAsync(memoryStream);

                        // 3. Calcola l'hash dal MemoryStream
                        // (Assicurati che la posizione sia all'inizio se il tuo metodo non lo fa già)
                        memoryStream.Position = 0;
                        string sha = _shaManager.HashFile(memoryStream);
                        _logger?.Warning($"Sha {fileName} {sha}");

                        // 4. Riporta la posizione all'inizio prima di passarlo al download
                        memoryStream.Position = 0;

                        // 5. Usa lo STESSO MemoryStream per il download
                        using var streamRef = new DotNetStreamReference(stream: memoryStream);
                        await runtime.InvokeVoidAsync("downloadFileFromStream", fileName, streamRef);
                    }
                }
                catch(Exception ex)
                {
                    _logger?.Error(ex.Message);
                }
            }

            return;
        }


        public async Task<HttpResponseMessage> PostAsync(string url, MultipartFormDataContent body)
        {
            var client = _httpFactory?.CreateClient(ClientName);
            if(client is not null)
            {
                try
                {
                    var response = await client.PostAsync(url, body);
                    return response;
                }
                catch(Exception ex)
                {
                    _logger?.Information(ex.Message);
                }
            }
            return new HttpResponseMessage(HttpStatusCode.BadRequest);
        }


        public async Task<T> PostAsync<T>(string url, MultipartFormDataContent body)
        {

            var client = _httpFactory?.CreateClient(ClientName);

            if(client is not null)
            {
                try
                {
                    var response = await client.PostAsync(url, body);

                    if(response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadFromJsonAsync<T>();
                        response.EnsureSuccessStatusCode();

                        if(result is not null)
                        {
                            return result;
                        }

                    }
                }
                catch(Exception ex)
                {
                    _logger?.Information(ex.Message);
                }
            }

            return default;
        }




        public async Task<T> PostAsync<T, U>(string url, U body)
        {
            var client = _httpFactory?.CreateClient(ClientName);

            if(client is not null)
            {
                try
                {
                    var response = await client.PostAsJsonAsync(url, body);

                    if(response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadFromJsonAsync<T>();
                        response.EnsureSuccessStatusCode();

                        if(result is not null)
                        {
                            return result;
                        }

                    }
                }
                catch(Exception ex)
                {
                    _logger?.Information(ex.Message);
                }
            }

            return default;
        }

        public async Task<T?> GetAsync<T>(string address)
        {
            var client = _httpFactory?.CreateClient(ClientName);

            if(client is not null)
            {
                try
                {
                    var response = await client.GetAsync(address);

                    if(response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadFromJsonAsync<T>();

                        if(result is not null)
                        {
                            return result;
                        }

                    }
                }
                catch(Exception ex)
                {
                    _logger?.Information(ex.Message);
                }
            }

            return default;
        }


    }
}

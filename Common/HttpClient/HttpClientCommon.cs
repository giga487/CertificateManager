using Microsoft.JSInterop;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
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
        public HttpClientFactoryCommon(IHttpClientFactory factory, Serilog.ILogger logger)
        {
            _httpFactory = factory;
            _logger = logger;

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
                        var stream = await response.Content.ReadAsStreamAsync();
                        var fileName = beforeName + response.Content.Headers.ContentDisposition?.FileNameStar ?? "downloaded_file";

                        using var networkStream = await response.Content.ReadAsStreamAsync();
                        var memoryStream = new MemoryStream();
                        await networkStream.CopyToAsync(memoryStream);

                        memoryStream.Position = 0;
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

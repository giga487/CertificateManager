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

        public async Task<T?> GetAsync<T>(string address)
        {
            var client = _httpFactory?.CreateClient(ClientName);

            if(client is not null)
            {
                try
                {
                    var response = await client.GetAsync("/api/info/Logs");

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

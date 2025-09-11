using CertificateManager.Client.src;
using Common;
using CommonBlazor.HttpClient;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.FluentUI.AspNetCore.Components;
using System;

namespace CertificateManager.Client
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.Services.AddFluentUIComponents();

            LoggerBuilder<ClientLogMessage> loggbuilder = new LoggerBuilder<ClientLogMessage>("LOG/Cert.Log");
            Serilog.ILogger? logger = loggbuilder.GetContext("GRPCServer");

            if(logger is not null)
            {
                builder.Logging.ClearProviders();
                //builder.Logging.AddSerilog(logger);
                builder.Services.AddSingleton<Serilog.ILogger>(logger);
            }

            var uri = new UriBuilder(builder.HostEnvironment.BaseAddress).Uri;

            builder.Services.AddTransient<CertificateGeneratorMV>();
            builder.Services.AddSingleton<HttpClientFactoryCommon>();
            builder.Services.AddHttpClient(HttpClientFactoryCommon.ClientName, client => client.BaseAddress = uri);

            await builder.Build().RunAsync();
        }
    }
}

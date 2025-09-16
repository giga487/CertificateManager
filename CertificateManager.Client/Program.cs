using CertificateCommon;
using CertificateManager.Client.src.Models;
using Common;
using CommonBlazor.HttpClient;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.FluentUI.AspNetCore.Components;
using System;

namespace CertificateManager.Client
{
    public class AppData
    {
        //IHttpContextAccessor _context { get; init; }
        //public AppData(IHttpContextAccessor context)
        //{
        //    _context = context;
        //}

        //public string GetBaseUrl()
        //{
        //    var request = _context.HttpContext?.Request;

        //    if(request == null)
        //    {
        //        return "Not found";
        //    }

        //    var baseUrl = $"{request.Scheme}://{request.Host}{request.PathBase}";

        //    return baseUrl;
        //}

        public Uri? BaseUrl { get; set; }
    }
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

            builder.Services.AddSingleton(new AppData() { BaseUrl = uri });
            builder.Services.AddTransient<CertificateGeneratorMV>();
            builder.Services.AddTransient<CreateForCertificateMV>();
            builder.Services.AddTransient<ShaManager>();
            builder.Services.AddTransient<HelperMV>();
            builder.Services.AddSingleton<HttpClientFactoryCommon>();
            builder.Services.AddHttpClient(HttpClientFactoryCommon.ClientName, client => client.BaseAddress = uri);

            await builder.Build().RunAsync();
        }
    }
}

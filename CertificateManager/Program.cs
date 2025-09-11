using CertificateManager.Client.Pages;
using CertificateManager.Components;
using CertificateManager.src;
using Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.FluentUI.AspNetCore.Components;
using Serilog;
using Serilog.Events;

namespace CertificateManager
{
    public class CertificationManagerLogEvent : IMemorySinkMessage
    {
        public IMemorySinkMessage Build(LogEvent log)
        {
            return new CertificationManagerLogEvent();
        }
    }

    public class Program
    {
        public static Serilog.ILogger? Logger;
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorComponents()
                .AddInteractiveWebAssemblyComponents();
            builder.Services.AddFluentUIComponents();

            LoggerBuilder<CertificationManagerLogEvent> loggbuilder = new LoggerBuilder<CertificationManagerLogEvent>("LOG/Cert.Log");

            Logger = loggbuilder.GetContext("Certificate Manager");
            builder.Services.AddControllers();
            //Utility.PrintNMEAString(Logger);

            if(Logger is not null)
            {
                builder.Logging.ClearProviders();
                builder.Logging.AddSerilog(Logger);
                builder.Services.AddSingleton<Serilog.ILogger>(Logger);
            }

            builder.Services.AddHostedService<StartupClass>();

            FileManagerCertificate manager = new FileManagerCertificate("OUTPUT/Certificates.Json", Logger);

            builder.Services.AddSingleton(manager);
            builder.Services.AddSingleton<CertificateDB>();
            builder.Services.AddSingleton<CertificateCommon.CertificationManager>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseWebAssemblyDebugging();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.MapControllers();
            app.UseHttpsRedirection();

            app.UseStaticFiles();
            app.UseAntiforgery();

            app.MapRazorComponents<App>()
                .AddInteractiveWebAssemblyRenderMode()
                .AddAdditionalAssemblies(typeof(Client._Imports).Assembly);

            app.Run();
        }
    }
}

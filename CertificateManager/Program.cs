using CertificateCommon;
using CertificateManager.Client;
using CertificateManager.Client.src;
using CertificateManager.Client.src.Models;
using CertificateManager.src;
using Common;
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

            FileManagerCertificate manager = new FileManagerCertificate("OUTPUT/Certificates.Json", Logger, new ShaManager());

            builder.Services.AddSingleton<AppData>();
            builder.Services.AddSingleton(manager);
            builder.Services.AddSingleton<CertificateDB>();
            builder.Services.AddSingleton<CertificateCommon.CertificationManager>();

            builder.Services.AddHttpContextAccessor();

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

            app.UseHttpsRedirection();

            app.UseBlazorFrameworkFiles();
            app.UseStaticFiles();

            app.MapControllers();
            app.MapFallbackToFile("index.html");

            app.Run();
        }
    }
}

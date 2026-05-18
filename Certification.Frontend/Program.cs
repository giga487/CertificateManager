using CertificateCommon;
using CertificateManager.Client;
using CertificateManager.Client.src.Models;
using CommonBlazor.HttpClient;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.FluentUI.AspNetCore.Components;
using Serilog;

namespace Certification.Frontend
{
	public class Program
	{
		public static async Task Main(string[] args)
		{
			var builder = WebAssemblyHostBuilder.CreateDefault(args);
			builder.RootComponents.Add<App>("#app");
			builder.RootComponents.Add<HeadOutlet>("head::after");

			builder.Services.AddFluentUIComponents();

			var backendUrl = builder.Configuration["Backend:BaseUrl"];
			var backendUri = string.IsNullOrWhiteSpace(backendUrl)
				? new Uri(builder.HostEnvironment.BaseAddress)
				: new Uri(backendUrl);

			Serilog.ILogger logger = new LoggerConfiguration()
				.MinimumLevel.Debug()
				.WriteTo.BrowserConsole()
				.CreateLogger()
				.ForContext(Serilog.Core.Constants.SourceContextPropertyName, "Certification Frontend");

			logger?.Information($"Backend uri: {backendUrl} - Environment: {builder.HostEnvironment.BaseAddress}, selected {backendUri}");

			builder.Logging.ClearProviders();
			builder.Logging.AddSerilog(logger);
			builder.Services.AddSingleton(logger);

			builder.Services.AddSingleton(new AppData { BaseUrl = backendUri });
			builder.Services.AddTransient<CertificateOvervieVM>();
			builder.Services.AddTransient<CreateForCertificateMV>();
			builder.Services.AddTransient<CertificateUtilityVM>();
			builder.Services.AddTransient<CARootInfoVM>();
			builder.Services.AddTransient<HelperMV>();
			builder.Services.AddTransient<ShaManager>();
			builder.Services.AddSingleton<HttpClientFactoryCommon>();

			builder.Services.AddScoped(sp => new HttpClient { BaseAddress = backendUri });
			builder.Services.AddHttpClient(HttpClientFactoryCommon.ClientName, client => client.BaseAddress = backendUri);

			await builder.Build().RunAsync();
		}
	}
}

namespace CertificateManager.Client
{
	public class AppData
	{
		public Uri? BaseUrl { get; init; }
	}
}

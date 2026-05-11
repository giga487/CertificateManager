
using CertificateCommon;
using CertificateManager.src;
using Certification.Backend.Services;
using Common;
using Serilog;
using Serilog.Events;

namespace Certification.Backend
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

			LoggerBuilder<CertificationManagerLogEvent> logBuilder = new("LOG/Cert.Log");
			Logger = logBuilder.GetContext("Certification Backend");
			if(Logger is not null)
			{
				builder.Logging.ClearProviders();
				builder.Logging.AddSerilog(Logger);
				builder.Services.AddSingleton(Logger);
			}

			builder.Services.AddControllers();
			builder.Services.AddOpenApi();
			builder.Services.AddCors(options =>
			{
				options.AddPolicy("Frontend", policy =>
				{
					var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
						?? ["http://localhost:5107", "https://localhost:7245"];

					policy.WithOrigins(origins)
						.AllowAnyHeader()
						.AllowAnyMethod();
				});
			});
			builder.Services.AddHttpContextAccessor();
			builder.Services.AddHostedService<StartupClass>();

			var outputOptions = CertificateOutputOptions.FromConfiguration(builder.Configuration);
			outputOptions.EnsureDirectories();
			builder.Services.AddSingleton(outputOptions);

			FileManagerCertificate fileManager = new(outputOptions.DatabasePaths, Logger, new ShaManager());
			builder.Services.AddSingleton(fileManager);
			builder.Services.AddSingleton<CertificateCommon.CertificationManager>();

			var app = builder.Build();

			if(app.Environment.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
				app.MapOpenApi();
				app.UseSwaggerUI(options =>
				{
					options.SwaggerEndpoint("/openapi/v1.json", "Certification Backend API v1");
				});
			}

			app.UseCors("Frontend");
			app.UseHttpsRedirection();
			app.UseAuthorization();

			app.MapControllers();

			app.Run();
		}
	}
}

using CertificateCommon;

namespace Certification.Backend.Services
{
	public class StartupClass : IHostedService
	{
		private CertificationManager? Manager { get; init; }
		private Serilog.ILogger? Logger { get; init; }

		public StartupClass(CertificationManager manager, Serilog.ILogger logger)
		{
			Manager = manager;
			Logger = logger.ForContext<StartupClass>();
		}

		public Task StartAsync(CancellationToken cancellationToken)
		{
			string workingPath = AppContext.BaseDirectory;
			Logger?.Information($"Working in {workingPath}");
			Logger?.Information("Starting the backend application");

			if(Manager?.CARoot is null)
			{
				throw new CARootNotFoundException();
			}

			return Task.CompletedTask;
		}

		public Task StopAsync(CancellationToken cancellationToken)
		{
			return Task.CompletedTask;
		}
	}
}

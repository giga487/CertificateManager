
using CertificateCommon;

namespace CertificateManager.src
{
    public class StartupClass : IHostedService
    {
        private CertificationManager? _manager { get; init; }
        private Serilog.ILogger? _logger { get; init; }

        public StartupClass(CertificationManager manager, Serilog.ILogger logger)
        {
            _manager = manager;
            _logger = logger.ForContext<StartupClass>();
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            string workingPath = AppContext.BaseDirectory;
            _logger?.Information($"Working in {workingPath}");
            _logger?.Information("Starting the Application");

            if((_manager?.CARoot is null))
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

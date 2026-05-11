using Microsoft.Extensions.Configuration;

namespace CertificateCommon
{
    public sealed class CertificateOutputOptions
    {
        public const string SectionName = "CertificateOutputs";

        public string[] Outputs { get; init; } = [];
        public string DatabaseFileName { get; init; } = "Certificates.Json";

        public static CertificateOutputOptions FromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection(SectionName);
            var configuredOutputs = section.GetSection("Outputs").GetChildren()
                .Select(output => output.Value)
                .Where(output => !string.IsNullOrWhiteSpace(output))
                .Cast<string>()
                .ToArray();

            var databaseFileName = section.GetSection("DatabaseFileName").Value;
            var options = new CertificateOutputOptions
            {
                Outputs = configuredOutputs,
                DatabaseFileName = string.IsNullOrWhiteSpace(databaseFileName) ? "Certificates.Json" : databaseFileName
            };

            if(options.Outputs.Length == 0)
            {
                var legacyOutput = configuration.GetSection("CertificationManager").GetSection("Output").Value;
                options = new CertificateOutputOptions
                {
                    Outputs = string.IsNullOrWhiteSpace(legacyOutput) ? ["Output"] : [legacyOutput],
                    DatabaseFileName = options.DatabaseFileName
                };
            }

            return options;
        }

        public string PrimaryOutput => Outputs.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "Output";

        public string PrimaryDatabasePath => GetDatabasePath(PrimaryOutput);

        public string[] DatabasePaths => Outputs
            .Where(output => !string.IsNullOrWhiteSpace(output))
            .Select(GetDatabasePath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        public void EnsureDirectories()
        {
            foreach(var output in Outputs.Where(output => !string.IsNullOrWhiteSpace(output)))
            {
                Directory.CreateDirectory(output);
            }
        }

        private string GetDatabasePath(string output)
        {
            return Path.Combine(output, DatabaseFileName);
        }
    }
}

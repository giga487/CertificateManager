using Common;
using Serilog.Events;

namespace CertificateManager.Client
{
    internal class ClientLogMessage : IMemorySinkMessage
    {
        public IMemorySinkMessage Build(LogEvent log)
        {
            return new ClientLogMessage();
        }
    }
}
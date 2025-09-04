using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Common
{
    public interface IMemorySinkMessage
    {
        public IMemorySinkMessage Build(LogEvent log);
    }

    public class MemorySink<TMemoryMessage> : ILogEventSink where TMemoryMessage : IMemorySinkMessage, new()
    {
        private int _maxCount = 100;
        private Utility.LimitedQueue<LogEvent> _queue;
        public void Emit(LogEvent logEvent)
        {
            _queue.Add(logEvent);
        }

        public MemorySink(int maxCount)
        {
            _maxCount = maxCount;
            _queue = new Utility.LimitedQueue<LogEvent>(maxCount);
        }
        public List<LogEvent> Flush()
        {
            return _queue.Flush().ToList();
        }

        public virtual List<TMemoryMessage> Items()
        {
            var list = new List<TMemoryMessage>();
            foreach(var log in _queue.GetItems(true))
            {
                TMemoryMessage message = new TMemoryMessage();
                message.Build(log);

                //var writer = new StringWriter();
                //var formatter = new Serilog.Formatting.Display.MessageTemplateTextFormatter("{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}", null);
                //formatter.Format(log, writer);
                list.Add(message);
            }
            return list;
        }
    }
    public class LoggerBuilder<TMemoryMessage> where TMemoryMessage : IMemorySinkMessage, new()
    {
        public MemorySink<TMemoryMessage> MemorySink { get; protected set; } = new(500);
        public Serilog.ILogger? Logger { get; protected set; }
        public LoggerBuilder(string fileName)
        {
            Console.OutputEncoding = Encoding.UTF8;

            string outputTempalte = "{Timestamp:HH:mm:ss:fff} [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}";
            var configuration = new LoggerConfiguration()
                 .WriteTo.File(fileName,
                     fileSizeLimitBytes: 10 * 1024 * 1024,
                     flushToDiskInterval: TimeSpan.FromSeconds(5),
                     retainedFileCountLimit: 10,
                     outputTemplate: outputTempalte,
                     rollingInterval: RollingInterval.Day)
                 .WriteTo.Console(restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Information, outputTemplate: outputTempalte)
                 .Enrich.WithEnvironmentName()
                 .WriteTo.Sink(MemorySink, LogEventLevel.Information)
                 .WriteTo.BrowserConsole(LogEventLevel.Warning, outputTempalte)
                 .Filter.ByExcluding(Matching.FromSource("Microsoft.AspNetCore"));

            configuration.MinimumLevel.Override("Microsoft.AspNetCore.Hosting.Diagnostics", LogEventLevel.Error);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.Routing.EndpointMiddleware", LogEventLevel.Error);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.DataProtection.KeyManagement.XmlKeyManager", LogEventLevel.Error);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.Mvc.Infrastructure.DefaultActionDescriptorCollectionProvider", LogEventLevel.Error);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.Server.Kestrel", LogEventLevel.Error);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.StaticFiles.StaticFileMiddleware", LogEventLevel.Error);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.Mvc.Infrastructure.ObjectResultExecutor", LogEventLevel.Information);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.Mvc.Infrastructure.ControllerActionInvoker", LogEventLevel.Information);
            configuration.MinimumLevel.Override("Microsoft.AspNetCore.Cors.Infrastructure.CorsService", LogEventLevel.Information);
            
            
            Logger = Log.Logger = configuration.CreateLogger();
        }

        public Serilog.ILogger? GetContext(string name)
        {
            if(Log.Logger is null)
                return null;

            return Log.Logger.ForContext(Serilog.Core.Constants.SourceContextPropertyName, name);
        }
    }
}

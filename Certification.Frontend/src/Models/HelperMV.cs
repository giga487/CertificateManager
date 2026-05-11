using Common.src.Architecture.Interface;
using System.ComponentModel;

namespace CertificateManager.Client.src.Models
{
    public class HelperMV : IViewModel, IAsyncDisposable
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;

        public string Host { get; init; }
        public HelperMV(AppData? appData)
        {
            if(appData?.BaseUrl is null)
                return;

            Host = appData.BaseUrl.AbsoluteUri;
        }


        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }

        public void OnStateChange(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}

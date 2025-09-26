using System.ComponentModel;

namespace Common.src.Architecture.Interface
{

    public interface IViewModel: IAsyncDisposable
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;

        public void OnStateChange(string propertyName);
    }


}

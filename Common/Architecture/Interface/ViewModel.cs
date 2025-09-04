using System.ComponentModel;

namespace Common.src.Architecture.Interface
{

    public interface IViewModel
    {
        public event EventHandler<PropertyChangedEventArgs>? PropertyChanged;

        public void OnStateChange(string propertyName);
    }


}

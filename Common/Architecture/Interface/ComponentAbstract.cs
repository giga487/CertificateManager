using Common.src.Architecture.Interface;
using Microsoft.AspNetCore.Components;
using System.ComponentModel;

namespace Common.src.Architecture.BaseClass
{

    public abstract class Component<T> : ComponentBase, IDisposable where T : IViewModel
    {
        [Inject]
        public T? ViewModel { get; set; }
        [Inject]
        protected Serilog.ILogger? _logger { get; set; }
        private void OnStateChange(object? sender, PropertyChangedEventArgs e)
        {
            StateHasChanged();
        }
        protected override void OnInitialized()
        {
            base.OnInitialized();

            if(ViewModel is not null)
                ViewModel.PropertyChanged += OnStateChange;

            _logger = _logger?.ForContext(Serilog.Core.Constants.SourceContextPropertyName, $"Component<{typeof(T).Name}>");
            _logger?.Information($"Opened the {typeof(T).Name} model view");
        }

        public void Dispose()
        {
            if(ViewModel is not null)
                ViewModel.PropertyChanged -= OnStateChange;
        }
    }
}

using Common.src.Architecture.Interface;
using Microsoft.AspNetCore.Components;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Common.src.Architecture.BaseClass
{

    public abstract class Page<T> : ComponentBase, IDisposable where T : IViewModel
    {
        [Inject]
        [NotNull]
        public T? ViewModel { get; set; }

        [Inject]
        [NotNull]
        protected Serilog.ILogger? _logger { get; set; }
        public void PropertyChanged() => StateHasChanged();

        private void OnStateChange(object? sender, PropertyChangedEventArgs e)
        {
            StateHasChanged();
        }
        protected override void OnInitialized()
        {
            base.OnInitialized();

            if(ViewModel is not null)
                ViewModel.PropertyChanged += OnStateChange;

            _logger = _logger?.ForContext(Serilog.Core.Constants.SourceContextPropertyName, $"Page<{typeof(T).Name}>");
            _logger?.Information($"Opened the {typeof(T).Name} model view");
        }

        public virtual void Dispose()
        {
            if(ViewModel is not null)
                ViewModel.PropertyChanged -= OnStateChange;
        }
    }
}

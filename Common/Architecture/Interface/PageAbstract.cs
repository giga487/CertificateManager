using Common.src.Architecture.Interface;
using Microsoft.AspNetCore.Components;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Common.src.Architecture.BaseClass
{

    public abstract class Page<T> : ComponentBase, IAsyncDisposable where T : IViewModel
    {
        private bool _disposed;

        [Inject]
        [NotNull]
        public T? ViewModel { get; set; }

        [Inject]
        [NotNull]
        protected Serilog.ILogger? _logger { get; set; }
        public void PropertyChanged() => StateHasChanged();

        private void OnStateChange(object? sender, PropertyChangedEventArgs e)
        {
            if(_disposed)
            {
                return;
            }

            _ = InvokeAsync(() =>
            {
                if(!_disposed)
                {
                    StateHasChanged();
                }
            });
        }
        protected override void OnInitialized()
        {
            base.OnInitialized();

            if(ViewModel is not null)
                ViewModel.PropertyChanged += OnStateChange;

            _logger = _logger?.ForContext(Serilog.Core.Constants.SourceContextPropertyName, $"Page<{typeof(T).Name}>");
            _logger?.Information($"Opened the {typeof(T).Name} model view");
        }

        public async ValueTask DisposeAsync()
        {
            if(_disposed)
            {
                return;
            }

            _disposed = true;

            if(ViewModel is not null)
            {
                ViewModel.PropertyChanged -= OnStateChange;
                try
                {
                    await ViewModel.DisposeAsync();
                }
                catch(Exception ex)
                {
                    _logger?.Warning(ex, "Error disposing the {ViewModel} model view", typeof(T).Name);
                }
            }

        }
    }
}

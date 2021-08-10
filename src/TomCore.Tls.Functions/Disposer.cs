using System;
using System.Threading.Tasks;

namespace TomCore.Tls.Functions
{
    internal class Disposer : IAsyncDisposable
    {
        private readonly Func<Task> _disposeFunc;

        public Disposer(Func<Task> disposeFunc)
        {
            _disposeFunc = disposeFunc;
        }

        public ValueTask DisposeAsync()
        {
            return new(_disposeFunc());
        }
    }
}
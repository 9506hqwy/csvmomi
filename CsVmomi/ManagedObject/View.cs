namespace CsVmomi;

public partial class View : ManagedObject, IAsyncDisposable, IDisposable
{
    private bool disposed;

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        await this.DisposeAsyncCore().ConfigureAwait(false);
        this.Dispose(false);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !this.disposed)
        {
            this.DestroyView().Wait();
            this.disposed = true;
        }
    }

    protected virtual async ValueTask DisposeAsyncCore()
    {
        if (!this.disposed)
        {
            await this.DestroyView().ConfigureAwait(false);
            this.disposed = true;
        }
    }
}

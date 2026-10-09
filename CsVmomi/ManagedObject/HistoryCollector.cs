namespace CsVmomi;

public partial class HistoryCollector : ManagedObject, IAsyncDisposable, IDisposable
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
            this.DestroyCollector().Wait();
            this.disposed = true;
        }
    }

    protected virtual async ValueTask DisposeAsyncCore()
    {
        if (!this.disposed)
        {
            await this.DestroyCollector().ConfigureAwait(false);
            this.disposed = true;
        }
    }
}

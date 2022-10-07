namespace CsVmomi;

public partial class PropertyFilter : ManagedObject, IAsyncDisposable, IDisposable
{
    private bool disposed = false;

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        await this.DisposeAsyncCore();
        this.Dispose(false);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !this.disposed)
        {
            this.DestroyPropertyFilter().Wait();
            this.disposed = true;
        }
    }

    protected async virtual ValueTask DisposeAsyncCore()
    {
        if (!this.disposed)
        {
            await this.DestroyPropertyFilter();
            this.disposed = true;
        }
    }
}

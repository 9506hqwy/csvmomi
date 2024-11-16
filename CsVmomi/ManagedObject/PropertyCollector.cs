namespace CsVmomi;

public partial class PropertyCollector : ManagedObject, IAsyncDisposable, IDisposable
{
    private bool disposed = false;

    public async Task<PropertyFilter?> CreateFilter(
        ManagedObject obj,
        string pathSet,
        bool partialUpdates)
    {
        var specSet = this.CreatePropertyFilterSpec(obj, pathSet);
        return await this.CreateFilter(specSet, partialUpdates);
    }

    public async Task<PropertyFilter?> CreateFilter(
        ManagedObject obj,
        bool all,
        string[]? pathSet,
        bool reportMissingObjectsInResults,
        bool partialUpdates)
    {
        var specSet = this.CreatePropertyFilterSpec(obj, all, pathSet, reportMissingObjectsInResults);
        return await this.CreateFilter(specSet, partialUpdates);
    }

    public async Task<PropertyFilter?> CreateFilter(
        ObjectSpec objectSet,
        PropertySpec propSet,
        bool reportMissingObjectsInResults,
        bool partialUpdates)
    {
        var specSet = this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
        return await this.CreateFilter(specSet, partialUpdates);
    }

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

    public async Task<T?> RetrieveProperties<T>(
        ManagedObject obj,
        string pathSet)
    {
        var specSet = this.CreatePropertyFilterSpec(obj, pathSet);
        var contents = await this.RetrieveProperties(specSet);
        return contents.First().GetPropertyValue<T>(pathSet);
    }

    public async Task<ObjectContent> RetrieveProperties(
        ManagedObject obj,
        bool all,
        string[]? pathSet,
        bool reportMissingObjectsInResults)
    {
        var specSet = this.CreatePropertyFilterSpec(obj, all, pathSet, reportMissingObjectsInResults);
        var contents = await this.RetrieveProperties(specSet);
        return contents.First();
    }

    public async Task<ObjectContent[]?> RetrieveProperties(
        ObjectSpec objectSet,
        PropertySpec propSet,
        bool reportMissingObjectsInResults)
    {
        var specSet = this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
        return await this.RetrieveProperties(specSet);
    }

    public async Task<ObjectContent[]?> RetrieveProperties(PropertyFilterSpec specSet)
    {
        return await this.RetrieveProperties([specSet]);
    }

    public async Task<RetrieveResult?> RetrievePropertiesEx(
        ObjectSpec objectSet,
        PropertySpec propSet,
        bool reportMissingObjectsInResults,
        RetrieveOptions options)
    {
        var specSet = this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
        return await this.RetrievePropertiesEx(specSet, options);
    }

    public async Task<RetrieveResult?> RetrievePropertiesEx(PropertyFilterSpec specSet, RetrieveOptions options)
    {
        return await this.RetrievePropertiesEx([specSet], options);
    }

    internal IAsyncEnumerable<T> Enumerate<T>(
        ObjectSpec objectSet,
        PropertySpec propSet,
        bool reportMissingObjectsInResults,
        RetrieveOptions options,
        Func<ObjectContent, bool>? condition = null)
        where T : ManagedObject
    {
        var specSet = this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
        return this.Enumerate<T>(specSet, options, condition);
    }

    internal IAsyncEnumerable<T> Enumerate<T>(
        PropertyFilterSpec specSet, RetrieveOptions options, Func<ObjectContent, bool>? condition = null)
        where T : ManagedObject
    {
        return this.Enumerate<T>([specSet], options, condition);
    }

    internal async IAsyncEnumerable<T> Enumerate<T>(
        PropertyFilterSpec[] specSet, RetrieveOptions options, Func<ObjectContent, bool>? condition = null)
        where T : ManagedObject
    {
        string? token = null;
        try
        {
            var result = await this.Session.PropertyCollector.RetrievePropertiesEx(specSet, options);
            if (result == null)
            {
                yield break;
            }

            token = result.token;
            foreach (var obj in result.objects)
            {
                if (condition == null || condition(obj))
                {
                    yield return ManagedObject.Create<T>(obj.obj, this.Session)!;
                }
            }

            while (token != null)
            {
                result = await this.Session.PropertyCollector.ContinueRetrievePropertiesEx(token);
                token = result!.token;
                foreach (var obj in result.objects)
                {
                    if (condition == null || condition(obj))
                    {
                        yield return ManagedObject.Create<T>(obj.obj, this.Session)!;
                    }
                }
            }
        }
        finally
        {
            if (token != null)
            {
                await this.Session.PropertyCollector.CancelRetrievePropertiesEx(token);
            }
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !this.disposed)
        {
            this.DestroyPropertyCollector().Wait();
            this.disposed = true;
        }
    }

    protected virtual async ValueTask DisposeAsyncCore()
    {
        if (!this.disposed)
        {
            await this.DestroyPropertyCollector();
            this.disposed = true;
        }
    }

    private PropertyFilterSpec CreatePropertyFilterSpec(
        ManagedObject obj,
        string pathSet)
    {
        return this.CreatePropertyFilterSpec(obj, false, [pathSet], false);
    }

    private PropertyFilterSpec CreatePropertyFilterSpec(
        ManagedObject obj,
        bool all,
        string[]? pathSet,
        bool reportMissingObjectsInResults)
    {
        var objectSet = new ObjectSpec
        {
            obj = obj.VimReference,
            selectSet = null,
            skip = false,
            skipSpecified = true,
        };

        var propSet = new PropertySpec
        {
            all = all,
            allSpecified = true,
            pathSet = pathSet,
            type = obj.VimReference.type,
        };

        return this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
    }

    private PropertyFilterSpec CreatePropertyFilterSpec(
        ObjectSpec objectSet,
        PropertySpec propSet,
        bool reportMissingObjectsInResults)
    {
        return new PropertyFilterSpec
        {
            objectSet = [objectSet],
            propSet = [propSet],
            reportMissingObjectsInResults = reportMissingObjectsInResults,
            reportMissingObjectsInResultsSpecified = true,
        };
    }
}

namespace CsVmomi;

public partial class ManagedEntity : ExtensibleManagedObject
{
    public IAsyncEnumerable<T> Enumerate<T>()
        where T : ManagedEntity
    {
        return this.Enumerate<T>(null, null);
    }

    public IAsyncEnumerable<T> EnumerateUpper<T>()
        where T : ManagedEntity
    {
        return this.EnumerateUpper<T>(null, null);
    }

    public async System.Threading.Tasks.Task<T?> FindByName<T>(string name)
        where T : ManagedEntity
    {
        const string NAME = "name";

        Func<ObjectContent, bool> isMatch =
            o => o.GetPropertyValue<string>(NAME)!.ToLowerInvariant() == name.ToLowerInvariant();

        await foreach (var entity in this.Enumerate<T>(new[] { NAME }, isMatch))
        {
            return entity;
        }

        return null;
    }

    public async System.Threading.Tasks.Task<T?> FindFirst<T>()
        where T : ManagedEntity
    {
        await foreach (var entity in this.Enumerate<T>())
        {
            return entity;
        }

        return null;
    }

    public async System.Threading.Tasks.Task<T?> FindFirstUpper<T>()
        where T : ManagedEntity
    {
        await foreach (var entity in this.EnumerateUpper<T>())
        {
            return entity;
        }

        return null;
    }

    private IAsyncEnumerable<T> Enumerate<T>(string[]? pathSet, Func<ObjectContent, bool>? condition)
        where T : ManagedEntity
    {
        var helper = new PropertyFilterHelper();
        var objectSet = helper.TraverseChild(this);

        return this.Enumerate<T>(objectSet, pathSet, condition);
    }

    private async IAsyncEnumerable<T> Enumerate<T>(ObjectSpec objectSet, string[]? pathSet, Func<ObjectContent, bool>? condition)
        where T : ManagedEntity
    {
        var propSet = new PropertySpec
        {
            all = false,
            allSpecified = true,
            pathSet = pathSet,
            type = typeof(T).Name,
        };

        var options = new RetrieveOptions
        {
            maxObjects = 20,
            maxObjectsSpecified = true,
        };

        await foreach (var entity in this.Session.PropertyCollector.Enumerate<T>(objectSet, propSet, false, options, condition))
        {
            yield return entity;
        }
    }

    private IAsyncEnumerable<T> EnumerateUpper<T>(string[]? pathSet, Func<ObjectContent, bool>? condition)
        where T : ManagedEntity
    {
        var helper = new PropertyFilterHelper();
        var objectSet = helper.TraverseParent(this);

        return this.Enumerate<T>(objectSet, pathSet, condition);
    }
}

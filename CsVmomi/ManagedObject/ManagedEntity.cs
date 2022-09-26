namespace CsVmomi;

public partial class ManagedEntity : ExtensibleManagedObject
{
    public IAsyncEnumerable<T> Enumerate<T>()
        where T : ManagedObject
    {
        return this.Enumerate<T>(null, null);
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

    private async IAsyncEnumerable<T> Enumerate<T>(string[]? pathSet, Func<ObjectContent, bool>? condition)
        where T : ManagedObject
    {
        var view = await this.Session.ViewManager!.CreateContainerView(
            this,
            new[] { $"vim.{typeof(T).Name}" },
            true);
        string? token = null;
        try
        {
            var viewSpec = new TraversalSpec
            {
                name = "viewSpec",
                path = "view",
                selectSet = null,
                skip = false,
                skipSpecified = true,
                type = view!.Reference.type,
            };

            var objectSet = new ObjectSpec
            {
                obj = view.Reference,
                selectSet = new[] { viewSpec },
                skip = true,
                skipSpecified = true,
            };

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

            var result = await this.Session.PropertyCollector.RetrievePropertiesEx(objectSet, propSet, false, options);
            token = result!.token;
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

            await view!.DestroyView();
        }
    }
}

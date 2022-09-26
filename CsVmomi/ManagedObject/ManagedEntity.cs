namespace CsVmomi;

using VimService;

public partial class ManagedEntity : ExtensibleManagedObject
{
    public async IAsyncEnumerable<T> EnumerateManagedObject<T>()
        where T : ManagedObject
    {
        var view = await this.Session.ViewManager.CreateContainerView(
            this,
            new[] { $"vim.{typeof(T).Name}" },
            true);
        string token = null;
        try
        {
            var viewSpec = new TraversalSpec
            {
                name = "viewSpec",
                path = "view",
                selectSet = null,
                skip = false,
                skipSpecified = true,
                type = view.Reference.type,
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
                pathSet = null,
                type = typeof(T).Name,
            };

            var options = new RetrieveOptions
            {
                maxObjects = 20,
                maxObjectsSpecified = true,
            };

            var result = await this.Session.PropertyCollector.RetrievePropertiesEx(objectSet, propSet, false, options);
            token = result.token;
            foreach (var obj in result.objects)
            {
                yield return ManagedObject.Create<T>(obj.obj, this.Session);
            }

            while (token != null)
            {
                result = await this.Session.PropertyCollector.ContinueRetrievePropertiesEx(token);
                token = result.token;
                foreach (var obj in result.objects)
                {
                    yield return ManagedObject.Create<T>(obj.obj, this.Session);
                }
            }
        }
        finally
        {
            if (token != null)
            {
                await this.Session.PropertyCollector.CancelRetrievePropertiesEx(token);
            }

            await view.DestroyView();
        }
    }
}

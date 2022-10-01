namespace CsVmomi;

internal class PropertyFilterHelper
{
    private readonly IDictionary<string, TraversalSpec> cache;

    internal PropertyFilterHelper()
    {
        this.cache = new Dictionary<string, TraversalSpec>();
    }

    internal ObjectSpec TraverseChild<T>(T source)
        where T : ManagedEntity
    {
        return new ObjectSpec
        {
            obj = source.Reference,
            selectSet = this.CreateFrom(source),
            skip = true,
            skipSpecified = true,
        };
    }

    private SelectionSpec[] CreateFrom<T>(T source)
        where T : ManagedEntity
    {
        return source switch
        {
            ComputeResource _ => this.CreateComputeResource(),
            Datacenter _ => this.CreateDatacenter(),
            Datastore _ => this.CreateDatastore(),
            DistributedVirtualSwitch _ => this.CreateDistributedVirtualSwitch(),
            Folder _ => this.CreateFolder(),
            HostSystem _ => this.CreateHostSystem(),
            Network _ => this.CreateNetwork(),
            ResourcePool _ => this.CreateResourcePool(),
            _ => throw new NotSupportedException(),
        };
    }

    private SelectionSpec[] CreateComputeResource()
    {
        var datastore = this.InitSpec(typeof(ComputeResource), "datastore");
        this.SetSelectSet(datastore, this.CreateDatastore);

        var host = this.InitSpec(typeof(ComputeResource), "host");
        this.SetSelectSet(host, this.CreateHostSystem);

        var network = this.InitSpec(typeof(ComputeResource), "network");
        this.SetSelectSet(network, this.CreateNetwork);

        var resourcePool = this.InitSpec(typeof(ComputeResource), "resourcePool");
        this.SetSelectSet(resourcePool, this.CreateResourcePool);

        return new[] { datastore, host, network, resourcePool };
    }

    private SelectionSpec[] CreateDatacenter()
    {
        var datastoreFolder = this.InitSpec(typeof(Datacenter), "datastoreFolder");
        this.SetSelectSet(datastoreFolder, this.CreateFolder);

        var hostFolder = this.InitSpec(typeof(Datacenter), "hostFolder");
        this.SetSelectSet(hostFolder, this.CreateFolder);

        var networkFolder = this.InitSpec(typeof(Datacenter), "networkFolder");
        this.SetSelectSet(networkFolder, this.CreateFolder);

        var vmFolder = this.InitSpec(typeof(Datacenter), "vmFolder");
        this.SetSelectSet(vmFolder, this.CreateFolder);

        return new[] { datastoreFolder, hostFolder, networkFolder, vmFolder };
    }

    private SelectionSpec[] CreateDatastore()
    {
        return new[] { this.InitSpec(typeof(Datastore), "vm") };
    }

    private SelectionSpec[] CreateDistributedVirtualSwitch()
    {
        var portgroup = this.InitSpec(typeof(DistributedVirtualSwitch), "portgroup");
        this.SetSelectSet(portgroup, this.CreateNetwork);

        return new[] { portgroup };
    }

    private SelectionSpec[] CreateFolder()
    {
        var selectSet = () => this.CreateFolder()
            .Concat(this.CreateComputeResource())
            .Concat(this.CreateDatacenter())
            .Concat(this.CreateDatastore())
            .Concat(this.CreateDistributedVirtualSwitch())
            .Concat(this.CreateNetwork())
            .ToArray();

        var folder = this.InitSpec(typeof(Folder), "childEntity");
        this.SetSelectSet(folder, selectSet);

        return new[] { folder };
    }

    private SelectionSpec[] CreateHostSystem()
    {
        var datastore = this.InitSpec(typeof(HostSystem), "datastore");
        this.SetSelectSet(datastore, this.CreateDatastore);

        var network = this.InitSpec(typeof(HostSystem), "network");
        this.SetSelectSet(network, this.CreateNetwork);

        var vm = this.InitSpec(typeof(HostSystem), "vm");

        return new[] { datastore, network, vm };
    }

    private SelectionSpec[] CreateNetwork()
    {
        return new[] { this.InitSpec(typeof(Network), "vm") };
    }

    private SelectionSpec[] CreateResourcePool()
    {
        var resourcePool = this.InitSpec(typeof(ResourcePool), "resourcePool");
        this.SetSelectSet(resourcePool, this.CreateResourcePool);

        var vm = this.InitSpec(typeof(ResourcePool), "vm");

        return new[] { resourcePool, vm };
    }

    private SelectionSpec InitSelection(string name)
    {
        return new SelectionSpec
        {
            name = name,
        };
    }

    private SelectionSpec InitSpec(Type type, string? path)
    {
        var name = $"{type.Name}Spec{path}";
        return this.cache.ContainsKey(name)
            ? this.InitSelection(name)
            : this.InitTraversal(name, type.Name, path);
    }

    private TraversalSpec InitTraversal(string name, string type, string? path)
    {
        var spec = new TraversalSpec
        {
            name = name,
            path = path,
            selectSet = null,
            skip = false,
            skipSpecified = true,
            type = type,
        };
        this.cache.Add(spec.name, spec);
        return spec;
    }

    private void SetSelectSet(SelectionSpec spec, Func<SelectionSpec[]> selectSet)
    {
        if (spec is TraversalSpec t)
        {
            t.selectSet = selectSet();
        }
    }
}

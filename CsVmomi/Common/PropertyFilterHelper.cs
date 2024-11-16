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
            obj = source.VimReference,
            selectSet = this.TraverseLower(source),
            skip = true,
            skipSpecified = true,
        };
    }

    internal ObjectSpec TraverseParent<T>(T source)
        where T : ManagedEntity
    {
        return new ObjectSpec
        {
            obj = source.VimReference,
            selectSet = this.TraverseUpper(source),
            skip = true,
            skipSpecified = true,
        };
    }

    private SelectionSpec[] CreateComputeResourceLower()
    {
        var datastore = this.InitSpec(typeof(ComputeResource), "datastore");
        this.SetSelectSet(datastore, this.CreateDatastoreLower);

        var host = this.InitSpec(typeof(ComputeResource), "host");
        this.SetSelectSet(host, this.CreateHostSystemLower);

        var network = this.InitSpec(typeof(ComputeResource), "network");
        this.SetSelectSet(network, this.CreateNetworkLower);

        var resourcePool = this.InitSpec(typeof(ComputeResource), "resourcePool");
        this.SetSelectSet(resourcePool, this.CreateResourcePoolLower);

        return [datastore, host, network, resourcePool];
    }

    private SelectionSpec[] CreateDatacenterLower()
    {
        var datastoreFolder = this.InitSpec(typeof(Datacenter), "datastoreFolder");
        this.SetSelectSet(datastoreFolder, this.CreateFolderLower);

        var hostFolder = this.InitSpec(typeof(Datacenter), "hostFolder");
        this.SetSelectSet(hostFolder, this.CreateFolderLower);

        var networkFolder = this.InitSpec(typeof(Datacenter), "networkFolder");
        this.SetSelectSet(networkFolder, this.CreateFolderLower);

        var vmFolder = this.InitSpec(typeof(Datacenter), "vmFolder");
        this.SetSelectSet(vmFolder, this.CreateFolderLower);

        return [datastoreFolder, hostFolder, networkFolder, vmFolder];
    }

    private SelectionSpec[] CreateDatastoreLower()
    {
        return [this.InitSpec(typeof(Datastore), "vm")];
    }

    private SelectionSpec[] CreateDatastoreUpper()
    {
        return [this.InitSpec(typeof(Datastore), "host")];
    }

    private SelectionSpec[] CreateDistributedVirtualSwitchLower()
    {
        var portgroup = this.InitSpec(typeof(DistributedVirtualSwitch), "portgroup");
        this.SetSelectSet(portgroup, this.CreateNetworkLower);

        return [portgroup];
    }

    private SelectionSpec[] CreateFolderLower()
    {
        var selectSet = () => this.CreateFolderLower()
            .Concat(this.CreateComputeResourceLower())
            .Concat(this.CreateDatacenterLower())
            .Concat(this.CreateDatastoreLower())
            .Concat(this.CreateDistributedVirtualSwitchLower())
            .Concat(this.CreateNetworkLower())
            .ToArray();

        var folder = this.InitSpec(typeof(Folder), "childEntity");
        this.SetSelectSet(folder, selectSet);

        return [folder];
    }

    private SelectionSpec[] CreateHostSystemLower()
    {
        var datastore = this.InitSpec(typeof(HostSystem), "datastore");
        this.SetSelectSet(datastore, this.CreateDatastoreLower);

        var network = this.InitSpec(typeof(HostSystem), "network");
        this.SetSelectSet(network, this.CreateNetworkLower);

        var vm = this.InitSpec(typeof(HostSystem), "vm");

        return [datastore, network, vm];
    }

    private SelectionSpec[] CreateManagedEntityUpper()
    {
        var parent = this.InitSpec(typeof(ManagedEntity), "parent");
        this.SetSelectSet(parent, this.CreateManagedEntityUpper);

        return [parent];
    }

    private SelectionSpec[] CreateNetworkLower()
    {
        return [this.InitSpec(typeof(Network), "vm")];
    }

    private SelectionSpec[] CreateNetworkUpper()
    {
        var host = this.InitSpec(typeof(Network), "host");

        var sw = this.InitSpec(typeof(DistributedVirtualPortgroup), "config.distributedVirtualSwitch");

        return [host, sw];
    }

    private SelectionSpec[] CreateResourcePoolLower()
    {
        var resourcePool = this.InitSpec(typeof(ResourcePool), "resourcePool");
        this.SetSelectSet(resourcePool, this.CreateResourcePoolLower);

        var vm = this.InitSpec(typeof(ResourcePool), "vm");

        return [resourcePool, vm];
    }

    private SelectionSpec[] CreateVirtualMachineUpper()
    {
        var datastore = this.InitSpec(typeof(VirtualMachine), "datastore");
        this.SetSelectSet(datastore, this.CreateDatastoreUpper);

        var network = this.InitSpec(typeof(VirtualMachine), "network");
        this.SetSelectSet(datastore, this.CreateNetworkUpper);

        var parentVApp = this.InitSpec(typeof(VirtualMachine), "parentVApp");

        var resourcePool = this.InitSpec(typeof(VirtualMachine), "resourcePool");

        var host = this.InitSpec(typeof(VirtualMachine), "runtime.host");

        return [datastore, network, parentVApp, resourcePool, host];
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

    private SelectionSpec[] TraverseLower<T>(T source)
        where T : ManagedEntity
    {
        return source switch
        {
            ComputeResource => this.CreateComputeResourceLower(),
            Datacenter => this.CreateDatacenterLower(),
            Datastore => this.CreateDatastoreLower(),
            DistributedVirtualSwitch => this.CreateDistributedVirtualSwitchLower(),
            Folder => this.CreateFolderLower(),
            HostSystem => this.CreateHostSystemLower(),
            Network => this.CreateNetworkLower(),
            ResourcePool => this.CreateResourcePoolLower(),
            _ => throw new NotSupportedException(),
        };
    }

    private SelectionSpec[] TraverseUpper<T>(T source)
        where T : ManagedEntity
    {
        var entity = this.CreateManagedEntityUpper();

        return source switch
        {
            ComputeResource => entity,
            Datacenter => entity,
            Datastore => [.. entity, .. this.CreateDatastoreUpper()],
            DistributedVirtualSwitch => entity,
            Folder => entity,
            HostSystem => entity,
            Network => [.. entity, .. this.CreateNetworkUpper()],
            ResourcePool => entity,
            VirtualMachine => [.. entity, .. this.CreateVirtualMachineUpper()],
            _ => throw new NotSupportedException(),
        };
    }

    private void SetSelectSet(SelectionSpec spec, Func<SelectionSpec[]> selectSet)
    {
        if (spec is TraversalSpec t)
        {
            t.selectSet = selectSet();
        }
    }
}

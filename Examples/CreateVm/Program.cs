using CsVmomi;
using VimService;

try
{
    await Work(args);
}
catch (Exception e)
{
    await Console.Error.WriteLineAsync(string.Format("{0}", e));
}

async System.Threading.Tasks.Task Work(string[] args)
{
    if (args.Length < 6)
    {
        // GUESTOS
        // https://vdc-download.vmware.com/vmwb-repository/dcr-public/bf660c0a-f060-46e8-a94d-4b5e6ffc77ad/208bc706-e281-49b6-a0ce-b402ec19ef82/SDK/vsphere-ws/docs/ReferenceGuide/vim.vm.GuestOsDescriptor.GuestOsIdentifier.html
        await Console.Error.WriteLineAsync("CreateVm URL USERNAME PASSWORD HOSTNAME VMNAME GUESTOS [DATASTORE]");
        return;
    }

    if (!Uri.TryCreate(args[0], UriKind.Absolute, out var url))
    {
        await Console.Error.WriteLineAsync("URL is invalid format.");
        return;
    }

    var session = await Session.Get(url);
    session.MessageToolBox.Fixup = Fixup.FixupNamespaceNotPreserve();
    _ = await session.SessionManager!.Login(args[1], args[2]);
    try
    {
        var host = await session.RootFolder.FindByName<HostSystem>(args[3]) ?? throw new Exception($"Not found ESXi `{args[3]}`.");
        var vmName = args[4];

        var clusterResource = (await host.GetPropertyParent()) as ComputeResource;
        var resoucePool = await clusterResource!.GetPropertyResourcePool();

        var envBrowser = await clusterResource!.GetPropertyEnvironmentBrowser();
        var configDescriptor = (await envBrowser!.QueryConfigOptionDescriptor())!.First(d => d.defaultConfigOption);
        var configOption = await envBrowser.QueryConfigOption(configDescriptor.key, null);
        var osDescriptor = configOption!.guestOSDescriptor.FirstOrDefault(d => d.id == args[5]) ?? throw new Exception($"Not found Guest OS `{args[5]}`.");
        var datastore = args.Length switch
        {
            int n when n < 7 => await host.FindFirst<Datastore>(),
            _ => await host.FindByName<Datastore>(args[6]),
        } ?? throw new Exception($"Not found datastore.");
        await CreateVm(resoucePool!, host, vmName, datastore, osDescriptor);

        await Console.Out.WriteLineAsync("Success.");
    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

async System.Threading.Tasks.Task CreateVm(
    ResourcePool pool,
    HostSystem host,
    string vmName,
    Datastore datastore,
    GuestOsDescriptor osDescriptor)
{
    int deviceKey = 0;

    var dsName = await datastore.GetPropertyName();

    var devices = new List<VirtualDeviceConfigSpec>();
    if (osDescriptor.usbRecommended)
    {
        var ctrl = CreateController(osDescriptor.recommendedUSBController.Replace("vim.", ""), --deviceKey);
        devices.Add(ctrl);
    }

    {
        var ctrl = CreateController(osDescriptor.recommendedCdromController.Replace("vim.", ""), --deviceKey);
        devices.Add(ctrl);

        var dev = CreateCdrom(--deviceKey, ctrl.device.key);
        devices.Add(dev);
    }

    var spec = new VirtualMachineConfigSpec
    {
        deviceChange = [.. devices],
        files = new VirtualMachineFileInfo
        {
            vmPathName = $"[{dsName}] {vmName}/{vmName}.vmx",
        },
        firmware = osDescriptor.recommendedFirmware,
        guestId = osDescriptor.id,
        memoryMB = osDescriptor.recommendedMemMB,
        memoryMBSpecified = true,
        name = vmName,
        numCoresPerSocket = osDescriptor.numRecommendedCoresPerSocket,
        numCoresPerSocketSpecified = true,
        numCPUs = osDescriptor.numRecommendedPhysicalSockets,
        numCPUsSpecified = true,
        virtualICH7MPresent = osDescriptor.ich7mRecommended,
        virtualICH7MPresentSpecified = true,
        virtualSMCPresent = osDescriptor.smcRecommended,
        virtualSMCPresentSpecified = true,
    };

    var datacenter = await host.FindFirstUpper<Datacenter>();
    var vmFolder = await datacenter!.GetPropertyVmFolder();

    var task = await vmFolder.CreateVM_Task(spec, pool, host);
    var state = await task!.WaitForCompleted(TimeSpan.FromSeconds(1800));
    if (state == TaskInfoState.error)
    {
        var error = await task.GetProperty<LocalizedMethodFault>("info.error");
        throw new Exception(error!.localizedMessage);
    }
}

VirtualDeviceConfigSpec CreateCdrom(int key, int controllerKey)
{
    var dev = new VirtualCdrom
    {
        backing = new VirtualCdromAtapiBackingInfo
        {
            deviceName = string.Empty,
            useAutoDetect = true,
            useAutoDetectSpecified = true,
        },
        controllerKey = controllerKey,
        controllerKeySpecified = true,
        key = key,
    };

    return new VirtualDeviceConfigSpec
    {
        device = dev,
        operation = VirtualDeviceConfigSpecOperation.add,
        operationSpecified = true,
    };
}

VirtualDeviceConfigSpec CreateController(string controllerType, int key)
{
    var type = typeof(VirtualController).Assembly.GetTypes()
        .Where(t => typeof(VirtualController).IsAssignableFrom(t))
        .First(t => t.Name == controllerType);

    var ctrl = (VirtualController)Activator.CreateInstance(type)!;
    ctrl.key = key;

    return new VirtualDeviceConfigSpec
    {
        device = ctrl,
        operation = VirtualDeviceConfigSpecOperation.add,
        operationSpecified = true,
    };
}

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
    if (args.Length < 4)
    {
        await Console.Error.WriteLineAsync("AddVmNic URL USERNAME PASSWORD VMNAME [NETWORK]");
        return;
    }

    if (!Uri.TryCreate(args[0], UriKind.Absolute, out var url))
    {
        await Console.Error.WriteLineAsync("URL is invalid format.");
        return;
    }

    var session = await Session.Get(url);
    session.MessageToolBox.Fixup = Fixup.FixupNamespaceNotPreserve();
    await session.SessionManager!.Login(args[1], args[2]);
    try
    {
        var vm = await session.RootFolder.FindByName<VirtualMachine>(args[3]);
        if (vm == null)
        {
            throw new Exception($"Not found virtual machine `{args[3]}`.");
        }

        var host = await vm.FindFirstUpper<HostSystem>();

        var network = args.Length switch
        {
            int n when n < 5 => await host!.FindFirst<Network>(),
            _ => await host!.FindByName<Network>(args[4]),
        };
        if (network == null)
        {
            throw new Exception($"Not found network.");
        }

        var guestId = await vm.GetProperty<string>("config.guestId");

        var hwVersion = await vm.GetProperty<string>("config.version");

        var envBrowser = await vm.GetPropertyEnvironmentBrowser();
        var configOption = await envBrowser.QueryConfigOption(hwVersion, null);
        var osDescriptor = configOption!.guestOSDescriptor.FirstOrDefault(d => d.id == guestId);

        var type = typeof(VirtualEthernetCard).Assembly.GetTypes()
            .Where(t => typeof(VirtualEthernetCard).IsAssignableFrom(t))
            .First(t => t.Name == osDescriptor!.recommendedEthernetCard.Replace("vim.", ""));

        var nic = (VirtualEthernetCard)Activator.CreateInstance(type)!;
        nic.connectable = new VirtualDeviceConnectInfo
        {
            connected = true,
            startConnected = true,
        };
        nic.key = -1;

        switch (network)
        {
            case DistributedVirtualPortgroup dvp:
                var dvs = await dvp.FindFirstUpper<DistributedVirtualSwitch>();
                nic.backing = new VirtualEthernetCardDistributedVirtualPortBackingInfo
                {
                    port = new DistributedVirtualSwitchPortConnection
                    {
                        portgroupKey = await dvp.GetPropertyKey(),
                        switchUuid = await dvs!.GetPropertyUuid(),
                    },
                };
                break;
            case OpaqueNetwork on:
                var name = await on.GetPropertyName();
                var nws = await host.GetProperty<HostOpaqueNetworkInfo[]>("config.network.opaqueNetwork");
                var nw = nws!.First(n => n.opaqueNetworkName == name);
                nic.backing = new VirtualEthernetCardOpaqueNetworkBackingInfo
                {
                    opaqueNetworkId = nw.opaqueNetworkId,
                    opaqueNetworkType = nw.opaqueNetworkType,
                };
                break;
            default:
                nic.backing = new VirtualEthernetCardNetworkBackingInfo
                {
                    deviceName = await network.GetPropertyName(),
                };
                break;
        }

        var change = new VirtualDeviceConfigSpec
        {
            device = nic,
            operation = VirtualDeviceConfigSpecOperation.add,
            operationSpecified = true,
        };

        var spec = new VirtualMachineConfigSpec
        {
            deviceChange = new[] { change },
        };

        var task = await vm.ReconfigVM_Task(spec);
        var state = await task!.WaitForCompleted(TimeSpan.FromSeconds(300));
        if (state == TaskInfoState.error)
        {
            var error = await task.GetProperty<LocalizedMethodFault>("info.error");
            throw new Exception(error!.localizedMessage);
        }

        await Console.Out.WriteLineAsync("Success.");

    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

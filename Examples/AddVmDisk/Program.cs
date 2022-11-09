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
    if (args.Length < 5)
    {
        await Console.Error.WriteLineAsync("AddVmDisk URL USERNAME PASSWORD VMNAME SIZE [DATASTORE]");
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

        var vmName = await vm.GetPropertyName();

        if (!int.TryParse(args[4], out var size) || size < 1)
        {
            throw new Exception($"Invalid value `{args[4]}`.");
        }

        var host = await vm.FindFirstUpper<HostSystem>();
        var datastore = args.Length switch
        {
            int n when n < 6 => await host!.FindFirst<Datastore>(),
            _ => await host!.FindByName<Datastore>(args[5]),
        };
        if (datastore == null)
        {
            throw new Exception($"Not found datastore.");
        }

        var datastoreName = await datastore.GetPropertyName();

        (var guestId, var hwVersion, var devices) =
            await vm.GetProperty<string, string, VirtualDevice[]>(
                "config.guestId", "config.version", "config.hardware.device");

        var envBrowser = await vm.GetPropertyEnvironmentBrowser();
        var configOption = await envBrowser.QueryConfigOption(hwVersion, null);
        var osDescriptor = configOption!.guestOSDescriptor.FirstOrDefault(d => d.id == guestId);
        var hwOptions = configOption.hardwareOptions.virtualDeviceOption
            .OfType<VirtualControllerOption>()
            .FirstOrDefault(o => o.type == osDescriptor!.recommendedDiskController);

        var type = typeof(VirtualController).Assembly.GetTypes()
            .Where(t => typeof(VirtualController).IsAssignableFrom(t))
            .First(t => t.Name == osDescriptor!.recommendedDiskController.Replace("vim.", ""));

        int deviceKey = 0;
        var deviceChange = new List<VirtualDeviceConfigSpec>();

        var ctrl = devices!
            .Where(d => type.IsAssignableFrom(d.GetType()))
            .FirstOrDefault(d => devices!.Count(c => c.controllerKey == d.key) < hwOptions!.devices.max);
        if (ctrl == null)
        {
            ctrl = (VirtualController)Activator.CreateInstance(type)!;
            ctrl.key = --deviceKey;
            deviceChange.Add(new VirtualDeviceConfigSpec
            {
                device = ctrl,
                operation = VirtualDeviceConfigSpecOperation.add,
                operationSpecified = true,
            });
        }

        var units = devices!.Where(d => d.controllerKey == ctrl.key).Select(d => d.unitNumber).ToList();
        if (hwOptions is VirtualSCSIControllerOption option)
        {
            units.Add(option.scsiCtlrUnitNumber);
        }

        var disk = new VirtualDisk
        {
            backing = new VirtualDiskFlatVer2BackingInfo
            {
                diskMode = "persistent",
                fileName = $"[{datastoreName}]",
                thinProvisioned = true,
                thinProvisionedSpecified = true,
            },
            capacityInKB = size * 1024 * 1024,
            controllerKey = ctrl.key,
            controllerKeySpecified = true,
            key = --deviceKey,
            unitNumber = Enumerable.Range(0, 100).First(i => !units.Contains(i)),
            unitNumberSpecified = true,
        };
        deviceChange.Add(new VirtualDeviceConfigSpec
        {
            device = disk,
            fileOperation = VirtualDeviceConfigSpecFileOperation.create,
            fileOperationSpecified = true,
            operation = VirtualDeviceConfigSpecOperation.add,
            operationSpecified = true,
        });

        var spec = new VirtualMachineConfigSpec
        {
            deviceChange = deviceChange.ToArray(),
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

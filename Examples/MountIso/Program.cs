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

static async System.Threading.Tasks.Task Work(string[] args)
{
    if (args.Length != 5)
    {
        await Console.Error.WriteLineAsync("MountIso URL USERNAME PASSWORD VMNAME DATASTOREPATH");
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
        var vm = await session.RootFolder.FindByName<VirtualMachine>(args[3]) ?? throw new Exception($"Not found virtual machine `{args[3]}`.");
        var devices = await vm.GetProperty<VirtualDevice[]>("config.hardware.device");
        var cdrom = devices!.OfType<VirtualCdrom>().FirstOrDefault() ?? throw new Exception($"Not found CD/DVD drive `{args[3]}`.");
        cdrom.backing = new VirtualCdromIsoBackingInfo
        {
            fileName = args[4],
        };
        cdrom.connectable = new VirtualDeviceConnectInfo
        {
            connected = true,
            startConnected = true,
        };

        var change = new VirtualDeviceConfigSpec
        {
            device = cdrom,
            operation = VirtualDeviceConfigSpecOperation.edit,
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

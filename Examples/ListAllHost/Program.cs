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
    if (args.Length != 3)
    {
        await Console.Error.WriteLineAsync("ListAllHost URL USERNAME PASSWORD");
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
        await foreach (var host in session.RootFolder.Enumerate<HostSystem>())
        {
            var (name, hardware, powerState) =
                await host.GetProperty<string, HostHardwareSummary, HostSystemPowerState>(
                    "name", "summary.hardware", "summary.runtime.powerState");

            await Console.Out.WriteLineAsync(string.Format("Name        : {0}", name));
            await Console.Out.WriteLineAsync(string.Format("Vendor      : {0}", hardware!.vendor));
            await Console.Out.WriteLineAsync(string.Format("Model       : {0}", hardware.model));
            await Console.Out.WriteLineAsync(string.Format("CPU Model   : {0}", hardware.cpuModel));
            await Console.Out.WriteLineAsync(string.Format("UUID        : {0}", hardware.uuid));
            await Console.Out.WriteLineAsync(string.Format("Power State : {0}", powerState));
        }
    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

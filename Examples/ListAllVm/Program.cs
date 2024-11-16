namespace Examples;

using CsVmomi;
using VimService;

internal class ListAllVm
{
    internal static async System.Threading.Tasks.Task Main(string[] args)
    {
        try
        {
            await ListAllVm.Work(args);
        }
        catch (Exception e)
        {
            await Console.Error.WriteLineAsync(string.Format("{0}", e));
        }
    }

    private static async System.Threading.Tasks.Task Work(string[] args)
    {
        if (args.Length != 3)
        {
            await Console.Error.WriteLineAsync("ListAllVm URL USERNAME PASSWORD");
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
            await foreach (var vm in session.RootFolder.Enumerate<VirtualMachine>())
            {
                var (name, summary) = await vm.GetProperty<string, VirtualMachineSummary>("name", "summary");

                await Console.Out.WriteLineAsync(string.Format("Name          : {0}", name));
                await Console.Out.WriteLineAsync(string.Format("Template      : {0}", summary!.config.template));
                await Console.Out.WriteLineAsync(string.Format("Path          : {0}", summary.config.vmPathName));
                await Console.Out.WriteLineAsync(string.Format("Guest         : {0}", summary.config.guestFullName));
                await Console.Out.WriteLineAsync(string.Format("Instance UUID : {0}", summary.config.instanceUuid));
                await Console.Out.WriteLineAsync(string.Format("BIOS UUID     : {0}", summary.config.uuid));
                await Console.Out.WriteLineAsync();
            }
        }
        finally
        {
            await session.SessionManager!.Logout();
        }
    }
}

namespace Examples;

using CsVmomi;
using VimService;

internal class ShutdownHost
{
    internal static async System.Threading.Tasks.Task Main(string[] args)
    {
        try
        {
            await ShutdownHost.Work(args);
        }
        catch (Exception e)
        {
            await Console.Error.WriteLineAsync(string.Format("{0}", e));
        }
    }

    private static async System.Threading.Tasks.Task Work(string[] args)
    {
        if (args.Length != 4)
        {
            await Console.Error.WriteLineAsync("ShutdownHost URL USERNAME PASSWORD HOSTNAME");
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
            var task = await host.ShutdownHost_Task(true);
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
}

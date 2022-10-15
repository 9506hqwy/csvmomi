namespace Examples;

using CsVmomi;
using VimService;

internal class PowerOnVm
{
    internal static async System.Threading.Tasks.Task Main(string[] args)
    {
        try
        {
            await PowerOnVm.Work(args);
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
            await Console.Error.WriteLineAsync("PowerOnVm URL USERNAME PASSWORD VMNAME");
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

            var task = await vm.PowerOnVM_Task(null);
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

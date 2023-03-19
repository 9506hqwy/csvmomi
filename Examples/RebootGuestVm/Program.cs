using CsVmomi;

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
    if (args.Length != 4)
    {
        await Console.Error.WriteLineAsync("RebootGuestVm URL USERNAME PASSWORD VMNAME");
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

        await vm.RebootGuest();

        await Console.Out.WriteLineAsync("Success.");
    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

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
    await session.SessionManager.Login(args[1], args[2]);
    try
    {
        var vm = await FindVm(session, args[3]);
        await vm.RebootGuest();

        await Console.Out.WriteLineAsync("Success.");
    }
    finally
    {
        await session.SessionManager.Logout();
    }
}

async Task<VirtualMachine> FindVm(Session session, string vmname)
{
    var view = await session.ViewManager.CreateContainerView(
           session.RootFolder,
           new[] { "vim.VirtualMachine" },
           true);

    var objs = await view.GetPropertyView();
    var vms = objs.Cast<VirtualMachine>().ToArray();

    foreach (var vm in vms)
    {
        var name = await vm.GetPropertyName();
        if (name.ToLowerInvariant() == vmname.ToLowerInvariant())
        {
            return vm;
        }
    }

    throw new Exception($"Not found virtual machine `{vmname}`.");
}

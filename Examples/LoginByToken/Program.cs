using CsVmomi;

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
    if (args.Length != 3)
    {
        await Console.Error.WriteLineAsync("LoginByToken URL USERNAME PASSWORD");
        return;
    }

    if (!Uri.TryCreate(args[0], UriKind.Absolute, out var url))
    {
        await Console.Error.WriteLineAsync("URL is invalid format.");
        return;
    }

    var session = await Session.Get(new Uri(args[0]));
    session.MessageToolBox.Fixup = Fixup.FixupNamespaceNotPreserve();

    var duration = TimeSpan.FromSeconds(600);

    session.SetStsClient(args[1], args[2]);
    var token = await Sso.GetBearerToken(session, duration);

    _ = await Sso.LoginByToken(session, token.RequestedSecurityToken, duration);
    try
    {
        await foreach (var vm in session.RootFolder.Enumerate<VirtualMachine>())
        {
            var name = await vm.GetPropertyName();
            await Console.Out.WriteLineAsync(name);
        }
    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

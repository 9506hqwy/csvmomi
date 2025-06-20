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
    if (args.Length != 3)
    {
        await Console.Error.WriteLineAsync("ListAllIso URL USERNAME PASSWORD");
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
        await foreach (var datastore in session.RootFolder.Enumerate<Datastore>())
        {
            var name = await datastore.GetPropertyName();
            var browser = await datastore!.GetPropertyBrowser();

            var spec = new HostDatastoreBrowserSearchSpec
            {
                query =
                [
                    new IsoImageFileQuery(),
                ],
            };

            var task = await browser.SearchDatastoreSubFolders_Task($"[{name}]", spec);
            var state = await task!.WaitForCompleted(TimeSpan.FromSeconds(300));
            if (state == TaskInfoState.error)
            {
                var error = await task.GetProperty<LocalizedMethodFault>("info.error");
                throw new Exception(error!.localizedMessage);
            }

            if ((await task.GetPropertyInfo()).result is not HostDatastoreBrowserSearchResults[] results)
            {
                continue;
            }

            foreach (var result in results)
            {
                foreach (var file in result.file)
                {
                    if (result.folderPath == $"[{name}]")
                    {
                        await Console.Out.WriteLineAsync($"{result.folderPath} {file.path}");
                    }
                    else
                    {
                        await Console.Out.WriteLineAsync($"{result.folderPath}/{file.path}");
                    }
                }
            }
        }
    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

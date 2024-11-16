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
        await Console.Error.WriteLineAsync("PollEvent URL USERNAME PASSWORD");
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
        var events = new Queue<Event>();
        var printer = new System.Threading.Tasks.Task(() =>
        {
            // 標準出力スレッド
            while (true)
            {
                Event[]? evts = null;
                lock (events)
                {
                    _ = Monitor.Wait(events);
                    evts = [.. events];
                    events.Clear();
                }

                foreach (var evt in evts)
                {
                    Console.WriteLine("{0} : {1}", evt.createdTime.ToLocalTime(), evt.fullFormattedMessage);
                }
            }
        });
        printer.Start();

        var filter = new EventFilterSpec
        {
            maxCount = 1000,
            maxCountSpecified = true,
        };
        await using var collector = await session.EventManager!.CreateCollectorForEvents(filter);
        await collector!.ResetCollector();

        await using var prop = await session.PropertyCollector.CreatePropertyCollector();
        _ = await prop!.CreateFilter(session.EventManager, "latestEvent", false);

        var version = string.Empty;
        var options = new WaitOptions
        {
            maxObjectUpdates = 1,
            maxObjectUpdatesSpecified = true,
            maxWaitSeconds = 60,
            maxWaitSecondsSpecified = true,
        };

        while (true)
        {
            // イベント検出スレッド
            var updateSet = await prop.WaitForUpdatesEx(version, options);
            if (updateSet == null)
            {
                continue;
            }

            version = updateSet.version;

            var evts = await collector.ReadNextEvents(filter.maxCount);

            lock (events)
            {
                Array.ForEach(evts!, events.Enqueue);
                Monitor.Pulse(events);
            }
        }
    }
    finally
    {
        await session.SessionManager!.Logout();
    }
}

namespace CsVmomi;

public partial class Task : ExtensibleManagedObject
{
    public async System.Threading.Tasks.Task<TaskInfoState> WaitForCompleted(TimeSpan timeout)
    {
        await using var collector = await this.Session.PropertyCollector.CreatePropertyCollector();

        // Task.info.state のみ対象とする。
        await collector!.CreateFilter(this, "info.state", false);

        var version = string.Empty;
        var options = new WaitOptions
        {
            maxObjectUpdates = 1,
            maxObjectUpdatesSpecified = true,
            maxWaitSeconds = 60,
            maxWaitSecondsSpecified = true,
        };

        var deadline = DateTime.UtcNow.Add(timeout);
        while (DateTime.UtcNow < deadline)
        {
            // HTTP コネクションを接続したままにするため複数同時に実行すると上限の考慮が必要になる。
            // https://learn.microsoft.com/en-us/dotnet/api/system.net.servicepoint.connectionlimit
            var updateSet = await collector.WaitForUpdatesEx(version, options);
            if (updateSet == null)
            {
                continue;
            }

            version = updateSet.version;

            // 1 オブジェクトのため updateSet.truncated は考慮しない。
            var state = (TaskInfoState)updateSet.filterSet[0].objectSet[0].changeSet[0].val;
            if (state == TaskInfoState.error
                || state == TaskInfoState.success)
            {
                return state;
            }
        }

        throw new TimeoutException();
    }
}

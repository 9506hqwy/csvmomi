namespace CsVmomi;

using SmsService;

#pragma warning disable IDE0058 // Expression value is never used

public partial class SmsProvider : ManagedObject
{
    protected SmsProvider(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<SmsProviderInfo?> QueryProviderInfo()
    {
        return await this.Session.SmsClient!.QueryProviderInfo(this.SmsReference);
    }
}

public partial class SmsServiceInstance : ManagedObject
{
    protected SmsServiceInstance(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<SmsAboutInfo?> QueryAboutInfo()
    {
        return await this.Session.SmsClient!.QueryAboutInfo(this.SmsReference);
    }

    public async System.Threading.Tasks.Task<SmsStorageManager?> QueryStorageManager()
    {
        var res = await this.Session.SmsClient!.QueryStorageManager(this.SmsReference);
        return ManagedObject.Create<SmsStorageManager>(res, this.Session);
    }
}

public partial class SmsStorageManager : ManagedObject
{
    protected SmsStorageManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<StorageArray[]?> QueryArray(string[]? providerId)
    {
        return await this.Session.SmsClient!.QueryArray(this.SmsReference, providerId);
    }

    public async System.Threading.Tasks.Task<StorageArray?> QueryArrayAssociatedWithLun(string canonicalName)
    {
        return await this.Session.SmsClient!.QueryArrayAssociatedWithLun(this.SmsReference, canonicalName);
    }

    public async System.Threading.Tasks.Task<BackingStoragePool[]?> QueryAssociatedBackingStoragePool(string? entityId, string? entityType)
    {
        return await this.Session.SmsClient!.QueryAssociatedBackingStoragePool(this.SmsReference, entityId, entityType);
    }

    public async System.Threading.Tasks.Task<DatastoreBackingPoolMapping[]?> QueryDatastoreBackingPoolMapping(Datastore[] datastore)
    {
        return await this.Session.SmsClient!.QueryDatastoreBackingPoolMapping(this.SmsReference, datastore.Select(m => m.SmsReference).ToArray());
    }

    public async System.Threading.Tasks.Task<StorageCapability?> QueryDatastoreCapability(Datastore datastore)
    {
        return await this.Session.SmsClient!.QueryDatastoreCapability(this.SmsReference, datastore.SmsReference);
    }

    public async System.Threading.Tasks.Task<bool> QueryDrsMigrationCapabilityForPerformance(Datastore srcDatastore, Datastore dstDatastore)
    {
        return await this.Session.SmsClient!.QueryDrsMigrationCapabilityForPerformance(this.SmsReference, srcDatastore.SmsReference, dstDatastore.SmsReference);
    }

    public async System.Threading.Tasks.Task<DrsMigrationCapabilityResult?> QueryDrsMigrationCapabilityForPerformanceEx(Datastore[] datastore)
    {
        return await this.Session.SmsClient!.QueryDrsMigrationCapabilityForPerformanceEx(this.SmsReference, datastore.Select(m => m.SmsReference).ToArray());
    }

    public async System.Threading.Tasks.Task<StorageFileSystem[]?> QueryFileSystemAssociatedWithArray(string arrayId)
    {
        return await this.Session.SmsClient!.QueryFileSystemAssociatedWithArray(this.SmsReference, arrayId);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryHostAssociatedWithLun(string scsi3Id, string arrayId)
    {
        var res = await this.Session.SmsClient!.QueryHostAssociatedWithLun(this.SmsReference, scsi3Id, arrayId);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<StorageLun[]?> QueryLunAssociatedWithArray(string arrayId)
    {
        return await this.Session.SmsClient!.QueryLunAssociatedWithArray(this.SmsReference, arrayId);
    }

    public async System.Threading.Tasks.Task<StorageLun[]?> QueryLunAssociatedWithPort(string portId, string arrayId)
    {
        return await this.Session.SmsClient!.QueryLunAssociatedWithPort(this.SmsReference, portId, arrayId);
    }

    public async System.Threading.Tasks.Task<Datastore?> QueryNfsDatastoreAssociatedWithFileSystem(string fileSystemId, string arrayId)
    {
        var res = await this.Session.SmsClient!.QueryNfsDatastoreAssociatedWithFileSystem(this.SmsReference, fileSystemId, arrayId);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<StoragePort[]?> QueryPortAssociatedWithArray(string arrayId)
    {
        return await this.Session.SmsClient!.QueryPortAssociatedWithArray(this.SmsReference, arrayId);
    }

    public async System.Threading.Tasks.Task<StoragePort?> QueryPortAssociatedWithLun(string scsi3Id, string arrayId)
    {
        return await this.Session.SmsClient!.QueryPortAssociatedWithLun(this.SmsReference, scsi3Id, arrayId);
    }

    public async System.Threading.Tasks.Task<StoragePort[]?> QueryPortAssociatedWithProcessor(string processorId, string arrayId)
    {
        return await this.Session.SmsClient!.QueryPortAssociatedWithProcessor(this.SmsReference, processorId, arrayId);
    }

    public async System.Threading.Tasks.Task<StorageProcessor[]?> QueryProcessorAssociatedWithArray(string arrayId)
    {
        return await this.Session.SmsClient!.QueryProcessorAssociatedWithArray(this.SmsReference, arrayId);
    }

    public async System.Threading.Tasks.Task<SmsProvider[]?> QueryProvider()
    {
        var res = await this.Session.SmsClient!.QueryProvider(this.SmsReference);
        return res?.Select(r => ManagedObject.Create<SmsProvider>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<StorageContainerResult?> QueryStorageContainer(StorageContainerSpec? containerSpec)
    {
        return await this.Session.SmsClient!.QueryStorageContainer(this.SmsReference, containerSpec);
    }

    public async System.Threading.Tasks.Task<Datastore?> QueryVmfsDatastoreAssociatedWithLun(string scsi3Id, string arrayId)
    {
        var res = await this.Session.SmsClient!.QueryVmfsDatastoreAssociatedWithLun(this.SmsReference, scsi3Id, arrayId);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<SmsTask?> RegisterProvider_Task(SmsProviderSpec providerSpec)
    {
        var res = await this.Session.SmsClient!.RegisterProvider_Task(this.SmsReference, providerSpec);
        return ManagedObject.Create<SmsTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<SmsTask?> UnregisterProvider_Task(string providerId)
    {
        var res = await this.Session.SmsClient!.UnregisterProvider_Task(this.SmsReference, providerId);
        return ManagedObject.Create<SmsTask>(res, this.Session);
    }
}

public partial class SmsTask : ManagedObject
{
    protected SmsTask(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<SmsTaskInfo?> QuerySmsTaskInfo()
    {
        return await this.Session.SmsClient!.QuerySmsTaskInfo(this.SmsReference);
    }

    public async System.Threading.Tasks.Task<object?> QuerySmsTaskResult()
    {
        return await this.Session.SmsClient!.QuerySmsTaskResult(this.SmsReference);
    }
}

public partial class VasaProvider : SmsProvider
{
    protected VasaProvider(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<SmsTask?> VasaProviderReconnect_Task()
    {
        var res = await this.Session.SmsClient!.VasaProviderReconnect_Task(this.SmsReference);
        return ManagedObject.Create<SmsTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<SmsTask?> VasaProviderRefreshCertificate_Task()
    {
        var res = await this.Session.SmsClient!.VasaProviderRefreshCertificate_Task(this.SmsReference);
        return ManagedObject.Create<SmsTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<SmsTask?> VasaProviderRevokeCertificate_Task()
    {
        var res = await this.Session.SmsClient!.VasaProviderRevokeCertificate_Task(this.SmsReference);
        return ManagedObject.Create<SmsTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<SmsTask?> VasaProviderSync_Task(string? arrayId)
    {
        var res = await this.Session.SmsClient!.VasaProviderSync_Task(this.SmsReference, arrayId);
        return ManagedObject.Create<SmsTask>(res, this.Session);
    }
}

#pragma warning restore IDE0058 // Expression value is never used

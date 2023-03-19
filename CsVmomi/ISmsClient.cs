namespace CsVmomi;

using SmsService;

public interface ISmsClient
{
    public Uri Uri { get; }

    public string? GetCookie(string name);

    System.Net.CookieCollection? GetCookie();

    void SetCookie(System.Net.CookieCollection? cookie);

    System.Threading.Tasks.Task<SmsAboutInfo?> QueryAboutInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<StorageArray[]?> QueryArray(ManagedObjectReference self, string[]? providerId);

    System.Threading.Tasks.Task<StorageArray?> QueryArrayAssociatedWithLun(ManagedObjectReference self, string canonicalName);

    System.Threading.Tasks.Task<BackingStoragePool[]?> QueryAssociatedBackingStoragePool(ManagedObjectReference self, string? entityId, string? entityType);

    System.Threading.Tasks.Task<DatastoreBackingPoolMapping[]?> QueryDatastoreBackingPoolMapping(ManagedObjectReference self, ManagedObjectReference[] datastore);

    System.Threading.Tasks.Task<StorageCapability?> QueryDatastoreCapability(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<bool> QueryDrsMigrationCapabilityForPerformance(ManagedObjectReference self, ManagedObjectReference srcDatastore, ManagedObjectReference dstDatastore);

    System.Threading.Tasks.Task<DrsMigrationCapabilityResult?> QueryDrsMigrationCapabilityForPerformanceEx(ManagedObjectReference self, ManagedObjectReference[] datastore);

    System.Threading.Tasks.Task<StorageFileSystem[]?> QueryFileSystemAssociatedWithArray(ManagedObjectReference self, string arrayId);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryHostAssociatedWithLun(ManagedObjectReference self, string scsi3Id, string arrayId);

    System.Threading.Tasks.Task<StorageLun[]?> QueryLunAssociatedWithArray(ManagedObjectReference self, string arrayId);

    System.Threading.Tasks.Task<StorageLun[]?> QueryLunAssociatedWithPort(ManagedObjectReference self, string portId, string arrayId);

    System.Threading.Tasks.Task<ManagedObjectReference?> QueryNfsDatastoreAssociatedWithFileSystem(ManagedObjectReference self, string fileSystemId, string arrayId);

    System.Threading.Tasks.Task<StoragePort[]?> QueryPortAssociatedWithArray(ManagedObjectReference self, string arrayId);

    System.Threading.Tasks.Task<StoragePort?> QueryPortAssociatedWithLun(ManagedObjectReference self, string scsi3Id, string arrayId);

    System.Threading.Tasks.Task<StoragePort[]?> QueryPortAssociatedWithProcessor(ManagedObjectReference self, string processorId, string arrayId);

    System.Threading.Tasks.Task<StorageProcessor[]?> QueryProcessorAssociatedWithArray(ManagedObjectReference self, string arrayId);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryProvider(ManagedObjectReference self);

    System.Threading.Tasks.Task<SmsProviderInfo?> QueryProviderInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<SmsTaskInfo?> QuerySmsTaskInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<object?> QuerySmsTaskResult(ManagedObjectReference self);

    System.Threading.Tasks.Task<StorageContainerResult?> QueryStorageContainer(ManagedObjectReference self, StorageContainerSpec? containerSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> QueryStorageManager(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> QueryVmfsDatastoreAssociatedWithLun(ManagedObjectReference self, string scsi3Id, string arrayId);

    System.Threading.Tasks.Task<ManagedObjectReference?> RegisterProvider_Task(ManagedObjectReference self, SmsProviderSpec providerSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> UnregisterProvider_Task(ManagedObjectReference self, string providerId);

    System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderReconnect_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderRefreshCertificate_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderRevokeCertificate_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderSync_Task(ManagedObjectReference self, string? arrayId);
}

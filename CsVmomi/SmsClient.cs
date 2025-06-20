namespace CsVmomi;

using System.ServiceModel.Channels;
using SmsService;

#pragma warning disable IDE0058 // Expression value is never used

public class SmsClient : ISmsClient
{
    private readonly SmsPortTypeClient inner;

    internal SmsClient(SmsPortTypeClient inner)
    {
        this.inner = inner;
    }

    public Uri Uri => this.inner.Endpoint.Address.Uri;

    public string? GetCookie(string name)
    {
        return this.GetCookie()?
            .OfType<System.Net.Cookie>()
            .FirstOrDefault(c => c.Name == name)?
            .Value;
    }

    public System.Net.CookieCollection? GetCookie()
    {
        return this.inner.InnerChannel.GetProperty<IHttpCookieContainerManager>()?
            .CookieContainer
            .GetCookies(this.Uri);
    }

    public void SetCookie(System.Net.CookieCollection? cookie)
    {
        var container = this.inner.InnerChannel
            .GetProperty<IHttpCookieContainerManager>()!
            .CookieContainer;

        foreach (var c in cookie.OfType<System.Net.Cookie>())
        {
            container.Add(new System.Net.Cookie(c.Name, c.Value, this.Uri.AbsolutePath, this.Uri.Host));
        }
    }

    public async System.Threading.Tasks.Task<SmsAboutInfo?> QueryAboutInfo(ManagedObjectReference self)
    {
        var req = new QueryAboutInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryAboutInfoAsync(req);

        return res.QueryAboutInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StorageArray[]?> QueryArray(ManagedObjectReference self, string[]? providerId)
    {
        var req = new QueryArrayRequestType
        {
            _this = self,
            providerId = providerId,
        };

        var res = await this.inner.QueryArrayAsync(req);

        return res.QueryArrayResponse1;
    }

    public async System.Threading.Tasks.Task<StorageArray?> QueryArrayAssociatedWithLun(ManagedObjectReference self, string canonicalName)
    {
        var req = new QueryArrayAssociatedWithLunRequestType
        {
            _this = self,
            canonicalName = canonicalName,
        };

        var res = await this.inner.QueryArrayAssociatedWithLunAsync(req);

        return res.QueryArrayAssociatedWithLunResponse.returnval;
    }

    public async System.Threading.Tasks.Task<BackingStoragePool[]?> QueryAssociatedBackingStoragePool(ManagedObjectReference self, string? entityId, string? entityType)
    {
        var req = new QueryAssociatedBackingStoragePoolRequestType
        {
            _this = self,
            entityId = entityId,
            entityType = entityType,
        };

        var res = await this.inner.QueryAssociatedBackingStoragePoolAsync(req);

        return res.QueryAssociatedBackingStoragePoolResponse1;
    }

    public async System.Threading.Tasks.Task<DatastoreBackingPoolMapping[]?> QueryDatastoreBackingPoolMapping(ManagedObjectReference self, ManagedObjectReference[] datastore)
    {
        var req = new QueryDatastoreBackingPoolMappingRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.QueryDatastoreBackingPoolMappingAsync(req);

        return res.QueryDatastoreBackingPoolMappingResponse1;
    }

    public async System.Threading.Tasks.Task<StorageCapability?> QueryDatastoreCapability(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new QueryDatastoreCapabilityRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.QueryDatastoreCapabilityAsync(req);

        return res.QueryDatastoreCapabilityResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> QueryDrsMigrationCapabilityForPerformance(ManagedObjectReference self, ManagedObjectReference srcDatastore, ManagedObjectReference dstDatastore)
    {
        var req = new QueryDrsMigrationCapabilityForPerformanceRequestType
        {
            _this = self,
            srcDatastore = srcDatastore,
            dstDatastore = dstDatastore,
        };

        var res = await this.inner.QueryDrsMigrationCapabilityForPerformanceAsync(req);

        return res.QueryDrsMigrationCapabilityForPerformanceResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DrsMigrationCapabilityResult?> QueryDrsMigrationCapabilityForPerformanceEx(ManagedObjectReference self, ManagedObjectReference[] datastore)
    {
        var req = new QueryDrsMigrationCapabilityForPerformanceExRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.QueryDrsMigrationCapabilityForPerformanceExAsync(req);

        return res.QueryDrsMigrationCapabilityForPerformanceExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StorageFileSystem[]?> QueryFileSystemAssociatedWithArray(ManagedObjectReference self, string arrayId)
    {
        var req = new QueryFileSystemAssociatedWithArrayRequestType
        {
            _this = self,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryFileSystemAssociatedWithArrayAsync(req);

        return res.QueryFileSystemAssociatedWithArrayResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryHostAssociatedWithLun(ManagedObjectReference self, string scsi3Id, string arrayId)
    {
        var req = new QueryHostAssociatedWithLunRequestType
        {
            _this = self,
            scsi3Id = scsi3Id,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryHostAssociatedWithLunAsync(req);

        return res.QueryHostAssociatedWithLunResponse1;
    }

    public async System.Threading.Tasks.Task<StorageLun[]?> QueryLunAssociatedWithArray(ManagedObjectReference self, string arrayId)
    {
        var req = new QueryLunAssociatedWithArrayRequestType
        {
            _this = self,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryLunAssociatedWithArrayAsync(req);

        return res.QueryLunAssociatedWithArrayResponse1;
    }

    public async System.Threading.Tasks.Task<StorageLun[]?> QueryLunAssociatedWithPort(ManagedObjectReference self, string portId, string arrayId)
    {
        var req = new QueryLunAssociatedWithPortRequestType
        {
            _this = self,
            portId = portId,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryLunAssociatedWithPortAsync(req);

        return res.QueryLunAssociatedWithPortResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> QueryNfsDatastoreAssociatedWithFileSystem(ManagedObjectReference self, string fileSystemId, string arrayId)
    {
        var req = new QueryNfsDatastoreAssociatedWithFileSystemRequestType
        {
            _this = self,
            fileSystemId = fileSystemId,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryNfsDatastoreAssociatedWithFileSystemAsync(req);

        return res.QueryNfsDatastoreAssociatedWithFileSystemResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StoragePort[]?> QueryPortAssociatedWithArray(ManagedObjectReference self, string arrayId)
    {
        var req = new QueryPortAssociatedWithArrayRequestType
        {
            _this = self,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryPortAssociatedWithArrayAsync(req);

        return res.QueryPortAssociatedWithArrayResponse1;
    }

    public async System.Threading.Tasks.Task<StoragePort?> QueryPortAssociatedWithLun(ManagedObjectReference self, string scsi3Id, string arrayId)
    {
        var req = new QueryPortAssociatedWithLunRequestType
        {
            _this = self,
            scsi3Id = scsi3Id,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryPortAssociatedWithLunAsync(req);

        return res.QueryPortAssociatedWithLunResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StoragePort[]?> QueryPortAssociatedWithProcessor(ManagedObjectReference self, string processorId, string arrayId)
    {
        var req = new QueryPortAssociatedWithProcessorRequestType
        {
            _this = self,
            processorId = processorId,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryPortAssociatedWithProcessorAsync(req);

        return res.QueryPortAssociatedWithProcessorResponse1;
    }

    public async System.Threading.Tasks.Task<StorageProcessor[]?> QueryProcessorAssociatedWithArray(ManagedObjectReference self, string arrayId)
    {
        var req = new QueryProcessorAssociatedWithArrayRequestType
        {
            _this = self,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryProcessorAssociatedWithArrayAsync(req);

        return res.QueryProcessorAssociatedWithArrayResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryProvider(ManagedObjectReference self)
    {
        var req = new QueryProviderRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryProviderAsync(req);

        return res.QueryProviderResponse1;
    }

    public async System.Threading.Tasks.Task<SmsProviderInfo?> QueryProviderInfo(ManagedObjectReference self)
    {
        var req = new QueryProviderInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryProviderInfoAsync(req);

        return res.QueryProviderInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<SmsTaskInfo?> QuerySmsTaskInfo(ManagedObjectReference self)
    {
        var req = new QuerySmsTaskInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.QuerySmsTaskInfoAsync(req);

        return res.QuerySmsTaskInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<object?> QuerySmsTaskResult(ManagedObjectReference self)
    {
        var req = new QuerySmsTaskResultRequestType
        {
            _this = self,
        };

        var res = await this.inner.QuerySmsTaskResultAsync(req);

        return res.QuerySmsTaskResultResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StorageContainerResult?> QueryStorageContainer(ManagedObjectReference self, StorageContainerSpec? containerSpec)
    {
        var req = new QueryStorageContainerRequestType
        {
            _this = self,
            containerSpec = containerSpec,
        };

        var res = await this.inner.QueryStorageContainerAsync(req);

        return res.QueryStorageContainerResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> QueryStorageManager(ManagedObjectReference self)
    {
        var req = new QueryStorageManagerRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryStorageManagerAsync(req);

        return res.QueryStorageManagerResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> QueryVmfsDatastoreAssociatedWithLun(ManagedObjectReference self, string scsi3Id, string arrayId)
    {
        var req = new QueryVmfsDatastoreAssociatedWithLunRequestType
        {
            _this = self,
            scsi3Id = scsi3Id,
            arrayId = arrayId,
        };

        var res = await this.inner.QueryVmfsDatastoreAssociatedWithLunAsync(req);

        return res.QueryVmfsDatastoreAssociatedWithLunResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RegisterProvider_Task(ManagedObjectReference self, SmsProviderSpec providerSpec)
    {
        var req = new RegisterProviderRequestType
        {
            _this = self,
            providerSpec = providerSpec,
        };

        var res = await this.inner.RegisterProvider_TaskAsync(req);

        return res.RegisterProvider_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UnregisterProvider_Task(ManagedObjectReference self, string providerId)
    {
        var req = new UnregisterProviderRequestType
        {
            _this = self,
            providerId = providerId,
        };

        var res = await this.inner.UnregisterProvider_TaskAsync(req);

        return res.UnregisterProvider_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderReconnect_Task(ManagedObjectReference self)
    {
        var req = new VasaProviderReconnectRequestType
        {
            _this = self,
        };

        var res = await this.inner.VasaProviderReconnect_TaskAsync(req);

        return res.VasaProviderReconnect_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderRefreshCertificate_Task(ManagedObjectReference self)
    {
        var req = new VasaProviderRefreshCertificateRequestType
        {
            _this = self,
        };

        var res = await this.inner.VasaProviderRefreshCertificate_TaskAsync(req);

        return res.VasaProviderRefreshCertificate_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderRevokeCertificate_Task(ManagedObjectReference self)
    {
        var req = new VasaProviderRevokeCertificateRequestType
        {
            _this = self,
        };

        var res = await this.inner.VasaProviderRevokeCertificate_TaskAsync(req);

        return res.VasaProviderRevokeCertificate_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VasaProviderSync_Task(ManagedObjectReference self, string? arrayId)
    {
        var req = new VasaProviderSyncRequestType
        {
            _this = self,
            arrayId = arrayId,
        };

        var res = await this.inner.VasaProviderSync_TaskAsync(req);

        return res.VasaProviderSync_TaskResponse.returnval;
    }

}

#pragma warning restore IDE0058 // Expression value is never used

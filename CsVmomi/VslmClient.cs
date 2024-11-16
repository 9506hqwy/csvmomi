namespace CsVmomi;

using System.ServiceModel.Channels;
using VslmService;

#pragma warning disable IDE0058 // Expression value is never used

public class VslmClient : IVslmClient
{
    private readonly VslmPortTypeClient inner;

    internal VslmClient(VslmPortTypeClient inner)
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

    public async System.Threading.Tasks.Task<VslmServiceInstanceContent?> RetrieveContent(ManagedObjectReference self)
    {
        var req = new RetrieveContentRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveContentAsync(req);

        return res.RetrieveContentResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmAttachDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference vm, int controllerKey, bool controllerKeySpecified, int unitNumber, bool unitNumberSpecified)
    {
        var req = new VslmAttachDiskRequestType
        {
            _this = self,
            id = id,
            vm = vm,
            controllerKey = controllerKey,
            controllerKeySpecified = controllerKeySpecified,
            unitNumber = unitNumber,
            unitNumberSpecified = unitNumberSpecified,
        };

        var res = await this.inner.VslmAttachDisk_TaskAsync(req);

        return res.VslmAttachDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task VslmAttachTagToVStorageObject(ManagedObjectReference self, ID id, string category, string tag)
    {
        var req = new VslmAttachTagToVStorageObjectRequestType
        {
            _this = self,
            id = id,
            category = category,
            tag = tag,
        };

        await this.inner.VslmAttachTagToVStorageObjectAsync(req);
    }

    public async System.Threading.Tasks.Task VslmCancelTask(ManagedObjectReference self)
    {
        var req = new VslmCancelTaskRequestType
        {
            _this = self,
        };

        await this.inner.VslmCancelTaskAsync(req);
    }

    public async System.Threading.Tasks.Task VslmClearVStorageObjectControlFlags(ManagedObjectReference self, ID id, string[]? controlFlags)
    {
        var req = new VslmClearVStorageObjectControlFlagsRequestType
        {
            _this = self,
            id = id,
            controlFlags = controlFlags,
        };

        await this.inner.VslmClearVStorageObjectControlFlagsAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmCloneVStorageObject_Task(ManagedObjectReference self, ID id, VslmCloneSpec spec)
    {
        var req = new VslmCloneVStorageObjectRequestType
        {
            _this = self,
            id = id,
            spec = spec,
        };

        var res = await this.inner.VslmCloneVStorageObject_TaskAsync(req);

        return res.VslmCloneVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmCreateDisk_Task(ManagedObjectReference self, VslmCreateSpec spec)
    {
        var req = new VslmCreateDiskRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.VslmCreateDisk_TaskAsync(req);

        return res.VslmCreateDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmCreateDiskFromSnapshot_Task(ManagedObjectReference self, ID id, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path)
    {
        var req = new VslmCreateDiskFromSnapshotRequestType
        {
            _this = self,
            id = id,
            snapshotId = snapshotId,
            name = name,
            profile = profile,
            crypto = crypto,
            path = path,
        };

        var res = await this.inner.VslmCreateDiskFromSnapshot_TaskAsync(req);

        return res.VslmCreateDiskFromSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmCreateSnapshot_Task(ManagedObjectReference self, ID id, string description)
    {
        var req = new VslmCreateSnapshotRequestType
        {
            _this = self,
            id = id,
            description = description,
        };

        var res = await this.inner.VslmCreateSnapshot_TaskAsync(req);

        return res.VslmCreateSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmDeleteSnapshot_Task(ManagedObjectReference self, ID id, ID snapshotId)
    {
        var req = new VslmDeleteSnapshotRequestType
        {
            _this = self,
            id = id,
            snapshotId = snapshotId,
        };

        var res = await this.inner.VslmDeleteSnapshot_TaskAsync(req);

        return res.VslmDeleteSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmDeleteVStorageObject_Task(ManagedObjectReference self, ID id)
    {
        var req = new VslmDeleteVStorageObjectRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.VslmDeleteVStorageObject_TaskAsync(req);

        return res.VslmDeleteVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task VslmDetachTagFromVStorageObject(ManagedObjectReference self, ID id, string category, string tag)
    {
        var req = new VslmDetachTagFromVStorageObjectRequestType
        {
            _this = self,
            id = id,
            category = category,
            tag = tag,
        };

        await this.inner.VslmDetachTagFromVStorageObjectAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmExtendDisk_Task(ManagedObjectReference self, ID id, long newCapacityInMB)
    {
        var req = new VslmExtendDiskRequestType
        {
            _this = self,
            id = id,
            newCapacityInMB = newCapacityInMB,
        };

        var res = await this.inner.VslmExtendDisk_TaskAsync(req);

        return res.VslmExtendDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmInflateDisk_Task(ManagedObjectReference self, ID id)
    {
        var req = new VslmInflateDiskRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.VslmInflateDisk_TaskAsync(req);

        return res.VslmInflateDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VslmTagEntry[]?> VslmListTagsAttachedToVStorageObject(ManagedObjectReference self, ID id)
    {
        var req = new VslmListTagsAttachedToVStorageObjectRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.VslmListTagsAttachedToVStorageObjectAsync(req);

        return res.VslmListTagsAttachedToVStorageObjectResponse1;
    }

    public async System.Threading.Tasks.Task<VslmVsoVStorageObjectQueryResult?> VslmListVStorageObjectForSpec(ManagedObjectReference self, VslmVsoVStorageObjectQuerySpec[]? query, int maxResult)
    {
        var req = new VslmListVStorageObjectForSpecRequestType
        {
            _this = self,
            query = query,
            maxResult = maxResult,
        };

        var res = await this.inner.VslmListVStorageObjectForSpecAsync(req);

        return res.VslmListVStorageObjectForSpecResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ID[]?> VslmListVStorageObjectsAttachedToTag(ManagedObjectReference self, string category, string tag)
    {
        var req = new VslmListVStorageObjectsAttachedToTagRequestType
        {
            _this = self,
            category = category,
            tag = tag,
        };

        var res = await this.inner.VslmListVStorageObjectsAttachedToTagAsync(req);

        return res.VslmListVStorageObjectsAttachedToTagResponse1;
    }

    public async System.Threading.Tasks.Task VslmLoginByToken(ManagedObjectReference self, string delegatedTokenXml)
    {
        var req = new VslmLoginByTokenRequestType
        {
            _this = self,
            delegatedTokenXml = delegatedTokenXml,
        };

        await this.inner.VslmLoginByTokenAsync(req);
    }

    public async System.Threading.Tasks.Task VslmLogout(ManagedObjectReference self)
    {
        var req = new VslmLogoutRequestType
        {
            _this = self,
        };

        await this.inner.VslmLogoutAsync(req);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> VslmQueryChangedDiskAreas(ManagedObjectReference self, ID id, ID snapshotId, long startOffset, string changeId)
    {
        var req = new VslmQueryChangedDiskAreasRequestType
        {
            _this = self,
            id = id,
            snapshotId = snapshotId,
            startOffset = startOffset,
            changeId = changeId,
        };

        var res = await this.inner.VslmQueryChangedDiskAreasAsync(req);

        return res.VslmQueryChangedDiskAreasResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VslmQueryDatastoreInfoResult[]?> VslmQueryDatastoreInfo(ManagedObjectReference self, string datastoreUrl)
    {
        var req = new VslmQueryDatastoreInfoRequestType
        {
            _this = self,
            datastoreUrl = datastoreUrl,
        };

        var res = await this.inner.VslmQueryDatastoreInfoAsync(req);

        return res.VslmQueryDatastoreInfoResponse1;
    }

    public async System.Threading.Tasks.Task<VslmDatastoreSyncStatus[]?> VslmQueryGlobalCatalogSyncStatus(ManagedObjectReference self)
    {
        var req = new VslmQueryGlobalCatalogSyncStatusRequestType
        {
            _this = self,
        };

        var res = await this.inner.VslmQueryGlobalCatalogSyncStatusAsync(req);

        return res.VslmQueryGlobalCatalogSyncStatusResponse1;
    }

    public async System.Threading.Tasks.Task<VslmDatastoreSyncStatus?> VslmQueryGlobalCatalogSyncStatusForDatastore(ManagedObjectReference self, string datastoreURL)
    {
        var req = new VslmQueryGlobalCatalogSyncStatusForDatastoreRequestType
        {
            _this = self,
            datastoreURL = datastoreURL,
        };

        var res = await this.inner.VslmQueryGlobalCatalogSyncStatusForDatastoreAsync(req);

        return res.VslmQueryGlobalCatalogSyncStatusForDatastoreResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VslmTaskInfo?> VslmQueryInfo(ManagedObjectReference self)
    {
        var req = new VslmQueryInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.VslmQueryInfoAsync(req);

        return res.VslmQueryInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<object?> VslmQueryTaskResult(ManagedObjectReference self)
    {
        var req = new VslmQueryTaskResultRequestType
        {
            _this = self,
        };

        var res = await this.inner.VslmQueryTaskResultAsync(req);

        return res.VslmQueryTaskResultResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmReconcileDatastoreInventory_Task(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new VslmReconcileDatastoreInventoryRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.VslmReconcileDatastoreInventory_TaskAsync(req);

        return res.VslmReconcileDatastoreInventory_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObject?> VslmRegisterDisk(ManagedObjectReference self, string path, string? name)
    {
        var req = new VslmRegisterDiskRequestType
        {
            _this = self,
            path = path,
            name = name,
        };

        var res = await this.inner.VslmRegisterDiskAsync(req);

        return res.VslmRegisterDiskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmRelocateVStorageObject_Task(ManagedObjectReference self, ID id, VslmRelocateSpec spec)
    {
        var req = new VslmRelocateVStorageObjectRequestType
        {
            _this = self,
            id = id,
            spec = spec,
        };

        var res = await this.inner.VslmRelocateVStorageObject_TaskAsync(req);

        return res.VslmRelocateVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task VslmRenameVStorageObject(ManagedObjectReference self, ID id, string name)
    {
        var req = new VslmRenameVStorageObjectRequestType
        {
            _this = self,
            id = id,
            name = name,
        };

        await this.inner.VslmRenameVStorageObjectAsync(req);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotDetails?> VslmRetrieveSnapshotDetails(ManagedObjectReference self, ID id, ID snapshotId)
    {
        var req = new VslmRetrieveSnapshotDetailsRequestType
        {
            _this = self,
            id = id,
            snapshotId = snapshotId,
        };

        var res = await this.inner.VslmRetrieveSnapshotDetailsAsync(req);

        return res.VslmRetrieveSnapshotDetailsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> VslmRetrieveSnapshotInfo(ManagedObjectReference self, ID id)
    {
        var req = new VslmRetrieveSnapshotInfoRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.VslmRetrieveSnapshotInfoAsync(req);

        return res.VslmRetrieveSnapshotInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> VslmRetrieveVStorageInfrastructureObjectPolicy(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new VslmRetrieveVStorageInfrastructureObjectPolicyRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.VslmRetrieveVStorageInfrastructureObjectPolicyAsync(req);

        return res.VslmRetrieveVStorageInfrastructureObjectPolicyResponse1;
    }

    public async System.Threading.Tasks.Task<VStorageObject?> VslmRetrieveVStorageObject(ManagedObjectReference self, ID id)
    {
        var req = new VslmRetrieveVStorageObjectRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.VslmRetrieveVStorageObjectAsync(req);

        return res.VslmRetrieveVStorageObjectResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VslmVsoVStorageObjectAssociations[]?> VslmRetrieveVStorageObjectAssociations(ManagedObjectReference self, ID[]? ids)
    {
        var req = new VslmRetrieveVStorageObjectAssociationsRequestType
        {
            _this = self,
            ids = ids,
        };

        var res = await this.inner.VslmRetrieveVStorageObjectAssociationsAsync(req);

        return res.VslmRetrieveVStorageObjectAssociationsResponse1;
    }

    public async System.Threading.Tasks.Task<KeyValue[]?> VslmRetrieveVStorageObjectMetadata(ManagedObjectReference self, ID id, ID? snapshotId, string? prefix)
    {
        var req = new VslmRetrieveVStorageObjectMetadataRequestType
        {
            _this = self,
            id = id,
            snapshotId = snapshotId,
            prefix = prefix,
        };

        var res = await this.inner.VslmRetrieveVStorageObjectMetadataAsync(req);

        return res.VslmRetrieveVStorageObjectMetadataResponse1;
    }

    public async System.Threading.Tasks.Task<string?> VslmRetrieveVStorageObjectMetadataValue(ManagedObjectReference self, ID id, ID? snapshotId, string key)
    {
        var req = new VslmRetrieveVStorageObjectMetadataValueRequestType
        {
            _this = self,
            id = id,
            snapshotId = snapshotId,
            key = key,
        };

        var res = await this.inner.VslmRetrieveVStorageObjectMetadataValueAsync(req);

        return res.VslmRetrieveVStorageObjectMetadataValueResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VslmVsoVStorageObjectResult[]?> VslmRetrieveVStorageObjects(ManagedObjectReference self, ID[]? ids)
    {
        var req = new VslmRetrieveVStorageObjectsRequestType
        {
            _this = self,
            ids = ids,
        };

        var res = await this.inner.VslmRetrieveVStorageObjectsAsync(req);

        return res.VslmRetrieveVStorageObjectsResponse1;
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> VslmRetrieveVStorageObjectState(ManagedObjectReference self, ID id)
    {
        var req = new VslmRetrieveVStorageObjectStateRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.VslmRetrieveVStorageObjectStateAsync(req);

        return res.VslmRetrieveVStorageObjectStateResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmRevertVStorageObject_Task(ManagedObjectReference self, ID id, ID snapshotId)
    {
        var req = new VslmRevertVStorageObjectRequestType
        {
            _this = self,
            id = id,
            snapshotId = snapshotId,
        };

        var res = await this.inner.VslmRevertVStorageObject_TaskAsync(req);

        return res.VslmRevertVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task VslmScheduleReconcileDatastoreInventory(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new VslmScheduleReconcileDatastoreInventoryRequestType
        {
            _this = self,
            datastore = datastore,
        };

        await this.inner.VslmScheduleReconcileDatastoreInventoryAsync(req);
    }

    public async System.Threading.Tasks.Task VslmSetVStorageObjectControlFlags(ManagedObjectReference self, ID id, string[]? controlFlags)
    {
        var req = new VslmSetVStorageObjectControlFlagsRequestType
        {
            _this = self,
            id = id,
            controlFlags = controlFlags,
        };

        await this.inner.VslmSetVStorageObjectControlFlagsAsync(req);
    }

    public async System.Threading.Tasks.Task VslmSyncDatastore(ManagedObjectReference self, string datastoreUrl, bool fullSync, ID? fcdId)
    {
        var req = new VslmSyncDatastoreRequestType
        {
            _this = self,
            datastoreUrl = datastoreUrl,
            fullSync = fullSync,
            fcdId = fcdId,
        };

        await this.inner.VslmSyncDatastoreAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmUpdateVStorageInfrastructureObjectPolicy_Task(ManagedObjectReference self, vslmInfrastructureObjectPolicySpec spec)
    {
        var req = new VslmUpdateVStorageInfrastructureObjectPolicyRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.VslmUpdateVStorageInfrastructureObjectPolicy_TaskAsync(req);

        return res.VslmUpdateVStorageInfrastructureObjectPolicy_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmUpdateVStorageObjectMetadata_Task(ManagedObjectReference self, ID id, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var req = new VslmUpdateVStorageObjectMetadataRequestType
        {
            _this = self,
            id = id,
            metadata = metadata,
            deleteKeys = deleteKeys,
        };

        var res = await this.inner.VslmUpdateVStorageObjectMetadata_TaskAsync(req);

        return res.VslmUpdateVStorageObjectMetadata_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VslmUpdateVstorageObjectPolicy_Task(ManagedObjectReference self, ID id, VirtualMachineProfileSpec[]? profile)
    {
        var req = new VslmUpdateVstorageObjectPolicyRequestType
        {
            _this = self,
            id = id,
            profile = profile,
        };

        var res = await this.inner.VslmUpdateVstorageObjectPolicy_TaskAsync(req);

        return res.VslmUpdateVstorageObjectPolicy_TaskResponse.returnval;
    }
}

#pragma warning restore IDE0058 // Expression value is never used

namespace CsVmomi;

using VslmService;

#pragma warning disable IDE0058 // Expression value is never used

public partial class VslmServiceInstance : ManagedObject
{
    protected VslmServiceInstance(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<VslmServiceInstanceContent> GetPropertyContent()
    {
        var obj = await this.GetProperty<VslmServiceInstanceContent>("content").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VslmServiceInstanceContent?> RetrieveContent()
    {
        return await this.Session.VslmClient!.RetrieveContent(this.VslmReference).ConfigureAwait(false);
    }
}

public partial class VslmSessionManager : ManagedObject
{
    protected VslmSessionManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task VslmLoginByToken(string delegatedTokenXml)
    {
        await this.Session.VslmClient!.VslmLoginByToken(this.VslmReference, delegatedTokenXml).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task VslmLogout()
    {
        await this.Session.VslmClient!.VslmLogout(this.VslmReference).ConfigureAwait(false);
    }
}

public partial class VslmStorageLifecycleManager : ManagedObject
{
    protected VslmStorageLifecycleManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<VslmQueryDatastoreInfoResult[]?> VslmQueryDatastoreInfo(string datastoreUrl)
    {
        return await this.Session.VslmClient!.VslmQueryDatastoreInfo(this.VslmReference, datastoreUrl).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task VslmSyncDatastore(string datastoreUrl, bool fullSync, ID? fcdId)
    {
        await this.Session.VslmClient!.VslmSyncDatastore(this.VslmReference, datastoreUrl, fullSync, fcdId).ConfigureAwait(false);
    }
}

public partial class VslmTask : ManagedObject
{
    protected VslmTask(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task VslmCancelTask()
    {
        await this.Session.VslmClient!.VslmCancelTask(this.VslmReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmTaskInfo?> VslmQueryInfo()
    {
        return await this.Session.VslmClient!.VslmQueryInfo(this.VslmReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<object?> VslmQueryTaskResult()
    {
        return await this.Session.VslmClient!.VslmQueryTaskResult(this.VslmReference).ConfigureAwait(false);
    }
}

public partial class VslmVStorageObjectManager : ManagedObject
{
    protected VslmVStorageObjectManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmAttachDisk_Task(ID id, VirtualMachine vm, int? controllerKey, int? unitNumber)
    {
        var res = await this.Session.VslmClient!.VslmAttachDisk_Task(this.VslmReference, id, vm.VslmReference, controllerKey ?? default, controllerKey.HasValue, unitNumber ?? default, unitNumber.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task VslmAttachTagToVStorageObject(ID id, string category, string tag)
    {
        await this.Session.VslmClient!.VslmAttachTagToVStorageObject(this.VslmReference, id, category, tag).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task VslmClearVStorageObjectControlFlags(ID id, string[]? controlFlags)
    {
        await this.Session.VslmClient!.VslmClearVStorageObjectControlFlags(this.VslmReference, id, controlFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmCloneVStorageObject_Task(ID id, VslmCloneSpec spec)
    {
        var res = await this.Session.VslmClient!.VslmCloneVStorageObject_Task(this.VslmReference, id, spec).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmCreateDisk_Task(VslmCreateSpec spec)
    {
        var res = await this.Session.VslmClient!.VslmCreateDisk_Task(this.VslmReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmCreateDiskFromSnapshot_Task(ID id, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path)
    {
        var res = await this.Session.VslmClient!.VslmCreateDiskFromSnapshot_Task(this.VslmReference, id, snapshotId, name, profile, crypto, path).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmCreateSnapshot_Task(ID id, string description)
    {
        var res = await this.Session.VslmClient!.VslmCreateSnapshot_Task(this.VslmReference, id, description).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmDeleteSnapshot_Task(ID id, ID snapshotId)
    {
        var res = await this.Session.VslmClient!.VslmDeleteSnapshot_Task(this.VslmReference, id, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmDeleteVStorageObject_Task(ID id)
    {
        var res = await this.Session.VslmClient!.VslmDeleteVStorageObject_Task(this.VslmReference, id).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task VslmDetachTagFromVStorageObject(ID id, string category, string tag)
    {
        await this.Session.VslmClient!.VslmDetachTagFromVStorageObject(this.VslmReference, id, category, tag).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmExtendDisk_Task(ID id, long newCapacityInMB)
    {
        var res = await this.Session.VslmClient!.VslmExtendDisk_Task(this.VslmReference, id, newCapacityInMB).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmInflateDisk_Task(ID id)
    {
        var res = await this.Session.VslmClient!.VslmInflateDisk_Task(this.VslmReference, id).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTagEntry[]?> VslmListTagsAttachedToVStorageObject(ID id)
    {
        return await this.Session.VslmClient!.VslmListTagsAttachedToVStorageObject(this.VslmReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmVsoVStorageObjectQueryResult?> VslmListVStorageObjectForSpec(VslmVsoVStorageObjectQuerySpec[]? query, int maxResult)
    {
        return await this.Session.VslmClient!.VslmListVStorageObjectForSpec(this.VslmReference, query, maxResult).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ID[]?> VslmListVStorageObjectsAttachedToTag(string category, string tag)
    {
        return await this.Session.VslmClient!.VslmListVStorageObjectsAttachedToTag(this.VslmReference, category, tag).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> VslmQueryChangedDiskAreas(ID id, ID snapshotId, long startOffset, string changeId)
    {
        return await this.Session.VslmClient!.VslmQueryChangedDiskAreas(this.VslmReference, id, snapshotId, startOffset, changeId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmDatastoreSyncStatus[]?> VslmQueryGlobalCatalogSyncStatus()
    {
        return await this.Session.VslmClient!.VslmQueryGlobalCatalogSyncStatus(this.VslmReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmDatastoreSyncStatus?> VslmQueryGlobalCatalogSyncStatusForDatastore(string datastoreURL)
    {
        return await this.Session.VslmClient!.VslmQueryGlobalCatalogSyncStatusForDatastore(this.VslmReference, datastoreURL).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmReconcileDatastoreInventory_Task(Datastore datastore)
    {
        var res = await this.Session.VslmClient!.VslmReconcileDatastoreInventory_Task(this.VslmReference, datastore.VslmReference).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> VslmRegisterDisk(string path, string? name)
    {
        return await this.Session.VslmClient!.VslmRegisterDisk(this.VslmReference, path, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmRelocateVStorageObject_Task(ID id, VslmRelocateSpec spec)
    {
        var res = await this.Session.VslmClient!.VslmRelocateVStorageObject_Task(this.VslmReference, id, spec).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task VslmRenameVStorageObject(ID id, string name)
    {
        await this.Session.VslmClient!.VslmRenameVStorageObject(this.VslmReference, id, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotDetails?> VslmRetrieveSnapshotDetails(ID id, ID snapshotId)
    {
        return await this.Session.VslmClient!.VslmRetrieveSnapshotDetails(this.VslmReference, id, snapshotId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> VslmRetrieveSnapshotInfo(ID id)
    {
        return await this.Session.VslmClient!.VslmRetrieveSnapshotInfo(this.VslmReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> VslmRetrieveVStorageInfrastructureObjectPolicy(Datastore datastore)
    {
        return await this.Session.VslmClient!.VslmRetrieveVStorageInfrastructureObjectPolicy(this.VslmReference, datastore.VslmReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> VslmRetrieveVStorageObject(ID id)
    {
        return await this.Session.VslmClient!.VslmRetrieveVStorageObject(this.VslmReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmVsoVStorageObjectAssociations[]?> VslmRetrieveVStorageObjectAssociations(ID[]? ids)
    {
        return await this.Session.VslmClient!.VslmRetrieveVStorageObjectAssociations(this.VslmReference, ids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<KeyValue[]?> VslmRetrieveVStorageObjectMetadata(ID id, ID? snapshotId, string? prefix)
    {
        return await this.Session.VslmClient!.VslmRetrieveVStorageObjectMetadata(this.VslmReference, id, snapshotId, prefix).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> VslmRetrieveVStorageObjectMetadataValue(ID id, ID? snapshotId, string key)
    {
        return await this.Session.VslmClient!.VslmRetrieveVStorageObjectMetadataValue(this.VslmReference, id, snapshotId, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmVsoVStorageObjectResult[]?> VslmRetrieveVStorageObjects(ID[]? ids)
    {
        return await this.Session.VslmClient!.VslmRetrieveVStorageObjects(this.VslmReference, ids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> VslmRetrieveVStorageObjectState(ID id)
    {
        return await this.Session.VslmClient!.VslmRetrieveVStorageObjectState(this.VslmReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmRevertVStorageObject_Task(ID id, ID snapshotId)
    {
        var res = await this.Session.VslmClient!.VslmRevertVStorageObject_Task(this.VslmReference, id, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task VslmScheduleReconcileDatastoreInventory(Datastore datastore)
    {
        await this.Session.VslmClient!.VslmScheduleReconcileDatastoreInventory(this.VslmReference, datastore.VslmReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task VslmSetVStorageObjectControlFlags(ID id, string[]? controlFlags)
    {
        await this.Session.VslmClient!.VslmSetVStorageObjectControlFlags(this.VslmReference, id, controlFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmUpdateVStorageInfrastructureObjectPolicy_Task(vslmInfrastructureObjectPolicySpec spec)
    {
        var res = await this.Session.VslmClient!.VslmUpdateVStorageInfrastructureObjectPolicy_Task(this.VslmReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmUpdateVStorageObjectMetadata_Task(ID id, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var res = await this.Session.VslmClient!.VslmUpdateVStorageObjectMetadata_Task(this.VslmReference, id, metadata, deleteKeys).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTask?> VslmUpdateVstorageObjectPolicy_Task(ID id, VirtualMachineProfileSpec[]? profile)
    {
        var res = await this.Session.VslmClient!.VslmUpdateVstorageObjectPolicy_Task(this.VslmReference, id, profile).ConfigureAwait(false);
        return ManagedObject.Create<VslmTask>(res, this.Session);
    }
}

#pragma warning restore IDE0058 // Expression value is never used

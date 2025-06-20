namespace CsVmomi;

using VslmService;

public interface IVslmClient
{
    Uri Uri { get; }

    string? GetCookie(string name);

    System.Net.CookieCollection? GetCookie();

    void SetCookie(System.Net.CookieCollection? cookie);

    System.Threading.Tasks.Task<VslmServiceInstanceContent?> RetrieveContent(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmAttachDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference vm, int controllerKey, bool controllerKeySpecified, int unitNumber, bool unitNumberSpecified);

    System.Threading.Tasks.Task VslmAttachTagToVStorageObject(ManagedObjectReference self, ID id, string category, string tag);

    System.Threading.Tasks.Task VslmCancelTask(ManagedObjectReference self);

    System.Threading.Tasks.Task VslmClearVStorageObjectControlFlags(ManagedObjectReference self, ID id, string[]? controlFlags);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmCloneVStorageObject_Task(ManagedObjectReference self, ID id, VslmCloneSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmCreateDisk_Task(ManagedObjectReference self, VslmCreateSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmCreateDiskFromSnapshot_Task(ManagedObjectReference self, ID id, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmCreateSnapshot_Task(ManagedObjectReference self, ID id, string description);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmDeleteSnapshot_Task(ManagedObjectReference self, ID id, ID snapshotId);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmDeleteVStorageObject_Task(ManagedObjectReference self, ID id);

    System.Threading.Tasks.Task VslmDetachTagFromVStorageObject(ManagedObjectReference self, ID id, string category, string tag);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmExtendDisk_Task(ManagedObjectReference self, ID id, long newCapacityInMB);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmInflateDisk_Task(ManagedObjectReference self, ID id);

    System.Threading.Tasks.Task<VslmTagEntry[]?> VslmListTagsAttachedToVStorageObject(ManagedObjectReference self, ID id);

    System.Threading.Tasks.Task<VslmVsoVStorageObjectQueryResult?> VslmListVStorageObjectForSpec(ManagedObjectReference self, VslmVsoVStorageObjectQuerySpec[]? query, int maxResult);

    System.Threading.Tasks.Task<ID[]?> VslmListVStorageObjectsAttachedToTag(ManagedObjectReference self, string category, string tag);

    System.Threading.Tasks.Task VslmLoginByToken(ManagedObjectReference self, string delegatedTokenXml);

    System.Threading.Tasks.Task VslmLogout(ManagedObjectReference self);

    System.Threading.Tasks.Task<DiskChangeInfo?> VslmQueryChangedDiskAreas(ManagedObjectReference self, ID id, ID snapshotId, long startOffset, string changeId);

    System.Threading.Tasks.Task<VslmQueryDatastoreInfoResult[]?> VslmQueryDatastoreInfo(ManagedObjectReference self, string datastoreUrl);

    System.Threading.Tasks.Task<VslmDatastoreSyncStatus[]?> VslmQueryGlobalCatalogSyncStatus(ManagedObjectReference self);

    System.Threading.Tasks.Task<VslmDatastoreSyncStatus?> VslmQueryGlobalCatalogSyncStatusForDatastore(ManagedObjectReference self, string datastoreURL);

    System.Threading.Tasks.Task<VslmTaskInfo?> VslmQueryInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<object?> VslmQueryTaskResult(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmReconcileDatastoreInventory_Task(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<VStorageObject?> VslmRegisterDisk(ManagedObjectReference self, string path, string? name);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmRelocateVStorageObject_Task(ManagedObjectReference self, ID id, VslmRelocateSpec spec);

    System.Threading.Tasks.Task VslmRenameVStorageObject(ManagedObjectReference self, ID id, string name);

    System.Threading.Tasks.Task<VStorageObjectSnapshotDetails?> VslmRetrieveSnapshotDetails(ManagedObjectReference self, ID id, ID snapshotId);

    System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> VslmRetrieveSnapshotInfo(ManagedObjectReference self, ID id);

    System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> VslmRetrieveVStorageInfrastructureObjectPolicy(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<VStorageObject?> VslmRetrieveVStorageObject(ManagedObjectReference self, ID id);

    System.Threading.Tasks.Task<VslmVsoVStorageObjectAssociations[]?> VslmRetrieveVStorageObjectAssociations(ManagedObjectReference self, ID[]? ids);

    System.Threading.Tasks.Task<KeyValue[]?> VslmRetrieveVStorageObjectMetadata(ManagedObjectReference self, ID id, ID? snapshotId, string? prefix);

    System.Threading.Tasks.Task<string?> VslmRetrieveVStorageObjectMetadataValue(ManagedObjectReference self, ID id, ID? snapshotId, string key);

    System.Threading.Tasks.Task<VslmVsoVStorageObjectResult[]?> VslmRetrieveVStorageObjects(ManagedObjectReference self, ID[]? ids);

    System.Threading.Tasks.Task<VStorageObjectStateInfo?> VslmRetrieveVStorageObjectState(ManagedObjectReference self, ID id);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmRevertVStorageObject_Task(ManagedObjectReference self, ID id, ID snapshotId);

    System.Threading.Tasks.Task VslmScheduleReconcileDatastoreInventory(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task VslmSetVStorageObjectControlFlags(ManagedObjectReference self, ID id, string[]? controlFlags);

    System.Threading.Tasks.Task VslmSyncDatastore(ManagedObjectReference self, string datastoreUrl, bool fullSync, ID? fcdId);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmUpdateVStorageInfrastructureObjectPolicy_Task(ManagedObjectReference self, vslmInfrastructureObjectPolicySpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmUpdateVStorageObjectMetadata_Task(ManagedObjectReference self, ID id, KeyValue[]? metadata, string[]? deleteKeys);

    System.Threading.Tasks.Task<ManagedObjectReference?> VslmUpdateVstorageObjectPolicy_Task(ManagedObjectReference self, ID id, VirtualMachineProfileSpec[]? profile);

}

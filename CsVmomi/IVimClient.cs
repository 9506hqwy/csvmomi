namespace CsVmomi;

public interface IVimClient
{
    Uri Uri { get; }

    string? GetCookie(string name);

    System.Net.CookieCollection? GetCookie();

    void SetCookie(System.Net.CookieCollection? cookie);

    System.Threading.Tasks.Task AbandonHciWorkflow(ManagedObjectReference self);

    System.Threading.Tasks.Task<string[]?> AbdicateDomOwnership(ManagedObjectReference self, string[] uuids);

    System.Threading.Tasks.Task<ManagedObjectReference?> AbortCustomization_Task(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth);

    System.Threading.Tasks.Task AcknowledgeAlarm(ManagedObjectReference self, ManagedObjectReference alarm, ManagedObjectReference entity);

    System.Threading.Tasks.Task<HostServiceTicket?> AcquireCimServicesTicket(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> AcquireCloneTicket(ManagedObjectReference self);

    System.Threading.Tasks.Task<GuestAuthentication?> AcquireCredentialsInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication requestedAuth, long sessionID, bool sessionIDSpecified);

    System.Threading.Tasks.Task<SessionManagerGenericServiceTicket?> AcquireGenericServiceTicket(ManagedObjectReference self, SessionManagerServiceRequestSpec spec);

    System.Threading.Tasks.Task<SessionManagerLocalTicket?> AcquireLocalTicket(ManagedObjectReference self, string userName);

    System.Threading.Tasks.Task<VirtualMachineMksTicket?> AcquireMksTicket(ManagedObjectReference self);

    System.Threading.Tasks.Task<VirtualMachineTicket?> AcquireTicket(ManagedObjectReference self, string ticketType);

    System.Threading.Tasks.Task<int> AddAuthorizationRole(ManagedObjectReference self, string name, string[]? privIds);

    System.Threading.Tasks.Task<CustomFieldDef?> AddCustomFieldDef(ManagedObjectReference self, string name, string? moType, PrivilegePolicyDef? fieldDefPolicy, PrivilegePolicyDef? fieldPolicy);

    System.Threading.Tasks.Task<ManagedObjectReference?> AddDisks_Task(ManagedObjectReference self, HostScsiDisk[] disk);

    System.Threading.Tasks.Task<ManagedObjectReference?> AddDVPortgroup_Task(ManagedObjectReference self, DVPortgroupConfigSpec[] spec);

    System.Threading.Tasks.Task<string?> AddFilter(ManagedObjectReference self, string providerId, string filterName, string[]? infoIds);

    System.Threading.Tasks.Task AddFilterEntities(ManagedObjectReference self, string filterId, ManagedObjectReference[]? entities);

    System.Threading.Tasks.Task AddGuestAlias(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username, bool mapCert, string base64Cert, GuestAuthAliasInfo aliasInfo);

    System.Threading.Tasks.Task<ManagedObjectReference?> AddHost_Task(ManagedObjectReference self, HostConnectSpec spec, bool asConnected, ManagedObjectReference? resourcePool, string? license);

    System.Threading.Tasks.Task AddInternetScsiSendTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets);

    System.Threading.Tasks.Task AddInternetScsiStaticTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets);

    System.Threading.Tasks.Task AddKey(ManagedObjectReference self, CryptoKeyPlain key);

    System.Threading.Tasks.Task<CryptoKeyResult[]?> AddKeys(ManagedObjectReference self, CryptoKeyPlain[]? keys);

    System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> AddLicense(ManagedObjectReference self, string licenseKey, KeyValue[]? labels);

    System.Threading.Tasks.Task AddMonitoredEntities(ManagedObjectReference self, string providerId, ManagedObjectReference[]? entities);

    System.Threading.Tasks.Task AddNetworkResourcePool(ManagedObjectReference self, DVSNetworkResourcePoolConfigSpec[] configSpec);

    System.Threading.Tasks.Task AddPortGroup(ManagedObjectReference self, HostPortGroupSpec portgrp);

    System.Threading.Tasks.Task<string?> AddServiceConsoleVirtualNic(ManagedObjectReference self, string portgroup, HostVirtualNicSpec nic);

    System.Threading.Tasks.Task<ManagedObjectReference?> AddStandaloneHost_Task(ManagedObjectReference self, HostConnectSpec spec, ComputeResourceConfigSpec? compResSpec, bool addConnected, string? license);

    System.Threading.Tasks.Task<string?> AddVirtualNic(ManagedObjectReference self, string portgroup, HostVirtualNicSpec nic);

    System.Threading.Tasks.Task AddVirtualSwitch(ManagedObjectReference self, string vswitchName, HostVirtualSwitchSpec? spec);

    System.Threading.Tasks.Task<string?> AllocateIpv4Address(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string allocationId);

    System.Threading.Tasks.Task<string?> AllocateIpv6Address(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string allocationId);

    System.Threading.Tasks.Task AnswerVM(ManagedObjectReference self, string questionId, string answerChoice);

    System.Threading.Tasks.Task<ManagedObjectReference?> ApplyEntitiesConfig_Task(ManagedObjectReference self, ApplyHostProfileConfigurationSpec[]? applyConfigSpecs);

    System.Threading.Tasks.Task<ManagedObjectReference?> ApplyEvcModeVM_Task(ManagedObjectReference self, HostFeatureMask[]? mask, bool completeMasks, bool completeMasksSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> ApplyHostConfig_Task(ManagedObjectReference self, ManagedObjectReference host, HostConfigSpec configSpec, ProfileDeferredPolicyOptionParameter[]? userInput);

    System.Threading.Tasks.Task ApplyRecommendation(ManagedObjectReference self, string key);

    System.Threading.Tasks.Task<ManagedObjectReference?> ApplyStorageDrsRecommendation_Task(ManagedObjectReference self, string[] key);

    System.Threading.Tasks.Task<ManagedObjectReference?> ApplyStorageDrsRecommendationToPod_Task(ManagedObjectReference self, ManagedObjectReference pod, string key);

    System.Threading.Tasks.Task<bool> AreAlarmActionsEnabled(ManagedObjectReference self, ManagedObjectReference entity);

    System.Threading.Tasks.Task AssignUserToGroup(ManagedObjectReference self, string user, string group);

    System.Threading.Tasks.Task AssociateProfile(ManagedObjectReference self, ManagedObjectReference[] entity);

    System.Threading.Tasks.Task<ManagedObjectReference?> AttachDisk_Task(ManagedObjectReference self, ID diskId, ManagedObjectReference datastore, int controllerKey, bool controllerKeySpecified, int unitNumber, bool unitNumberSpecified);

    System.Threading.Tasks.Task AttachScsiLun(ManagedObjectReference self, string lunUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> AttachScsiLunEx_Task(ManagedObjectReference self, string[] lunUuid);

    System.Threading.Tasks.Task AttachTagToVStorageObject(ManagedObjectReference self, ID id, string category, string tag);

    System.Threading.Tasks.Task AttachVmfsExtent(ManagedObjectReference self, string vmfsPath, HostScsiDiskPartition extent);

    System.Threading.Tasks.Task AutoStartPowerOff(ManagedObjectReference self);

    System.Threading.Tasks.Task AutoStartPowerOn(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> BackupFirmwareConfiguration(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> BatchAddHostsToCluster_Task(ManagedObjectReference self, ManagedObjectReference cluster, FolderNewHostSpec[]? newHosts, ManagedObjectReference[]? existingHosts, ComputeResourceConfigSpec? compResSpec, string? desiredState);

    System.Threading.Tasks.Task<ManagedObjectReference?> BatchAddStandaloneHosts_Task(ManagedObjectReference self, FolderNewHostSpec[]? newHosts, ComputeResourceConfigSpec? compResSpec, bool addConnected);

    System.Threading.Tasks.Task<DatacenterBasicConnectInfo[]?> BatchQueryConnectInfo(ManagedObjectReference self, HostConnectSpec[]? hostSpecs);

    System.Threading.Tasks.Task BindVnic(ManagedObjectReference self, string iScsiHbaName, string vnicDevice);

    System.Threading.Tasks.Task<DiagnosticManagerLogHeader?> BrowseDiagnosticLog(ManagedObjectReference self, ManagedObjectReference? host, string key, int start, bool startSpecified, int lines, bool linesSpecified);

    System.Threading.Tasks.Task CancelRecommendation(ManagedObjectReference self, string key);

    System.Threading.Tasks.Task CancelRetrievePropertiesEx(ManagedObjectReference self, string token);

    System.Threading.Tasks.Task CancelStorageDrsRecommendation(ManagedObjectReference self, string[] key);

    System.Threading.Tasks.Task CancelTask(ManagedObjectReference self);

    System.Threading.Tasks.Task CancelWaitForUpdates(ManagedObjectReference self);

    System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> CanProvisionObjects(ManagedObjectReference self, VsanNewPolicyBatch[] npbs, bool ignoreSatisfiability, bool ignoreSatisfiabilitySpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> CertMgrRefreshCACertificatesAndCRLs_Task(ManagedObjectReference self, ManagedObjectReference[] host);

    System.Threading.Tasks.Task<ManagedObjectReference?> CertMgrRefreshCertificates_Task(ManagedObjectReference self, ManagedObjectReference[] host);

    System.Threading.Tasks.Task<ManagedObjectReference?> CertMgrRevokeCertificates_Task(ManagedObjectReference self, ManagedObjectReference[] host);

    System.Threading.Tasks.Task ChangeAccessMode(ManagedObjectReference self, string principal, bool isGroup, HostAccessMode accessMode);

    System.Threading.Tasks.Task ChangeFileAttributesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes);

    System.Threading.Tasks.Task<ManagedObjectReference?> ChangeKey_Task(ManagedObjectReference self, CryptoKeyPlain newKey);

    System.Threading.Tasks.Task ChangeLockdownMode(ManagedObjectReference self, HostLockdownMode mode);

    System.Threading.Tasks.Task ChangeNFSUserPassword(ManagedObjectReference self, string password);

    System.Threading.Tasks.Task ChangeOwner(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, string owner);

    System.Threading.Tasks.Task ChangePassword(ManagedObjectReference self, string user, string oldPassword, string newPassword);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckAddHostEvc_Task(ManagedObjectReference self, HostConnectSpec cnxSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckAnswerFileStatus_Task(ManagedObjectReference self, ManagedObjectReference[] host);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckClone_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference folder, string name, VirtualMachineCloneSpec spec, string[]? testType);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckCompatibility_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host, ManagedObjectReference? pool, string[]? testType);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckCompliance_Task(ManagedObjectReference self, ManagedObjectReference[]? profile, ManagedObjectReference[]? entity);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckConfigureEvcMode_Task(ManagedObjectReference self, string evcModeKey, string? evcGraphicsModeKey);

    System.Threading.Tasks.Task CheckCustomizationResources(ManagedObjectReference self, string guestOs);

    System.Threading.Tasks.Task CheckCustomizationSpec(ManagedObjectReference self, CustomizationSpec spec);

    System.Threading.Tasks.Task<UpdateSet?> CheckForUpdates(ManagedObjectReference self, string? version);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckHostPatch_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, HostPatchManagerPatchManagerOperationSpec? spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckInstantClone_Task(ManagedObjectReference self, ManagedObjectReference vm, VirtualMachineInstantCloneSpec spec, string[]? testType);

    System.Threading.Tasks.Task<bool> CheckLicenseFeature(ManagedObjectReference self, ManagedObjectReference? host, string featureKey);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckMigrate_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host, ManagedObjectReference? pool, VirtualMachinePowerState state, bool stateSpecified, string[]? testType);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckPowerOn_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host, ManagedObjectReference? pool, string[]? testType);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckProfileCompliance_Task(ManagedObjectReference self, ManagedObjectReference[]? entity);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckRelocate_Task(ManagedObjectReference self, ManagedObjectReference vm, VirtualMachineRelocateSpec spec, string[]? testType);

    System.Threading.Tasks.Task<ManagedObjectReference?> CheckVmConfig_Task(ManagedObjectReference self, VirtualMachineConfigSpec spec, ManagedObjectReference? vm, ManagedObjectReference? host, ManagedObjectReference? pool, string[]? testType);

    System.Threading.Tasks.Task ClearComplianceStatus(ManagedObjectReference self, ManagedObjectReference[]? profile, ManagedObjectReference[]? entity);

    System.Threading.Tasks.Task ClearNFSUser(ManagedObjectReference self);

    System.Threading.Tasks.Task ClearSystemEventLog(ManagedObjectReference self);

    System.Threading.Tasks.Task ClearTriggeredAlarms(ManagedObjectReference self, AlarmFilterSpec filter);

    System.Threading.Tasks.Task ClearVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags);

    System.Threading.Tasks.Task<UserSession?> CloneSession(ManagedObjectReference self, string cloneTicket);

    System.Threading.Tasks.Task<ManagedObjectReference?> CloneVApp_Task(ManagedObjectReference self, string name, ManagedObjectReference target, VAppCloneSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CloneVM_Task(ManagedObjectReference self, ManagedObjectReference folder, string name, VirtualMachineCloneSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CloneVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmCloneSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> CloseInventoryViewFolder(ManagedObjectReference self, ManagedObjectReference[] entity);

    System.Threading.Tasks.Task<ClusterEnterMaintenanceResult?> ClusterEnterMaintenanceMode(ManagedObjectReference self, ManagedObjectReference[] host, OptionValue[]? option, ClusterComputeResourceMaintenanceInfo? info);

    System.Threading.Tasks.Task<ManagedObjectReference?> CompositeHostProfile_Task(ManagedObjectReference self, ManagedObjectReference source, ManagedObjectReference[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toBeReplacedWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied);

    System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfo(ManagedObjectReference self, string devicePath, HostDiskPartitionLayout layout, string? partitionFormat);

    System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfoForResize(ManagedObjectReference self, HostScsiDiskPartition partition, HostDiskPartitionBlockRange blockRange, string? partitionFormat);

    System.Threading.Tasks.Task ConfigureCryptoKey(ManagedObjectReference self, CryptoKeyId? keyId);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureDatastoreIORM_Task(ManagedObjectReference self, ManagedObjectReference datastore, StorageIORMConfigSpec spec);

    System.Threading.Tasks.Task ConfigureDatastorePrincipal(ManagedObjectReference self, string userName, string? password);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureEvcMode_Task(ManagedObjectReference self, string evcModeKey, string? evcGraphicsModeKey);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureHCI_Task(ManagedObjectReference self, ClusterComputeResourceHCIConfigSpec clusterSpec, ClusterComputeResourceHostConfigurationInput[]? hostInputs);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureHostCache_Task(ManagedObjectReference self, HostCacheConfigurationSpec spec);

    System.Threading.Tasks.Task ConfigureLicenseSource(ManagedObjectReference self, ManagedObjectReference? host, LicenseSource licenseSource);

    System.Threading.Tasks.Task ConfigurePowerPolicy(ManagedObjectReference self, int key);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureStorageDrsForPod_Task(ManagedObjectReference self, ManagedObjectReference pod, StorageDrsConfigSpec spec, bool modify);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureVcha_Task(ManagedObjectReference self, VchaClusterConfigSpec configSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureVFlashResourceEx_Task(ManagedObjectReference self, string[]? devicePath);

    System.Threading.Tasks.Task ConnectNvmeController(ManagedObjectReference self, HostNvmeConnectSpec connectSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConnectNvmeControllerEx_Task(ManagedObjectReference self, HostNvmeConnectSpec[]? connectSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ConsolidateVMDisks_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<RetrieveResult?> ContinueRetrievePropertiesEx(ManagedObjectReference self, string token);

    System.Threading.Tasks.Task<string?> ConvertNamespacePathToUuidPath(ManagedObjectReference self, ManagedObjectReference? datacenter, string namespaceUrl);

    System.Threading.Tasks.Task<ManagedObjectReference?> CopyDatastoreFile_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destinationName, ManagedObjectReference? destinationDatacenter, bool force, bool forceSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> CopyVirtualDisk_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destName, ManagedObjectReference? destDatacenter, VirtualDiskSpec? destSpec, bool force, bool forceSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateAlarm(ManagedObjectReference self, ManagedObjectReference entity, AlarmSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateChildVM_Task(ManagedObjectReference self, VirtualMachineConfigSpec config, ManagedObjectReference? host);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateCluster(ManagedObjectReference self, string name, ClusterConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateClusterEx(ManagedObjectReference self, string name, ClusterConfigSpecEx spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateCollectorForEvents(ManagedObjectReference self, EventFilterSpec filter);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateCollectorForTasks(ManagedObjectReference self, TaskFilterSpec filter);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateCollectorWithInfoFilterForTasks(ManagedObjectReference self, TaskFilterSpec filter, TaskInfoFilterSpec? infoFilter);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateContainerView(ManagedObjectReference self, ManagedObjectReference container, string[]? type, bool recursive);

    System.Threading.Tasks.Task CreateCustomizationSpec(ManagedObjectReference self, CustomizationSpecItem item);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateDatacenter(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task<ApplyProfile?> CreateDefaultProfile(ManagedObjectReference self, string profileType, string? profileTypeName, ManagedObjectReference? profile);

    System.Threading.Tasks.Task<OvfCreateDescriptorResult?> CreateDescriptor(ManagedObjectReference self, ManagedObjectReference obj, OvfCreateDescriptorParams cdp);

    System.Threading.Tasks.Task CreateDiagnosticPartition(ManagedObjectReference self, HostDiagnosticPartitionCreateSpec spec);

    System.Threading.Tasks.Task<string?> CreateDirectory(ManagedObjectReference self, ManagedObjectReference datastore, string? displayName, string? policy, long size, bool sizeSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateDisk_Task(ManagedObjectReference self, VslmCreateSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateDiskFromSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateDVPortgroup_Task(ManagedObjectReference self, DVPortgroupConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateDVS_Task(ManagedObjectReference self, DVSCreateSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateFilter(ManagedObjectReference self, PropertyFilterSpec spec, bool partialUpdates);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateFolder(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task CreateGroup(ManagedObjectReference self, HostAccountSpec group);

    System.Threading.Tasks.Task<OvfCreateImportSpecResult?> CreateImportSpec(ManagedObjectReference self, string ovfDescriptor, ManagedObjectReference resourcePool, ManagedObjectReference datastore, OvfCreateImportSpecParams cisp);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateInventoryView(ManagedObjectReference self);

    System.Threading.Tasks.Task<int> CreateIpPool(ManagedObjectReference self, ManagedObjectReference dc, IpPool pool);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateListView(ManagedObjectReference self, ManagedObjectReference[]? obj);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateListViewFromView(ManagedObjectReference self, ManagedObjectReference view);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateLocalDatastore(ManagedObjectReference self, string name, string path);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateNasDatastore(ManagedObjectReference self, HostNasVolumeSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateNvdimmNamespace_Task(ManagedObjectReference self, NvdimmNamespaceCreateSpec createSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateNvdimmPMemNamespace_Task(ManagedObjectReference self, NvdimmPMemNamespaceCreateSpec createSpec);

    System.Threading.Tasks.Task CreateNvmeOverRdmaAdapter(ManagedObjectReference self, string rdmaDeviceName);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateObjectScheduledTask(ManagedObjectReference self, ManagedObjectReference obj, ScheduledTaskSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreatePassiveNode_Task(ManagedObjectReference self, PassiveNodeDeploymentSpec passiveDeploymentSpec, SourceNodeSpec sourceVcSpec);

    System.Threading.Tasks.Task CreatePerfInterval(ManagedObjectReference self, PerfInterval intervalId);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateProfile(ManagedObjectReference self, ProfileCreateSpec createSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreatePropertyCollector(ManagedObjectReference self);

    System.Threading.Tasks.Task CreateRegistryKeyInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool isVolatile, string? classType);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateResourcePool(ManagedObjectReference self, string name, ResourceConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateScheduledTask(ManagedObjectReference self, ManagedObjectReference entity, ScheduledTaskSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateScreenshot_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateSecondaryVM_Task(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateSecondaryVMEx_Task(ManagedObjectReference self, ManagedObjectReference? host, FaultToleranceConfigSpec? spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateSnapshot_Task(ManagedObjectReference self, string name, string? description, bool memory, bool quiesce);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateSnapshotEx_Task(ManagedObjectReference self, string name, string? description, bool memory, VirtualMachineGuestQuiesceSpec? quiesceSpec);

    System.Threading.Tasks.Task CreateSoftwareAdapter(ManagedObjectReference self, HostHbaCreateSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateStoragePod(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task<TaskInfo?> CreateTask(ManagedObjectReference self, ManagedObjectReference obj, string taskTypeId, string? initiatedBy, bool cancelable, string? parentTaskKey, string? activationId);

    System.Threading.Tasks.Task<string?> CreateTemporaryDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath);

    System.Threading.Tasks.Task<string?> CreateTemporaryFileInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath);

    System.Threading.Tasks.Task CreateUser(ManagedObjectReference self, HostAccountSpec user);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateVApp(ManagedObjectReference self, string name, ResourceConfigSpec resSpec, VAppConfigSpec configSpec, ManagedObjectReference? vmFolder);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, VirtualDiskSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateVM_Task(ManagedObjectReference self, VirtualMachineConfigSpec config, ManagedObjectReference pool, ManagedObjectReference? host);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateVmfsDatastore(ManagedObjectReference self, VmfsDatastoreCreateSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateVvolDatastore(ManagedObjectReference self, HostDatastoreSystemVvolDatastoreSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> CreateWitnessNode_Task(ManagedObjectReference self, NodeDeploymentSpec witnessDeploymentSpec, SourceNodeSpec sourceVcSpec);

    System.Threading.Tasks.Task CryptoManagerHostDisable(ManagedObjectReference self);

    System.Threading.Tasks.Task CryptoManagerHostEnable(ManagedObjectReference self, CryptoKeyPlain initialKey);

    System.Threading.Tasks.Task CryptoManagerHostPrepare(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> CryptoUnlock_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<DateTime> CurrentTime(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> CustomizationSpecItemToXml(ManagedObjectReference self, CustomizationSpecItem item);

    System.Threading.Tasks.Task<ManagedObjectReference?> CustomizeGuest_Task(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, CustomizationSpec spec, OptionValue[]? configParams);

    System.Threading.Tasks.Task<ManagedObjectReference?> CustomizeVM_Task(ManagedObjectReference self, CustomizationSpec spec);

    System.Threading.Tasks.Task<StoragePlacementResult?> DatastoreEnterMaintenanceMode(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> DatastoreExitMaintenanceMode_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> DecodeLicense(ManagedObjectReference self, string licenseKey);

    System.Threading.Tasks.Task DefragmentAllDisks(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> DefragmentVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task DeleteCustomizationSpec(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeleteDatastoreFile_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task DeleteDirectory(ManagedObjectReference self, ManagedObjectReference? datacenter, string datastorePath);

    System.Threading.Tasks.Task DeleteDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string directoryPath, bool recursive);

    System.Threading.Tasks.Task DeleteFile(ManagedObjectReference self, string datastorePath);

    System.Threading.Tasks.Task DeleteFileInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string filePath);

    System.Threading.Tasks.Task DeleteHostSpecification(ManagedObjectReference self, ManagedObjectReference host);

    System.Threading.Tasks.Task DeleteHostSubSpecification(ManagedObjectReference self, ManagedObjectReference host, string subSpecName);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeleteNvdimmBlockNamespaces_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeleteNvdimmNamespace_Task(ManagedObjectReference self, NvdimmNamespaceDeleteSpec deleteSpec);

    System.Threading.Tasks.Task DeleteRegistryKeyInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive);

    System.Threading.Tasks.Task DeleteRegistryValueInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegValueNameSpec valueName);

    System.Threading.Tasks.Task DeleteScsiLunState(ManagedObjectReference self, string lunCanonicalName);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeleteSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task DeleteVffsVolumeState(ManagedObjectReference self, string vffsUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeleteVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task DeleteVmfsVolumeState(ManagedObjectReference self, string vmfsUuid);

    System.Threading.Tasks.Task<HostVsanInternalSystemDeleteVsanObjectsResult[]?> DeleteVsanObjects(ManagedObjectReference self, string[] uuids, bool force, bool forceSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeleteVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeleteVStorageObjectEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> DeployVcha_Task(ManagedObjectReference self, VchaClusterDeploymentSpec deploymentSpec);

    System.Threading.Tasks.Task DeselectVnic(ManagedObjectReference self);

    System.Threading.Tasks.Task DeselectVnicForNicType(ManagedObjectReference self, string nicType, string device);

    System.Threading.Tasks.Task<ManagedObjectReference?> Destroy_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyChildren(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyCollector(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyDatastore(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyIpPool(ManagedObjectReference self, ManagedObjectReference dc, int id, bool force);

    System.Threading.Tasks.Task DestroyNetwork(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyProfile(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyPropertyCollector(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyPropertyFilter(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> DestroyVcha_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task DestroyVffs(ManagedObjectReference self, string vffsPath);

    System.Threading.Tasks.Task DestroyView(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> DetachDisk_Task(ManagedObjectReference self, ID diskId);

    System.Threading.Tasks.Task DetachScsiLun(ManagedObjectReference self, string lunUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> DetachScsiLunEx_Task(ManagedObjectReference self, string[] lunUuid);

    System.Threading.Tasks.Task DetachTagFromVStorageObject(ManagedObjectReference self, ID id, string category, string tag);

    System.Threading.Tasks.Task<string?> DirectPathProfileManagerCreate(ManagedObjectReference self, DirectPathProfileManagerCreateSpec spec);

    System.Threading.Tasks.Task DirectPathProfileManagerDelete(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<DirectPathProfileInfo[]?> DirectPathProfileManagerList(ManagedObjectReference self, DirectPathProfileManagerFilterSpec filterSpec);

    System.Threading.Tasks.Task<DirectPathProfileManagerCapacityResult[]?> DirectPathProfileManagerQueryCapacity(ManagedObjectReference self, DirectPathProfileManagerTargetEntity target, DirectPathProfileManagerCapacityQuerySpec[]? querySpec);

    System.Threading.Tasks.Task DirectPathProfileManagerUpdate(ManagedObjectReference self, string id, DirectPathProfileManagerUpdateSpec spec);

    System.Threading.Tasks.Task DisableAlarm(ManagedObjectReference self, ManagedObjectReference alarm, ManagedObjectReference entity);

    System.Threading.Tasks.Task DisableClusteredVmdkSupport(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> DisableEvcMode_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<bool> DisableFeature(ManagedObjectReference self, ManagedObjectReference? host, string featureKey);

    System.Threading.Tasks.Task DisableHyperThreading(ManagedObjectReference self);

    System.Threading.Tasks.Task DisableMultipathPath(ManagedObjectReference self, string pathName);

    System.Threading.Tasks.Task<ManagedObjectReference?> DisableNetworkBoot_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task DisableRuleset(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<ManagedObjectReference?> DisableSecondaryVM_Task(ManagedObjectReference self, ManagedObjectReference vm);

    System.Threading.Tasks.Task DisableSmartCardAuthentication(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> DisconnectHost_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task DisconnectNvmeController(ManagedObjectReference self, HostNvmeDisconnectSpec disconnectSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> DisconnectNvmeControllerEx_Task(ManagedObjectReference self, HostNvmeDisconnectSpec[]? disconnectSpec);

    System.Threading.Tasks.Task DiscoverFcoeHbas(ManagedObjectReference self, FcoeConfigFcoeSpecification fcoeSpec);

    System.Threading.Tasks.Task<HostNvmeDiscoveryLog?> DiscoverNvmeControllers(ManagedObjectReference self, HostNvmeDiscoverSpec discoverSpec);

    System.Threading.Tasks.Task DissociateProfile(ManagedObjectReference self, ManagedObjectReference[]? entity);

    System.Threading.Tasks.Task<bool> DoesCustomizationSpecExist(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task<byte[]?> DownloadDescriptionTree(ManagedObjectReference self);

    System.Threading.Tasks.Task<bool> DropConnections(ManagedObjectReference self, VirtualMachineConnection[]? listOfConnections);

    System.Threading.Tasks.Task DuplicateCustomizationSpec(ManagedObjectReference self, string name, string newName);

    System.Threading.Tasks.Task<ManagedObjectReference?> DVPortgroupRollback_Task(ManagedObjectReference self, EntityBackupConfig? entityBackup);

    System.Threading.Tasks.Task<ManagedObjectReference?> DVSManagerExportEntity_Task(ManagedObjectReference self, SelectionSet[] selectionSet);

    System.Threading.Tasks.Task<ManagedObjectReference?> DVSManagerImportEntity_Task(ManagedObjectReference self, EntityBackupConfig[] entityBackup, string importType);

    System.Threading.Tasks.Task<ManagedObjectReference?> DVSManagerLookupDvPortGroup(ManagedObjectReference self, string switchUuid, string portgroupKey);

    System.Threading.Tasks.Task<ManagedObjectReference?> DvsReconfigureVmVnicNetworkResourcePool_Task(ManagedObjectReference self, DvsVmVnicResourcePoolConfigSpec[] configSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> DVSRollback_Task(ManagedObjectReference self, EntityBackupConfig? entityBackup);

    System.Threading.Tasks.Task<ManagedObjectReference?> EagerZeroVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task EmitSyslogMark(ManagedObjectReference self, string message);

    System.Threading.Tasks.Task EnableAlarm(ManagedObjectReference self, ManagedObjectReference alarm, ManagedObjectReference entity);

    System.Threading.Tasks.Task EnableAlarmActions(ManagedObjectReference self, ManagedObjectReference entity, bool enabled);

    System.Threading.Tasks.Task EnableClusteredVmdkSupport(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task EnableCrypto(ManagedObjectReference self, CryptoKeyPlain keyPlain);

    System.Threading.Tasks.Task<bool> EnableFeature(ManagedObjectReference self, ManagedObjectReference? host, string featureKey);

    System.Threading.Tasks.Task EnableHyperThreading(ManagedObjectReference self);

    System.Threading.Tasks.Task EnableMultipathPath(ManagedObjectReference self, string pathName);

    System.Threading.Tasks.Task<ManagedObjectReference?> EnableNetworkBoot_Task(ManagedObjectReference self, string networkBootMode);

    System.Threading.Tasks.Task EnableNetworkResourceManagement(ManagedObjectReference self, bool enable);

    System.Threading.Tasks.Task EnableRuleset(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<ManagedObjectReference?> EnableSecondaryVM_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host);

    System.Threading.Tasks.Task EnableSmartCardAuthentication(ManagedObjectReference self);

    System.Threading.Tasks.Task EnterLockdownMode(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> EnterMaintenanceMode_Task(ManagedObjectReference self, int timeout, bool evacuatePoweredOffVms, bool evacuatePoweredOffVmsSpecified, HostMaintenanceSpec? maintenanceSpec);

    System.Threading.Tasks.Task<DatabaseSizeEstimate?> EstimateDatabaseSize(ManagedObjectReference self, DatabaseSizeParam dbSizeParam);

    System.Threading.Tasks.Task<ManagedObjectReference?> EstimateStorageForConsolidateSnapshots_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task EsxAgentHostManagerUpdateConfig(ManagedObjectReference self, HostEsxAgentHostManagerConfigInfo configInfo);

    System.Threading.Tasks.Task<ManagedObjectReference?> EvacuateVsanNode_Task(ManagedObjectReference self, HostMaintenanceSpec maintenanceSpec, int timeout);

    System.Threading.Tasks.Task<ManagedObjectReference?> EvcManager(ManagedObjectReference self);

    System.Threading.Tasks.Task<ProfileExecuteResult?> ExecuteHostProfile(ManagedObjectReference self, ManagedObjectReference host, ProfileDeferredPolicyOptionParameter[]? deferredParam);

    System.Threading.Tasks.Task<string?> ExecuteSimpleCommand(ManagedObjectReference self, string[]? arguments);

    System.Threading.Tasks.Task ExitLockdownMode(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExitMaintenanceMode_Task(ManagedObjectReference self, int timeout);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExpandVmfsDatastore(ManagedObjectReference self, ManagedObjectReference datastore, VmfsDatastoreExpandSpec spec);

    System.Threading.Tasks.Task ExpandVmfsExtent(ManagedObjectReference self, string vmfsPath, HostScsiDiskPartition extent);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExportAnswerFile_Task(ManagedObjectReference self, ManagedObjectReference host);

    System.Threading.Tasks.Task<string?> ExportProfile(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExportSnapshot(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExportVApp(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExportVm(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExtendDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, long newCapacityInMB);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExtendHCI_Task(ManagedObjectReference self, ClusterComputeResourceHostConfigurationInput[]? hostInputs, SDDCBase? vSanConfigSpec);

    System.Threading.Tasks.Task ExtendVffs(ManagedObjectReference self, string vffsPath, string devicePath, HostDiskPartitionSpec? spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExtendVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, long newCapacityKb, bool eagerZero, bool eagerZeroSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> ExtendVmfsDatastore(ManagedObjectReference self, ManagedObjectReference datastore, VmfsDatastoreExtendSpec spec);

    System.Threading.Tasks.Task<string?> ExtractOvfEnvironment(ManagedObjectReference self);

    System.Threading.Tasks.Task<DiagnosticManagerAuditRecordResult?> FetchAuditRecords(ManagedObjectReference self, string? token);

    System.Threading.Tasks.Task<string[]?> FetchDVPortKeys(ManagedObjectReference self, DistributedVirtualSwitchPortCriteria? criteria);

    System.Threading.Tasks.Task<DistributedVirtualPort[]?> FetchDVPorts(ManagedObjectReference self, DistributedVirtualSwitchPortCriteria? criteria);

    System.Threading.Tasks.Task<SoftwarePackage[]?> FetchSoftwarePackages(ManagedObjectReference self);

    System.Threading.Tasks.Task<SystemEventInfo[]?> FetchSystemEventLog(ManagedObjectReference self);

    System.Threading.Tasks.Task<UserPrivilegeResult[]?> FetchUserPrivilegeOnEntities(ManagedObjectReference self, ManagedObjectReference[] entities, string userName);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAllByDnsName(ManagedObjectReference self, ManagedObjectReference? datacenter, string dnsName, bool vmSearch);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAllByIp(ManagedObjectReference self, ManagedObjectReference? datacenter, string ip, bool vmSearch);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAllByUuid(ManagedObjectReference self, ManagedObjectReference? datacenter, string uuid, bool vmSearch, bool instanceUuid, bool instanceUuidSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAssociatedProfile(ManagedObjectReference self, ManagedObjectReference entity);

    System.Threading.Tasks.Task<ManagedObjectReference?> FindByDatastorePath(ManagedObjectReference self, ManagedObjectReference datacenter, string path);

    System.Threading.Tasks.Task<ManagedObjectReference?> FindByDnsName(ManagedObjectReference self, ManagedObjectReference? datacenter, string dnsName, bool vmSearch);

    System.Threading.Tasks.Task<ManagedObjectReference?> FindByInventoryPath(ManagedObjectReference self, string inventoryPath);

    System.Threading.Tasks.Task<ManagedObjectReference?> FindByIp(ManagedObjectReference self, ManagedObjectReference? datacenter, string ip, bool vmSearch);

    System.Threading.Tasks.Task<ManagedObjectReference?> FindByUuid(ManagedObjectReference self, ManagedObjectReference? datacenter, string uuid, bool vmSearch, bool instanceUuid, bool instanceUuidSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> FindChild(ManagedObjectReference self, ManagedObjectReference entity, string name);

    System.Threading.Tasks.Task<Extension?> FindExtension(ManagedObjectReference self, string extensionKey);

    System.Threading.Tasks.Task<ClusterRuleInfo[]?> FindRulesForVm(ManagedObjectReference self, ManagedObjectReference vm);

    System.Threading.Tasks.Task<HostVffsVolume?> FormatVffs(ManagedObjectReference self, HostVffsSpec createSpec);

    System.Threading.Tasks.Task<HostVmfsVolume?> FormatVmfs(ManagedObjectReference self, HostVmfsSpec createSpec);

    System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequest(ManagedObjectReference self, bool useIpAddressAsCommonName, HostCertificateManagerCertificateSpec? spec);

    System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequestByDn(ManagedObjectReference self, string distinguishedName, HostCertificateManagerCertificateSpec? spec);

    System.Threading.Tasks.Task<string?> GenerateClientCsr(ManagedObjectReference self, KeyProviderId cluster, CryptoManagerKmipCertSignRequest? request);

    System.Threading.Tasks.Task<HostProfileManagerConfigTaskList?> GenerateConfigTaskList(ManagedObjectReference self, HostConfigSpec configSpec, ManagedObjectReference host);

    System.Threading.Tasks.Task<ManagedObjectReference?> GenerateHostConfigTaskSpec_Task(ManagedObjectReference self, StructuredCustomizations[]? hostsInfo);

    System.Threading.Tasks.Task<ManagedObjectReference?> GenerateHostProfileTaskList_Task(ManagedObjectReference self, HostConfigSpec configSpec, ManagedObjectReference host);

    System.Threading.Tasks.Task<CryptoKeyResult?> GenerateKey(ManagedObjectReference self, KeyProviderId? keyProvider, CryptoManagerKmipCustomAttributeSpec? spec, CryptoManagerKmipGenerateKeySpec? keySpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> GenerateLogBundles_Task(ManagedObjectReference self, bool includeDefault, ManagedObjectReference[]? host);

    System.Threading.Tasks.Task<string?> GenerateSelfSignedClientCert(ManagedObjectReference self, KeyProviderId cluster, CryptoManagerKmipCertSignRequest? request);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> GetAlarm(ManagedObjectReference self, ManagedObjectReference? entity);

    System.Threading.Tasks.Task<AlarmState[]?> GetAlarmState(ManagedObjectReference self, ManagedObjectReference entity);

    System.Threading.Tasks.Task<string?> GetClusterMode(ManagedObjectReference self);

    System.Threading.Tasks.Task<CryptoManagerHostKeyStatus[]?> GetCryptoKeyStatus(ManagedObjectReference self, CryptoKeyId[]? keys);

    System.Threading.Tasks.Task<CustomizationSpecItem?> GetCustomizationSpec(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task<KeyProviderId?> GetDefaultKmsCluster(ManagedObjectReference self, ManagedObjectReference? entity, bool defaultsToParent, bool defaultsToParentSpecified);

    System.Threading.Tasks.Task<string?> GetPublicKey(ManagedObjectReference self);

    System.Threading.Tasks.Task<ClusterResourceUsageSummary?> GetResourceUsage(ManagedObjectReference self);

    System.Threading.Tasks.Task<SiteInfo?> GetSiteInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> GetSystemVMsRestrictedDatastores(ManagedObjectReference self);

    System.Threading.Tasks.Task<VchaClusterHealth?> GetVchaClusterHealth(ManagedObjectReference self);

    System.Threading.Tasks.Task<VchaClusterConfigInfo?> GetVchaConfig(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> GetVsanObjExtAttrs(ManagedObjectReference self, string[] uuids);

    System.Threading.Tasks.Task<bool> HasMonitoredEntity(ManagedObjectReference self, string providerId, ManagedObjectReference entity);

    System.Threading.Tasks.Task<EntityPrivilege[]?> HasPrivilegeOnEntities(ManagedObjectReference self, ManagedObjectReference[] entity, string sessionId, string[]? privId);

    System.Threading.Tasks.Task<bool[]?> HasPrivilegeOnEntity(ManagedObjectReference self, ManagedObjectReference entity, string sessionId, string[]? privId);

    System.Threading.Tasks.Task<bool> HasProvider(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<EntityPrivilege[]?> HasUserPrivilegeOnEntities(ManagedObjectReference self, ManagedObjectReference[] entities, string userName, string[]? privId);

    System.Threading.Tasks.Task HostClearVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostCloneVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmCloneSpec spec);

    System.Threading.Tasks.Task HostConfigureVFlashResource(ManagedObjectReference self, HostVFlashManagerVFlashResourceConfigSpec spec);

    System.Threading.Tasks.Task HostConfigVFlashCache(ManagedObjectReference self, HostVFlashManagerVFlashCacheConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostCreateDisk_Task(ManagedObjectReference self, VslmCreateSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostDeleteVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostDeleteVStorageObjectEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostExtendDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, long newCapacityInMB);

    System.Threading.Tasks.Task<VirtualDiskVFlashCacheConfigInfo?> HostGetVFlashModuleDefaultConfig(ManagedObjectReference self, string vFlashModule);

    System.Threading.Tasks.Task<string?> HostImageConfigGetAcceptance(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostImageProfileSummary?> HostImageConfigGetProfile(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostInflateDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ID[]?> HostListVStorageObject(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task HostProfileResetValidationState(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> HostQueryVirtualDiskUuid(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostReconcileDatastoreInventory_Task(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified);

    System.Threading.Tasks.Task<VStorageObject?> HostRegisterDisk(ManagedObjectReference self, string path, string? name, bool modifyControlFlags, bool modifyControlFlagsSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostRelocateVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmRelocateSpec spec);

    System.Threading.Tasks.Task HostRemoveVFlashResource(ManagedObjectReference self);

    System.Threading.Tasks.Task HostRenameVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string name);

    System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> HostRetrieveVStorageInfrastructureObjectPolicy(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<VStorageObject?> HostRetrieveVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? diskInfoFlags);

    System.Threading.Tasks.Task<KeyValue[]?> HostRetrieveVStorageObjectMetadata(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID? snapshotId, string? prefix);

    System.Threading.Tasks.Task<string?> HostRetrieveVStorageObjectMetadataValue(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID? snapshotId, string key);

    System.Threading.Tasks.Task<VStorageObjectStateInfo?> HostRetrieveVStorageObjectState(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task HostScheduleReconcileDatastoreInventory(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostSetVirtualDiskUuid_Task(ManagedObjectReference self, string name, string? uuid);

    System.Threading.Tasks.Task HostSetVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> HostSpecGetUpdatedHosts(ManagedObjectReference self, string? startChangeID, string? endChangeID);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostUpdateVStorageObjectMetadata_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, KeyValue[]? metadata, string[]? deleteKeys);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostUpdateVStorageObjectMetadataEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, KeyValue[]? metadata, string[]? deleteKeys);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectCreateDiskFromSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path, string? provisioningType);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectCreateSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string description);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectDeleteSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> HostVStorageObjectRetrieveSnapshotInfo(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectRevert_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task HttpNfcLeaseAbort(ManagedObjectReference self, LocalizedMethodFault? fault);

    System.Threading.Tasks.Task HttpNfcLeaseComplete(ManagedObjectReference self);

    System.Threading.Tasks.Task<HttpNfcLeaseManifestEntry[]?> HttpNfcLeaseGetManifest(ManagedObjectReference self);

    System.Threading.Tasks.Task<HttpNfcLeaseProbeResult[]?> HttpNfcLeaseProbeUrls(ManagedObjectReference self, HttpNfcLeaseSourceFile[]? files, int timeout, bool timeoutSpecified);

    System.Threading.Tasks.Task HttpNfcLeaseProgress(ManagedObjectReference self, int percent);

    System.Threading.Tasks.Task<ManagedObjectReference?> HttpNfcLeasePullFromUrls_Task(ManagedObjectReference self, HttpNfcLeaseSourceFile[]? files);

    System.Threading.Tasks.Task HttpNfcLeaseSetManifestChecksumType(ManagedObjectReference self, KeyValue[]? deviceUrlsToChecksumTypes);

    System.Threading.Tasks.Task<UserSession?> ImpersonateUser(ManagedObjectReference self, string userName, string? locale);

    System.Threading.Tasks.Task<ManagedObjectReference?> ImportCertificateForCAM_Task(ManagedObjectReference self, string certPath, string camServer);

    System.Threading.Tasks.Task ImportUnmanagedSnapshot(ManagedObjectReference self, string vdisk, ManagedObjectReference? datacenter, string vvolId);

    System.Threading.Tasks.Task<ManagedObjectReference?> ImportVApp(ManagedObjectReference self, ImportSpec spec, ManagedObjectReference? folder, ManagedObjectReference? host);

    System.Threading.Tasks.Task IncreaseDirectorySize(ManagedObjectReference self, ManagedObjectReference? datacenter, string stableName, long size);

    System.Threading.Tasks.Task<ManagedObjectReference?> InflateDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> InflateVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task<ManagedObjectReference?> InitializeDisks_Task(ManagedObjectReference self, VsanHostDiskMapping[] mapping);

    System.Threading.Tasks.Task<ManagedObjectReference?> InitiateFailover_Task(ManagedObjectReference self, bool planned);

    System.Threading.Tasks.Task<FileTransferInformation?> InitiateFileTransferFromGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string guestFilePath);

    System.Threading.Tasks.Task<string?> InitiateFileTransferToGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes, long fileSize, bool overwrite);

    System.Threading.Tasks.Task<ManagedObjectReference?> InitiateTransitionToVLCM_Task(ManagedObjectReference self, ManagedObjectReference cluster);

    System.Threading.Tasks.Task<DateTime> InstallDate(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> InstallHostPatch_Task(ManagedObjectReference self, HostPatchManagerLocator repository, string updateID, bool force, bool forceSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> InstallHostPatchV2_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> InstallIoFilter_Task(ManagedObjectReference self, string vibUrl, ManagedObjectReference compRes, IoFilterManagerSslTrust? vibSslTrust);

    System.Threading.Tasks.Task InstallServerCertificate(ManagedObjectReference self, string cert);

    System.Threading.Tasks.Task InstallSmartCardTrustAnchor(ManagedObjectReference self, string cert);

    System.Threading.Tasks.Task<ManagedObjectReference?> InstantClone_Task(ManagedObjectReference self, VirtualMachineInstantCloneSpec spec);

    System.Threading.Tasks.Task<bool> IsClusteredVmdkEnabled(ManagedObjectReference self);

    System.Threading.Tasks.Task<bool> IsGuestOsCustomizable(ManagedObjectReference self, string guestId);

    System.Threading.Tasks.Task<bool> IsKmsClusterActive(ManagedObjectReference self, KeyProviderId? cluster);

    System.Threading.Tasks.Task<bool> IsSharedGraphicsActive(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> JoinDomain_Task(ManagedObjectReference self, string domainName, string userName, string password);

    System.Threading.Tasks.Task<ManagedObjectReference?> JoinDomainWithCAM_Task(ManagedObjectReference self, string domainName, string camServer);

    System.Threading.Tasks.Task<ManagedObjectReference?> LeaveCurrentDomain_Task(ManagedObjectReference self, bool force);

    System.Threading.Tasks.Task<string[]?> ListCACertificateRevocationLists(ManagedObjectReference self);

    System.Threading.Tasks.Task<string[]?> ListCACertificates(ManagedObjectReference self);

    System.Threading.Tasks.Task<GuestListFileInfo?> ListFilesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string filePath, int index, bool indexSpecified, int maxResults, bool maxResultsSpecified, string? matchPattern);

    System.Threading.Tasks.Task<GuestAliases[]?> ListGuestAliases(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username);

    System.Threading.Tasks.Task<GuestMappedAliases[]?> ListGuestMappedAliases(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth);

    System.Threading.Tasks.Task<CryptoKeyId[]?> ListKeys(ManagedObjectReference self, int limit, bool limitSpecified);

    System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmipServers(ManagedObjectReference self, int limit, bool limitSpecified);

    System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmsClusters(ManagedObjectReference self, bool includeKmsServers, bool includeKmsServersSpecified, int managementTypeFilter, bool managementTypeFilterSpecified, int statusFilter, bool statusFilterSpecified);

    System.Threading.Tasks.Task<GuestProcessInfo[]?> ListProcessesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, long[]? pids);

    System.Threading.Tasks.Task<GuestRegKeyRecordSpec[]?> ListRegistryKeysInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive, string? matchPattern);

    System.Threading.Tasks.Task<GuestRegValueSpec[]?> ListRegistryValuesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool expandStrings, string? matchPattern);

    System.Threading.Tasks.Task<string[]?> ListSmartCardTrustAnchors(ManagedObjectReference self);

    System.Threading.Tasks.Task<VslmTagEntry[]?> ListTagsAttachedToVStorageObject(ManagedObjectReference self, ID id);

    System.Threading.Tasks.Task<ID[]?> ListVStorageObject(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ID[]?> ListVStorageObjectsAttachedToTag(ManagedObjectReference self, string category, string tag);

    System.Threading.Tasks.Task<UserSession?> Login(ManagedObjectReference self, string userName, string password, string? locale);

    System.Threading.Tasks.Task<UserSession?> LoginBySSPI(ManagedObjectReference self, string base64Token, string? locale);

    System.Threading.Tasks.Task<UserSession?> LoginByToken(ManagedObjectReference self, string? locale);

    System.Threading.Tasks.Task<UserSession?> LoginExtensionByCertificate(ManagedObjectReference self, string extensionKey, string? locale);

    System.Threading.Tasks.Task<UserSession?> LoginExtensionBySubjectName(ManagedObjectReference self, string extensionKey, string? locale);

    System.Threading.Tasks.Task Logout(ManagedObjectReference self);

    System.Threading.Tasks.Task LogUserEvent(ManagedObjectReference self, ManagedObjectReference entity, string msg);

    System.Threading.Tasks.Task<ManagedObjectReference?> LookupDvPortGroup(ManagedObjectReference self, string portgroupKey);

    System.Threading.Tasks.Task<long> LookupVmOverheadMemory(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference host);

    System.Threading.Tasks.Task MakeDirectory(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, bool createParentDirectories, bool createParentDirectoriesSpecified);

    System.Threading.Tasks.Task MakeDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string directoryPath, bool createParentDirectories);

    System.Threading.Tasks.Task<ManagedObjectReference?> MakePrimaryVM_Task(ManagedObjectReference self, ManagedObjectReference vm);

    System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsLocal_Task(ManagedObjectReference self, string scsiDiskUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsNonLocal_Task(ManagedObjectReference self, string scsiDiskUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsNonSsd_Task(ManagedObjectReference self, string scsiDiskUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsSsd_Task(ManagedObjectReference self, string scsiDiskUuid);

    System.Threading.Tasks.Task MarkAsTemplate(ManagedObjectReference self);

    System.Threading.Tasks.Task MarkAsVirtualMachine(ManagedObjectReference self, ManagedObjectReference pool, ManagedObjectReference? host);

    System.Threading.Tasks.Task MarkDefault(ManagedObjectReference self, KeyProviderId clusterId);

    System.Threading.Tasks.Task MarkForRemoval(ManagedObjectReference self, string hbaName, bool remove);

    System.Threading.Tasks.Task MarkPerenniallyReserved(ManagedObjectReference self, string lunUuid, bool state);

    System.Threading.Tasks.Task<ManagedObjectReference?> MarkPerenniallyReservedEx_Task(ManagedObjectReference self, string[]? lunUuid, bool state);

    System.Threading.Tasks.Task MarkServiceProviderEntities(ManagedObjectReference self, ManagedObjectReference[]? entity);

    System.Threading.Tasks.Task<ManagedObjectReference?> MergeDvs_Task(ManagedObjectReference self, ManagedObjectReference dvs);

    System.Threading.Tasks.Task MergePermissions(ManagedObjectReference self, int srcRoleId, int dstRoleId);

    System.Threading.Tasks.Task<ManagedObjectReference?> MigrateVM_Task(ManagedObjectReference self, ManagedObjectReference? pool, ManagedObjectReference? host, VirtualMachineMovePriority priority, VirtualMachinePowerState state, bool stateSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> ModifyListView(ManagedObjectReference self, ManagedObjectReference[]? add, ManagedObjectReference[]? remove);

    System.Threading.Tasks.Task MountToolsInstaller(ManagedObjectReference self);

    System.Threading.Tasks.Task MountVffsVolume(ManagedObjectReference self, string vffsUuid);

    System.Threading.Tasks.Task MountVmfsVolume(ManagedObjectReference self, string vmfsUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> MountVmfsVolumeEx_Task(ManagedObjectReference self, string[] vmfsUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> MoveDatastoreFile_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destinationName, ManagedObjectReference? destinationDatacenter, bool force, bool forceSpecified);

    System.Threading.Tasks.Task MoveDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string srcDirectoryPath, string dstDirectoryPath);

    System.Threading.Tasks.Task<ManagedObjectReference?> MoveDVPort_Task(ManagedObjectReference self, string[] portKey, string? destinationPortgroupKey);

    System.Threading.Tasks.Task MoveFileInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string srcFilePath, string dstFilePath, bool overwrite);

    System.Threading.Tasks.Task<ManagedObjectReference?> MoveHostInto_Task(ManagedObjectReference self, ManagedObjectReference host, ManagedObjectReference? resourcePool);

    System.Threading.Tasks.Task<ManagedObjectReference?> MoveInto_Task(ManagedObjectReference self, ManagedObjectReference[] host);

    System.Threading.Tasks.Task<ManagedObjectReference?> MoveIntoFolder_Task(ManagedObjectReference self, ManagedObjectReference[] list);

    System.Threading.Tasks.Task MoveIntoResourcePool(ManagedObjectReference self, ManagedObjectReference[] list);

    System.Threading.Tasks.Task<ManagedObjectReference?> MoveVirtualDisk_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destName, ManagedObjectReference? destDatacenter, bool force, bool forceSpecified, VirtualMachineProfileSpec[]? profile);

    System.Threading.Tasks.Task NotifyAffectedServices(ManagedObjectReference self, string[]? services);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> OpenInventoryViewFolder(ManagedObjectReference self, ManagedObjectReference[] entity);

    System.Threading.Tasks.Task OverwriteCustomizationSpec(ManagedObjectReference self, CustomizationSpecItem item);

    System.Threading.Tasks.Task<OvfParseDescriptorResult?> ParseDescriptor(ManagedObjectReference self, string ovfDescriptor, OvfParseDescriptorParams pdp);

    System.Threading.Tasks.Task<ManagedObjectReference?> PerformDvsProductSpecOperation_Task(ManagedObjectReference self, string operation, DistributedVirtualSwitchProductSpec? productSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> PerformVsanUpgrade_Task(ManagedObjectReference self, ManagedObjectReference cluster, bool performObjectUpgrade, bool performObjectUpgradeSpecified, bool downgradeFormat, bool downgradeFormatSpecified, bool allowReducedRedundancy, bool allowReducedRedundancySpecified, ManagedObjectReference[]? excludeHosts);

    System.Threading.Tasks.Task<VsanUpgradeSystemPreflightCheckResult?> PerformVsanUpgradePreflightCheck(ManagedObjectReference self, ManagedObjectReference cluster, bool downgradeFormat, bool downgradeFormatSpecified);

    System.Threading.Tasks.Task<PlacementResult?> PlaceVm(ManagedObjectReference self, PlacementSpec placementSpec);

    System.Threading.Tasks.Task PostEvent(ManagedObjectReference self, Event eventToPost, TaskInfo? taskInfo);

    System.Threading.Tasks.Task PostHealthUpdates(ManagedObjectReference self, string providerId, HealthUpdate[]? updates);

    System.Threading.Tasks.Task<ManagedObjectReference?> PowerDownHostToStandBy_Task(ManagedObjectReference self, int timeoutSec, bool evacuatePoweredOffVms, bool evacuatePoweredOffVmsSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> PowerOffVApp_Task(ManagedObjectReference self, bool force);

    System.Threading.Tasks.Task<ManagedObjectReference?> PowerOffVM_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> PowerOnMultiVM_Task(ManagedObjectReference self, ManagedObjectReference[] vm, OptionValue[]? option);

    System.Threading.Tasks.Task<ManagedObjectReference?> PowerOnVApp_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> PowerOnVM_Task(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<ManagedObjectReference?> PowerUpHostFromStandBy_Task(ManagedObjectReference self, int timeoutSec);

    System.Threading.Tasks.Task PrepareCrypto(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> PrepareVcha_Task(ManagedObjectReference self, VchaClusterNetworkSpec networkSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> PromoteDisks_Task(ManagedObjectReference self, bool unlink, VirtualDisk[]? disks);

    System.Threading.Tasks.Task ProvisionServerPrivateKey(ManagedObjectReference self, string key);

    System.Threading.Tasks.Task<int> PutUsbScanCodes(ManagedObjectReference self, UsbScanCodeSpec spec);

    System.Threading.Tasks.Task<AnswerFileStatusResult[]?> QueryAnswerFileStatus(ManagedObjectReference self, ManagedObjectReference[] host);

    System.Threading.Tasks.Task<LicenseAssignmentManagerLicenseAssignment[]?> QueryAssignedLicenses(ManagedObjectReference self, string? entityId);

    System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableDisksForVmfs(ManagedObjectReference self, ManagedObjectReference? datastore);

    System.Threading.Tasks.Task<DistributedVirtualSwitchProductSpec[]?> QueryAvailableDvsSpec(ManagedObjectReference self, bool recommended, bool recommendedSpecified);

    System.Threading.Tasks.Task<HostDiagnosticPartition[]?> QueryAvailablePartition(ManagedObjectReference self);

    System.Threading.Tasks.Task<PerfMetricId[]?> QueryAvailablePerfMetric(ManagedObjectReference self, ManagedObjectReference entity, DateTime beginTime, bool beginTimeSpecified, DateTime endTime, bool endTimeSpecified, int intervalId, bool intervalIdSpecified);

    System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableSsds(ManagedObjectReference self, string? vffsPath);

    System.Threading.Tasks.Task<HostDateTimeSystemTimeZone[]?> QueryAvailableTimeZones(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostBootDeviceInfo?> QueryBootDevices(ManagedObjectReference self);

    System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryBoundVnics(ManagedObjectReference self, string iScsiHbaName);

    System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryCandidateNics(ManagedObjectReference self, string iScsiHbaName);

    System.Threading.Tasks.Task<DiskChangeInfo?> QueryChangedDiskAreas(ManagedObjectReference self, ManagedObjectReference? snapshot, int deviceKey, long startOffset, string changeId);

    System.Threading.Tasks.Task<string?> QueryCmmds(ManagedObjectReference self, HostVsanInternalSystemCmmdsQuery[] queries);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryCompatibleHostForExistingDvs(ManagedObjectReference self, ManagedObjectReference container, bool recursive, ManagedObjectReference dvs);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryCompatibleHostForNewDvs(ManagedObjectReference self, ManagedObjectReference container, bool recursive, DistributedVirtualSwitchProductSpec? switchProductSpec);

    System.Threading.Tasks.Task<DVSManagerPhysicalNicsList[]?> QueryCompatibleVmnicsFromHosts(ManagedObjectReference self, ManagedObjectReference[]? hosts, ManagedObjectReference dvs);

    System.Threading.Tasks.Task<ComplianceResult[]?> QueryComplianceStatus(ManagedObjectReference self, ManagedObjectReference[]? profile, ManagedObjectReference[]? entity);

    System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOption(ManagedObjectReference self, string? key, ManagedObjectReference? host);

    System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryConfigOptionDescriptor(ManagedObjectReference self);

    System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOptionEx(ManagedObjectReference self, EnvironmentBrowserConfigOptionQuerySpec? spec);

    System.Threading.Tasks.Task<ConfigTarget?> QueryConfigTarget(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<string?> QueryConfiguredModuleOptionString(ManagedObjectReference self, string name);

    System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfo(ManagedObjectReference self, string hostname, int port, string username, string password, string? sslThumbprint, string? sslCertificate);

    System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfoViaSpec(ManagedObjectReference self, HostConnectSpec spec);

    System.Threading.Tasks.Task<VirtualMachineConnection[]?> QueryConnections(ManagedObjectReference self);

    System.Threading.Tasks.Task<CryptoManagerKmipCryptoKeyStatus[]?> QueryCryptoKeyStatus(ManagedObjectReference self, CryptoKeyId[]? keyIds, int checkKeyBitMap);

    System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryDatacenterConfigOptionDescriptor(ManagedObjectReference self);

    System.Threading.Tasks.Task<StoragePerformanceSummary[]?> QueryDatastorePerformanceSummary(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<DateTime> QueryDateTime(ManagedObjectReference self);

    System.Threading.Tasks.Task<DiagnosticManagerLogDescriptor[]?> QueryDescriptions(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<DatastoreNamespaceManagerDirectoryInfo?> QueryDirectoryInfo(ManagedObjectReference self, ManagedObjectReference? datacenter, string stableName);

    System.Threading.Tasks.Task<VsanHostDiskResult[]?> QueryDisksForVsan(ManagedObjectReference self, string[]? canonicalName);

    System.Threading.Tasks.Task<VirtualDiskId[]?> QueryDisksUsingFilter(ManagedObjectReference self, string filterId, ManagedObjectReference compRes);

    System.Threading.Tasks.Task<ManagedObjectReference?> QueryDvsByUuid(ManagedObjectReference self, string uuid);

    System.Threading.Tasks.Task<DistributedVirtualSwitchManagerCompatibilityResult[]?> QueryDvsCheckCompatibility(ManagedObjectReference self, DistributedVirtualSwitchManagerHostContainer hostContainer, DistributedVirtualSwitchManagerDvsProductSpec? dvsProductSpec, DistributedVirtualSwitchManagerHostDvsFilterSpec[]? hostFilterSpec);

    System.Threading.Tasks.Task<DistributedVirtualSwitchHostProductSpec[]?> QueryDvsCompatibleHostSpec(ManagedObjectReference self, DistributedVirtualSwitchProductSpec? switchProductSpec);

    System.Threading.Tasks.Task<DVSManagerDvsConfigTarget?> QueryDvsConfigTarget(ManagedObjectReference self, ManagedObjectReference? host, ManagedObjectReference? dvs);

    System.Threading.Tasks.Task<DVSFeatureCapability?> QueryDvsFeatureCapability(ManagedObjectReference self, DistributedVirtualSwitchProductSpec? switchProductSpec);

    System.Threading.Tasks.Task<Event[]?> QueryEvents(ManagedObjectReference self, EventFilterSpec filter, EventManagerEventViewSpec? eventViewSpec);

    System.Threading.Tasks.Task<ProfileExpressionMetadata[]?> QueryExpressionMetadata(ManagedObjectReference self, string[]? expressionName, ManagedObjectReference? profile);

    System.Threading.Tasks.Task<ExtensionManagerIpAllocationUsage[]?> QueryExtensionIpAllocationUsage(ManagedObjectReference self, string[]? extensionKeys);

    System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibility(ManagedObjectReference self);

    System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibilityEx(ManagedObjectReference self, bool forLegacyFt, bool forLegacyFtSpecified);

    System.Threading.Tasks.Task<FileLockInfoResult?> QueryFileLockInfo(ManagedObjectReference self, string path, ManagedObjectReference? host);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryFilterEntities(ManagedObjectReference self, string filterId);

    System.Threading.Tasks.Task<string[]?> QueryFilterInfoIds(ManagedObjectReference self, string filterId);

    System.Threading.Tasks.Task<string[]?> QueryFilterList(ManagedObjectReference self, string providerId);

    System.Threading.Tasks.Task<string?> QueryFilterName(ManagedObjectReference self, string filterId);

    System.Threading.Tasks.Task<string?> QueryFirmwareConfigUploadURL(ManagedObjectReference self);

    System.Threading.Tasks.Task<HealthUpdateInfo[]?> QueryHealthUpdateInfos(ManagedObjectReference self, string providerId);

    System.Threading.Tasks.Task<HealthUpdate[]?> QueryHealthUpdates(ManagedObjectReference self, string providerId);

    System.Threading.Tasks.Task<HostConnectInfo?> QueryHostConnectionInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> QueryHostPatch_Task(ManagedObjectReference self, HostPatchManagerPatchManagerOperationSpec? spec);

    System.Threading.Tasks.Task<ProfileMetadata[]?> QueryHostProfileMetadata(ManagedObjectReference self, string[]? profileName, ManagedObjectReference? profile);

    System.Threading.Tasks.Task<VsanHostClusterStatus?> QueryHostStatus(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryHostsWithAttachedLun(ManagedObjectReference self, string lunUuid);

    System.Threading.Tasks.Task<ClusterIoFilterInfo[]?> QueryIoFilterInfo(ManagedObjectReference self, ManagedObjectReference compRes);

    System.Threading.Tasks.Task<IoFilterQueryIssueResult?> QueryIoFilterIssues(ManagedObjectReference self, string filterId, ManagedObjectReference compRes);

    System.Threading.Tasks.Task<StorageIORMConfigOption?> QueryIORMConfigOption(ManagedObjectReference self, ManagedObjectReference host);

    System.Threading.Tasks.Task<IpPoolManagerIpAllocation[]?> QueryIPAllocations(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string extensionKey);

    System.Threading.Tasks.Task<IpPool[]?> QueryIpPools(ManagedObjectReference self, ManagedObjectReference dc);

    System.Threading.Tasks.Task<LicenseAvailabilityInfo[]?> QueryLicenseSourceAvailability(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<LicenseUsageInfo?> QueryLicenseUsage(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<string[]?> QueryLockdownExceptions(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryManagedBy(ManagedObjectReference self, string extensionKey);

    System.Threading.Tasks.Task<long> QueryMaxQueueDepth(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<long> QueryMemoryOverhead(ManagedObjectReference self, long memorySize, int videoRamSize, bool videoRamSizeSpecified, int numVcpus);

    System.Threading.Tasks.Task<long> QueryMemoryOverheadEx(ManagedObjectReference self, VirtualMachineConfigInfo vmConfigInfo);

    System.Threading.Tasks.Task<IscsiMigrationDependency?> QueryMigrationDependencies(ManagedObjectReference self, string[] pnicDevice);

    System.Threading.Tasks.Task<KernelModuleInfo[]?> QueryModules(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryMonitoredEntities(ManagedObjectReference self, string providerId);

    System.Threading.Tasks.Task<VirtualNicManagerNetConfig?> QueryNetConfig(ManagedObjectReference self, string nicType);

    System.Threading.Tasks.Task<PhysicalNicHintInfo[]?> QueryNetworkHint(ManagedObjectReference self, string[]? device);

    System.Threading.Tasks.Task<HostNasVolumeUserInfo?> QueryNFSUser(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> QueryObjectsOnPhysicalVsanDisk(ManagedObjectReference self, string[] disks);

    System.Threading.Tasks.Task<OptionValue[]?> QueryOptions(ManagedObjectReference self, string? name);

    System.Threading.Tasks.Task<HostDiagnosticPartitionCreateDescription?> QueryPartitionCreateDesc(ManagedObjectReference self, string diskUuid, string diagnosticType);

    System.Threading.Tasks.Task<HostDiagnosticPartitionCreateOption[]?> QueryPartitionCreateOptions(ManagedObjectReference self, string storageType, string diagnosticType);

    System.Threading.Tasks.Task<HostPathSelectionPolicyOption[]?> QueryPathSelectionPolicyOptions(ManagedObjectReference self);

    System.Threading.Tasks.Task<PerfEntityMetricBase[]?> QueryPerf(ManagedObjectReference self, PerfQuerySpec[] querySpec);

    System.Threading.Tasks.Task<PerfCompositeMetric?> QueryPerfComposite(ManagedObjectReference self, PerfQuerySpec querySpec);

    System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounter(ManagedObjectReference self, int[] counterId);

    System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounterByLevel(ManagedObjectReference self, int level);

    System.Threading.Tasks.Task<PerfProviderSummary?> QueryPerfProviderSummary(ManagedObjectReference self, ManagedObjectReference entity);

    System.Threading.Tasks.Task<string?> QueryPhysicalVsanDisks(ManagedObjectReference self, string[]? props);

    System.Threading.Tasks.Task<IscsiStatus?> QueryPnicStatus(ManagedObjectReference self, string pnicDevice);

    System.Threading.Tasks.Task<ProfilePolicyMetadata[]?> QueryPolicyMetadata(ManagedObjectReference self, string[]? policyName, ManagedObjectReference? profile);

    System.Threading.Tasks.Task<string?> QueryProductLockerLocation(ManagedObjectReference self);

    System.Threading.Tasks.Task<ProfileProfileStructure?> QueryProfileStructure(ManagedObjectReference self, ManagedObjectReference? profile);

    System.Threading.Tasks.Task<string[]?> QueryProviderList(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> QueryProviderName(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<ResourceConfigOption?> QueryResourceConfigOption(ManagedObjectReference self);

    System.Threading.Tasks.Task<ServiceManagerServiceInfo[]?> QueryServiceList(ManagedObjectReference self, string? serviceName, string[]? location);

    System.Threading.Tasks.Task<HostStorageArrayTypePolicyOption[]?> QueryStorageArrayTypePolicyOptions(ManagedObjectReference self);

    System.Threading.Tasks.Task<LicenseFeatureInfo[]?> QuerySupportedFeatures(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<DistributedVirtualSwitchNetworkOffloadSpec[]?> QuerySupportedNetworkOffloadSpec(ManagedObjectReference self, DistributedVirtualSwitchProductSpec switchProductSpec);

    System.Threading.Tasks.Task<string?> QuerySyncingVsanObjects(ManagedObjectReference self, string[]? uuids);

    System.Threading.Tasks.Task<string[]?> QuerySystemUsers(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostCapability?> QueryTargetCapabilities(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task<HostTpmAttestationReport?> QueryTpmAttestationReport(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryUnmonitoredHosts(ManagedObjectReference self, string providerId, ManagedObjectReference cluster);

    System.Threading.Tasks.Task<string[]?> QueryUnownedFiles(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolume(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolumes(ManagedObjectReference self);

    System.Threading.Tasks.Task<int[]?> QueryUsedVlanIdInDvs(ManagedObjectReference self);

    System.Threading.Tasks.Task<int> QueryVirtualDiskFragmentation(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task<HostDiskDimensionsChs?> QueryVirtualDiskGeometry(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task<string?> QueryVirtualDiskUuid(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task<string?> QueryVirtualDiskUuidEx(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task<VmfsConfigOption[]?> QueryVmfsConfigOption(ManagedObjectReference self);

    System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreCreateOptions(ManagedObjectReference self, string devicePath, int vmfsMajorVersion, bool vmfsMajorVersionSpecified);

    System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExpandOptions(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExtendOptions(ManagedObjectReference self, ManagedObjectReference datastore, string devicePath, bool suppressExpandCandidates, bool suppressExpandCandidatesSpecified);

    System.Threading.Tasks.Task<HostVMotionCompatibility[]?> QueryVMotionCompatibility(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference[] host, string[]? compatibility);

    System.Threading.Tasks.Task<ManagedObjectReference?> QueryVMotionCompatibilityEx_Task(ManagedObjectReference self, ManagedObjectReference[] vm, ManagedObjectReference[] host);

    System.Threading.Tasks.Task<IscsiStatus?> QueryVnicStatus(ManagedObjectReference self, string vnicDevice);

    System.Threading.Tasks.Task<string?> QueryVsanObjects(ManagedObjectReference self, string[]? uuids);

    System.Threading.Tasks.Task<string[]?> QueryVsanObjectUuidsByFilter(ManagedObjectReference self, string[]? uuids, int limit, bool limitSpecified, int version, bool versionSpecified);

    System.Threading.Tasks.Task<string?> QueryVsanStatistics(ManagedObjectReference self, string[] labels);

    System.Threading.Tasks.Task<VsanUpgradeSystemUpgradeStatus?> QueryVsanUpgradeStatus(ManagedObjectReference self, ManagedObjectReference cluster);

    System.Threading.Tasks.Task<string[]?> ReadEnvironmentVariableInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string[]? names);

    System.Threading.Tasks.Task<Event[]?> ReadNextEvents(ManagedObjectReference self, int maxCount);

    System.Threading.Tasks.Task<TaskInfo[]?> ReadNextTasks(ManagedObjectReference self, int maxCount);

    System.Threading.Tasks.Task<TaskInfo[]?> ReadNextTasksByViewSpec(ManagedObjectReference self, TaskManagerTaskViewSpec viewSpec, TaskFilterSpec filterSpec, TaskInfoFilterSpec? infoFilterSpec);

    System.Threading.Tasks.Task<Event[]?> ReadPreviousEvents(ManagedObjectReference self, int maxCount);

    System.Threading.Tasks.Task<TaskInfo[]?> ReadPreviousTasks(ManagedObjectReference self, int maxCount);

    System.Threading.Tasks.Task RebootGuest(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> RebootHost_Task(ManagedObjectReference self, bool force);

    System.Threading.Tasks.Task<StoragePlacementResult?> RecommendDatastores(ManagedObjectReference self, StoragePlacementSpec storageSpec);

    System.Threading.Tasks.Task<ClusterHostRecommendation[]?> RecommendHostsForVm(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? pool);

    System.Threading.Tasks.Task<ManagedObjectReference?> RecommissionVsanNode_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconcileDatastoreInventory_Task(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconcileDatastoreInventoryEx_Task(ManagedObjectReference self, VStorageObjectReconcileSpec spec);

    System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> ReconfigurationSatisfiable(ManagedObjectReference self, VsanPolicyChangeBatch[] pcbs, bool ignoreSatisfiability, bool ignoreSatisfiabilitySpecified);

    System.Threading.Tasks.Task ReconfigureAlarm(ManagedObjectReference self, AlarmSpec spec);

    System.Threading.Tasks.Task ReconfigureAutostart(ManagedObjectReference self, HostAutoStartManagerConfig spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureCluster_Task(ManagedObjectReference self, ClusterConfigSpec spec, bool modify);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureComputeResource_Task(ManagedObjectReference self, ComputeResourceConfigSpec spec, bool modify);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDatacenter_Task(ManagedObjectReference self, DatacenterConfigSpec spec, bool modify);

    System.Threading.Tasks.Task ReconfigureDomObject(ManagedObjectReference self, string uuid, string policy);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDVPort_Task(ManagedObjectReference self, DVPortConfigSpec[] port);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDVPortgroup_Task(ManagedObjectReference self, DVPortgroupConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDvs_Task(ManagedObjectReference self, DVSConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureHostForDAS_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task ReconfigureScheduledTask(ManagedObjectReference self, ScheduledTaskSpec spec);

    System.Threading.Tasks.Task ReconfigureServiceConsoleReservation(ManagedObjectReference self, long cfgBytes);

    System.Threading.Tasks.Task ReconfigureSnmpAgent(ManagedObjectReference self, HostSnmpConfigSpec spec);

    System.Threading.Tasks.Task ReconfigureVirtualMachineReservation(ManagedObjectReference self, VirtualMachineMemoryReservationSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigVM_Task(ManagedObjectReference self, VirtualMachineConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReconnectHost_Task(ManagedObjectReference self, HostConnectSpec? cnxSpec, HostSystemReconnectSpec? reconnectSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> RectifyDvsHost_Task(ManagedObjectReference self, ManagedObjectReference[]? hosts);

    System.Threading.Tasks.Task<ManagedObjectReference?> RectifyDvsOnHost_Task(ManagedObjectReference self, ManagedObjectReference[] hosts);

    System.Threading.Tasks.Task Refresh(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshDatastore(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshDatastoreStorageInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshDateTimeSystem(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshDVPortState(ManagedObjectReference self, string[]? portKeys);

    System.Threading.Tasks.Task RefreshFirewall(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshGraphicsManager(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshHealthStatusSystem(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshNetworkSystem(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshRecommendation(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshRuntime(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshServices(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshStorageDrsRecommendation(ManagedObjectReference self, ManagedObjectReference pod);

    System.Threading.Tasks.Task<ManagedObjectReference?> RefreshStorageDrsRecommendationsForPod_Task(ManagedObjectReference self, ManagedObjectReference pod);

    System.Threading.Tasks.Task RefreshStorageInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task RefreshStorageSystem(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> RegisterChildVM_Task(ManagedObjectReference self, string path, string? name, ManagedObjectReference? host);

    System.Threading.Tasks.Task<VStorageObject?> RegisterDisk(ManagedObjectReference self, string path, string? name);

    System.Threading.Tasks.Task RegisterExtension(ManagedObjectReference self, Extension extension);

    System.Threading.Tasks.Task<string?> RegisterHealthUpdateProvider(ManagedObjectReference self, string name, HealthUpdateInfo[]? healthUpdateInfo);

    System.Threading.Tasks.Task RegisterKmipServer(ManagedObjectReference self, KmipServerSpec server);

    System.Threading.Tasks.Task RegisterKmsCluster(ManagedObjectReference self, KeyProviderId clusterId, string? managementType);

    System.Threading.Tasks.Task<ManagedObjectReference?> RegisterVM_Task(ManagedObjectReference self, string path, string? name, bool asTemplate, ManagedObjectReference? pool, ManagedObjectReference? host);

    System.Threading.Tasks.Task ReleaseCredentialsInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth);

    System.Threading.Tasks.Task ReleaseIpAllocation(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string allocationId);

    System.Threading.Tasks.Task ReleaseManagedSnapshot(ManagedObjectReference self, string vdisk, ManagedObjectReference? datacenter);

    System.Threading.Tasks.Task Reload(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ReloadVirtualMachineFromPath_Task(ManagedObjectReference self, string configurationPath);

    System.Threading.Tasks.Task<ManagedObjectReference?> RelocateVM_Task(ManagedObjectReference self, VirtualMachineRelocateSpec spec, VirtualMachineMovePriority priority, bool prioritySpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> RelocateVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmRelocateSpec spec);

    System.Threading.Tasks.Task RemoveAlarm(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> RemoveAllSnapshots_Task(ManagedObjectReference self, bool consolidate, bool consolidateSpecified, SnapshotSelectionSpec? spec);

    System.Threading.Tasks.Task RemoveAssignedLicense(ManagedObjectReference self, string entityId);

    System.Threading.Tasks.Task RemoveAuthorizationRole(ManagedObjectReference self, int roleId, bool failIfUsed);

    System.Threading.Tasks.Task RemoveCustomFieldDef(ManagedObjectReference self, int key);

    System.Threading.Tasks.Task RemoveDatastore(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> RemoveDatastoreEx_Task(ManagedObjectReference self, ManagedObjectReference[] datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> RemoveDisk_Task(ManagedObjectReference self, HostScsiDisk[] disk, HostMaintenanceSpec? maintenanceSpec, int timeout, bool timeoutSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> RemoveDiskMapping_Task(ManagedObjectReference self, VsanHostDiskMapping[] mapping, HostMaintenanceSpec? maintenanceSpec, int timeout, bool timeoutSpecified);

    System.Threading.Tasks.Task RemoveEntityPermission(ManagedObjectReference self, ManagedObjectReference entity, string user, bool isGroup);

    System.Threading.Tasks.Task RemoveFilter(ManagedObjectReference self, string filterId);

    System.Threading.Tasks.Task RemoveFilterEntities(ManagedObjectReference self, string filterId, ManagedObjectReference[]? entities);

    System.Threading.Tasks.Task RemoveGroup(ManagedObjectReference self, string groupName);

    System.Threading.Tasks.Task RemoveGuestAlias(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username, string base64Cert, GuestAuthSubject subject);

    System.Threading.Tasks.Task RemoveGuestAliasByCert(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username, string base64Cert);

    System.Threading.Tasks.Task RemoveInternetScsiSendTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets, bool force, bool forceSpecified);

    System.Threading.Tasks.Task RemoveInternetScsiStaticTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets);

    System.Threading.Tasks.Task RemoveKey(ManagedObjectReference self, CryptoKeyId key, bool force);

    System.Threading.Tasks.Task<CryptoKeyResult[]?> RemoveKeys(ManagedObjectReference self, CryptoKeyId[]? keys, bool force);

    System.Threading.Tasks.Task RemoveKmipServer(ManagedObjectReference self, KeyProviderId clusterId, string serverName);

    System.Threading.Tasks.Task RemoveLicense(ManagedObjectReference self, string licenseKey);

    System.Threading.Tasks.Task RemoveLicenseLabel(ManagedObjectReference self, string licenseKey, string labelKey);

    System.Threading.Tasks.Task RemoveMonitoredEntities(ManagedObjectReference self, string providerId, ManagedObjectReference[]? entities);

    System.Threading.Tasks.Task RemoveNetworkResourcePool(ManagedObjectReference self, string[] key);

    System.Threading.Tasks.Task RemoveNvmeOverRdmaAdapter(ManagedObjectReference self, string hbaDeviceName);

    System.Threading.Tasks.Task RemovePerfInterval(ManagedObjectReference self, int samplePeriod);

    System.Threading.Tasks.Task RemovePortGroup(ManagedObjectReference self, string pgName);

    System.Threading.Tasks.Task RemoveScheduledTask(ManagedObjectReference self);

    System.Threading.Tasks.Task RemoveServiceConsoleVirtualNic(ManagedObjectReference self, string device);

    System.Threading.Tasks.Task RemoveSmartCardTrustAnchor(ManagedObjectReference self, string issuer, string serial);

    System.Threading.Tasks.Task RemoveSmartCardTrustAnchorByFingerprint(ManagedObjectReference self, string fingerprint, string digest);

    System.Threading.Tasks.Task RemoveSmartCardTrustAnchorCertificate(ManagedObjectReference self, string certificate);

    System.Threading.Tasks.Task<ManagedObjectReference?> RemoveSnapshot_Task(ManagedObjectReference self, bool removeChildren, bool consolidate, bool consolidateSpecified);

    System.Threading.Tasks.Task RemoveSoftwareAdapter(ManagedObjectReference self, string hbaDeviceName);

    System.Threading.Tasks.Task RemoveUser(ManagedObjectReference self, string userName);

    System.Threading.Tasks.Task RemoveVirtualNic(ManagedObjectReference self, string device);

    System.Threading.Tasks.Task RemoveVirtualSwitch(ManagedObjectReference self, string vswitchName);

    System.Threading.Tasks.Task<ManagedObjectReference?> Rename_Task(ManagedObjectReference self, string newName);

    System.Threading.Tasks.Task RenameCustomFieldDef(ManagedObjectReference self, int key, string name);

    System.Threading.Tasks.Task RenameCustomizationSpec(ManagedObjectReference self, string name, string newName);

    System.Threading.Tasks.Task RenameDatastore(ManagedObjectReference self, string newName);

    System.Threading.Tasks.Task RenameSnapshot(ManagedObjectReference self, string? name, string? description);

    System.Threading.Tasks.Task RenameVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string name);

    System.Threading.Tasks.Task<vslmVClockInfo?> RenameVStorageObjectEx(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string name);

    System.Threading.Tasks.Task ReplaceCACertificatesAndCRLs(ManagedObjectReference self, string[] caCert, string[]? caCrl);

    System.Threading.Tasks.Task ReplaceSmartCardTrustAnchors(ManagedObjectReference self, string[]? certs);

    System.Threading.Tasks.Task RescanAllHba(ManagedObjectReference self);

    System.Threading.Tasks.Task RescanHba(ManagedObjectReference self, string hbaDevice);

    System.Threading.Tasks.Task RescanVffs(ManagedObjectReference self);

    System.Threading.Tasks.Task RescanVmfs(ManagedObjectReference self);

    System.Threading.Tasks.Task ResetCollector(ManagedObjectReference self);

    System.Threading.Tasks.Task ResetCounterLevelMapping(ManagedObjectReference self, int[] counters);

    System.Threading.Tasks.Task ResetEntityPermissions(ManagedObjectReference self, ManagedObjectReference entity, Permission[]? permission);

    System.Threading.Tasks.Task ResetFirmwareToFactoryDefaults(ManagedObjectReference self);

    System.Threading.Tasks.Task ResetGuestInformation(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> ResetListView(ManagedObjectReference self, ManagedObjectReference[]? obj);

    System.Threading.Tasks.Task ResetListViewFromView(ManagedObjectReference self, ManagedObjectReference view);

    System.Threading.Tasks.Task ResetSystemHealthInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ResetVM_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ResignatureUnresolvedVmfsVolume_Task(ManagedObjectReference self, HostUnresolvedVmfsResignatureSpec resolutionSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ResolveInstallationErrorsOnCluster_Task(ManagedObjectReference self, string filterId, ManagedObjectReference cluster);

    System.Threading.Tasks.Task<ManagedObjectReference?> ResolveInstallationErrorsOnHost_Task(ManagedObjectReference self, string filterId, ManagedObjectReference host);

    System.Threading.Tasks.Task<HostUnresolvedVmfsResolutionResult[]?> ResolveMultipleUnresolvedVmfsVolumes(ManagedObjectReference self, HostUnresolvedVmfsResolutionSpec[] resolutionSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> ResolveMultipleUnresolvedVmfsVolumesEx_Task(ManagedObjectReference self, HostUnresolvedVmfsResolutionSpec[] resolutionSpec);

    System.Threading.Tasks.Task RestartService(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task RestartServiceConsoleVirtualNic(ManagedObjectReference self, string device);

    System.Threading.Tasks.Task RestoreFirmwareConfiguration(ManagedObjectReference self, bool force);

    System.Threading.Tasks.Task<Permission[]?> RetrieveAllPermissions(ManagedObjectReference self);

    System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFile(ManagedObjectReference self, ManagedObjectReference host);

    System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFileForProfile(ManagedObjectReference self, ManagedObjectReference host, HostApplyProfile applyProfile);

    System.Threading.Tasks.Task<EventArgDesc[]?> RetrieveArgumentDescription(ManagedObjectReference self, string eventTypeId);

    System.Threading.Tasks.Task<HostCertificateManagerCertificateInfo[]?> RetrieveCertificateInfoList(ManagedObjectReference self);

    System.Threading.Tasks.Task<string?> RetrieveClientCert(ManagedObjectReference self, KeyProviderId cluster);

    System.Threading.Tasks.Task<string?> RetrieveClientCsr(ManagedObjectReference self, KeyProviderId cluster);

    System.Threading.Tasks.Task<ClusterDasAdvancedRuntimeInfo?> RetrieveDasAdvancedRuntimeInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<ProfileDescription?> RetrieveDescription(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostDiskPartitionInfo[]?> RetrieveDiskPartitionInfo(ManagedObjectReference self, string[] devicePath);

    System.Threading.Tasks.Task<VirtualMachineDynamicPassthroughInfo[]?> RetrieveDynamicPassthroughInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<Permission[]?> RetrieveEntityPermissions(ManagedObjectReference self, ManagedObjectReference entity, bool inherited);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> RetrieveEntityScheduledTask(ManagedObjectReference self, ManagedObjectReference? entity);

    System.Threading.Tasks.Task<long> RetrieveFreeEpcMemory(ManagedObjectReference self);

    System.Threading.Tasks.Task<long> RetrieveHardwareUptime(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostAccessControlEntry[]?> RetrieveHostAccessControlEntries(ManagedObjectReference self);

    System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizations(ManagedObjectReference self, ManagedObjectReference[]? hosts);

    System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizationsForProfile(ManagedObjectReference self, ManagedObjectReference[]? hosts, HostApplyProfile applyProfile);

    System.Threading.Tasks.Task<HostSpecification?> RetrieveHostSpecification(ManagedObjectReference self, ManagedObjectReference host, bool fromHost);

    System.Threading.Tasks.Task<CryptoManagerKmipServerCertInfo?> RetrieveKmipServerCert(ManagedObjectReference self, KeyProviderId keyProvider, KmipServerInfo server);

    System.Threading.Tasks.Task<ManagedObjectReference?> RetrieveKmipServersStatus_Task(ManagedObjectReference self, KmipClusterInfo[]? clusters);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> RetrieveObjectScheduledTask(ManagedObjectReference self, ManagedObjectReference? obj);

    System.Threading.Tasks.Task<ProductComponentInfo[]?> RetrieveProductComponents(ManagedObjectReference self);

    System.Threading.Tasks.Task<ObjectContent[]?> RetrieveProperties(ManagedObjectReference self, PropertyFilterSpec[] specSet);

    System.Threading.Tasks.Task<RetrieveResult?> RetrievePropertiesEx(ManagedObjectReference self, PropertyFilterSpec[] specSet, RetrieveOptions options);

    System.Threading.Tasks.Task<Permission[]?> RetrieveRolePermissions(ManagedObjectReference self, int roleId);

    System.Threading.Tasks.Task<string?> RetrieveSelfSignedClientCert(ManagedObjectReference self, KeyProviderId cluster);

    System.Threading.Tasks.Task<ServiceContent?> RetrieveServiceContent(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference[]?> RetrieveServiceProviderEntities(ManagedObjectReference self);

    System.Threading.Tasks.Task<VStorageObjectSnapshotDetails?> RetrieveSnapshotDetails(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> RetrieveSnapshotInfo(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<UserSearchResult[]?> RetrieveUserGroups(ManagedObjectReference self, string? domain, string searchStr, string? belongsToGroup, string? belongsToUser, bool exactMatch, bool findUsers, bool findGroups);

    System.Threading.Tasks.Task<VirtualMachineVendorDeviceGroupInfo[]?> RetrieveVendorDeviceGroupInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<VirtualMachineVgpuDeviceInfo[]?> RetrieveVgpuDeviceInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<VirtualMachineVgpuProfileInfo[]?> RetrieveVgpuProfileInfo(ManagedObjectReference self);

    System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> RetrieveVStorageInfrastructureObjectPolicy(ManagedObjectReference self, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<VStorageObject?> RetrieveVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? diskInfoFlags);

    System.Threading.Tasks.Task<VStorageObjectAssociations[]?> RetrieveVStorageObjectAssociations(ManagedObjectReference self, RetrieveVStorageObjSpec[]? ids);

    System.Threading.Tasks.Task<VStorageObjectStateInfo?> RetrieveVStorageObjectState(ManagedObjectReference self, ID id, ManagedObjectReference datastore);

    System.Threading.Tasks.Task<ManagedObjectReference?> RevertToCurrentSnapshot_Task(ManagedObjectReference self, ManagedObjectReference? host, bool suppressPowerOn, bool suppressPowerOnSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> RevertToSnapshot_Task(ManagedObjectReference self, ManagedObjectReference? host, bool suppressPowerOn, bool suppressPowerOnSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> RevertVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task<ManagedObjectReference?> RevertVStorageObjectEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task RewindCollector(ManagedObjectReference self);

    System.Threading.Tasks.Task RunScheduledTask(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostVsanInternalSystemVsanPhysicalDiskDiagnosticsResult[]?> RunVsanPhysicalDiskDiagnostics(ManagedObjectReference self, string[]? disks);

    System.Threading.Tasks.Task<ManagedObjectReference?> ScanHostPatch_Task(ManagedObjectReference self, HostPatchManagerLocator repository, string[]? updateID);

    System.Threading.Tasks.Task<ManagedObjectReference?> ScanHostPatchV2_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, HostPatchManagerPatchManagerOperationSpec? spec);

    System.Threading.Tasks.Task ScheduleReconcileDatastoreInventory(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified);

    System.Threading.Tasks.Task<ManagedObjectReference?> SearchDatastore_Task(ManagedObjectReference self, string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec);

    System.Threading.Tasks.Task<ManagedObjectReference?> SearchDatastoreSubFolders_Task(ManagedObjectReference self, string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec);

    System.Threading.Tasks.Task SelectActivePartition(ManagedObjectReference self, HostScsiDiskPartition? partition);

    System.Threading.Tasks.Task SelectVnic(ManagedObjectReference self, string device);

    System.Threading.Tasks.Task SelectVnicForNicType(ManagedObjectReference self, string nicType, string device);

    System.Threading.Tasks.Task SendNMI(ManagedObjectReference self);

    System.Threading.Tasks.Task SendTestNotification(ManagedObjectReference self);

    System.Threading.Tasks.Task<bool> SessionIsActive(ManagedObjectReference self, string sessionID, string userName);

    System.Threading.Tasks.Task<ManagedObjectReference?> SetClusterMode_Task(ManagedObjectReference self, string mode);

    System.Threading.Tasks.Task SetCollectorPageSize(ManagedObjectReference self, int maxCount);

    System.Threading.Tasks.Task SetCryptoMode(ManagedObjectReference self, string cryptoMode, ClusterComputeResourceCryptoModePolicy? policy);

    System.Threading.Tasks.Task SetCustomValue(ManagedObjectReference self, string key, string value);

    System.Threading.Tasks.Task SetDefaultKmsCluster(ManagedObjectReference self, ManagedObjectReference? entity, KeyProviderId? clusterId);

    System.Threading.Tasks.Task SetDisplayTopology(ManagedObjectReference self, VirtualMachineDisplayTopology[] displays);

    System.Threading.Tasks.Task SetEntityPermissions(ManagedObjectReference self, ManagedObjectReference entity, Permission[]? permission);

    System.Threading.Tasks.Task SetExtensionCertificate(ManagedObjectReference self, string extensionKey, string? certificatePem);

    System.Threading.Tasks.Task SetField(ManagedObjectReference self, ManagedObjectReference entity, int key, string value);

    System.Threading.Tasks.Task<CryptoKeyResult?> SetKeyCustomAttributes(ManagedObjectReference self, CryptoKeyId keyId, CryptoManagerKmipCustomAttributeSpec spec);

    System.Threading.Tasks.Task SetLicenseEdition(ManagedObjectReference self, ManagedObjectReference? host, string? featureKey);

    System.Threading.Tasks.Task SetLocale(ManagedObjectReference self, string locale);

    System.Threading.Tasks.Task SetMaxQueueDepth(ManagedObjectReference self, ManagedObjectReference datastore, long maxQdepth);

    System.Threading.Tasks.Task SetMultipathLunPolicy(ManagedObjectReference self, string lunId, HostMultipathInfoLogicalUnitPolicy policy);

    System.Threading.Tasks.Task SetNFSUser(ManagedObjectReference self, string user, string password);

    System.Threading.Tasks.Task SetPublicKey(ManagedObjectReference self, string extensionKey, string publicKey);

    System.Threading.Tasks.Task SetRegistryValueInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegValueSpec value);

    System.Threading.Tasks.Task SetScreenResolution(ManagedObjectReference self, int width, int height);

    System.Threading.Tasks.Task SetServiceAccount(ManagedObjectReference self, string extensionKey, string serviceAccount);

    System.Threading.Tasks.Task SetTaskDescription(ManagedObjectReference self, LocalizableMessage description);

    System.Threading.Tasks.Task SetTaskState(ManagedObjectReference self, TaskInfoState state, object? result, LocalizedMethodFault? fault);

    System.Threading.Tasks.Task SetVirtualDiskUuid(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, string uuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> SetVirtualDiskUuidEx_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, string? uuid);

    System.Threading.Tasks.Task SetVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags);

    System.Threading.Tasks.Task<ManagedObjectReference?> ShrinkVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, bool copy, bool copySpecified);

    System.Threading.Tasks.Task ShutdownGuest(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> ShutdownHost_Task(ManagedObjectReference self, bool force);

    System.Threading.Tasks.Task<ManagedObjectReference?> StageHostPatch_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> StampAllRulesWithUuid_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task StandbyGuest(ManagedObjectReference self);

    System.Threading.Tasks.Task StartDpuFailover(ManagedObjectReference self, string dvsName, string? targetDpuAlias);

    System.Threading.Tasks.Task<ManagedObjectReference?> StartGuestNetwork_Task(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth);

    System.Threading.Tasks.Task<long> StartProgramInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestProgramSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> StartRecording_Task(ManagedObjectReference self, string name, string? description);

    System.Threading.Tasks.Task<ManagedObjectReference?> StartReplaying_Task(ManagedObjectReference self, ManagedObjectReference replaySnapshot);

    System.Threading.Tasks.Task StartService(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<ManagedObjectReference?> StopRecording_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> StopReplaying_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task StopService(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<ManagedObjectReference?> SuspendVApp_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> SuspendVM_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> TerminateFaultTolerantVM_Task(ManagedObjectReference self, ManagedObjectReference? vm);

    System.Threading.Tasks.Task TerminateProcessInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, long pid);

    System.Threading.Tasks.Task TerminateSession(ManagedObjectReference self, string[] sessionId);

    System.Threading.Tasks.Task TerminateVM(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostDateTimeSystemServiceTestResult?> TestTimeService(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> TurnDiskLocatorLedOff_Task(ManagedObjectReference self, string[] scsiDiskUuids);

    System.Threading.Tasks.Task<ManagedObjectReference?> TurnDiskLocatorLedOn_Task(ManagedObjectReference self, string[] scsiDiskUuids);

    System.Threading.Tasks.Task<ManagedObjectReference?> TurnOffFaultToleranceForVM_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task UnassignUserFromGroup(ManagedObjectReference self, string user, string group);

    System.Threading.Tasks.Task UnbindVnic(ManagedObjectReference self, string iScsiHbaName, string vnicDevice, bool force);

    System.Threading.Tasks.Task<ManagedObjectReference?> UninstallHostPatch_Task(ManagedObjectReference self, string[]? bulletinIds, HostPatchManagerPatchManagerOperationSpec? spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> UninstallIoFilter_Task(ManagedObjectReference self, string filterId, ManagedObjectReference compRes);

    System.Threading.Tasks.Task UninstallService(ManagedObjectReference self, string id);

    System.Threading.Tasks.Task<ManagedObjectReference?> UnmapVmfsVolumeEx_Task(ManagedObjectReference self, string[] vmfsUuid);

    System.Threading.Tasks.Task UnmarkServiceProviderEntities(ManagedObjectReference self, ManagedObjectReference[]? entity);

    System.Threading.Tasks.Task<ManagedObjectReference?> UnmountDiskMapping_Task(ManagedObjectReference self, VsanHostDiskMapping[] mapping);

    System.Threading.Tasks.Task UnmountForceMountedVmfsVolume(ManagedObjectReference self, string vmfsUuid);

    System.Threading.Tasks.Task UnmountToolsInstaller(ManagedObjectReference self);

    System.Threading.Tasks.Task UnmountVffsVolume(ManagedObjectReference self, string vffsUuid);

    System.Threading.Tasks.Task UnmountVmfsVolume(ManagedObjectReference self, string vmfsUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> UnmountVmfsVolumeEx_Task(ManagedObjectReference self, string[] vmfsUuid);

    System.Threading.Tasks.Task<ManagedObjectReference?> UnregisterAndDestroy_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task UnregisterExtension(ManagedObjectReference self, string extensionKey);

    System.Threading.Tasks.Task UnregisterHealthUpdateProvider(ManagedObjectReference self, string providerId);

    System.Threading.Tasks.Task UnregisterKmsCluster(ManagedObjectReference self, KeyProviderId clusterId);

    System.Threading.Tasks.Task<ManagedObjectReference?> UnregisterVApp_Task(ManagedObjectReference self);

    System.Threading.Tasks.Task UnregisterVM(ManagedObjectReference self);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateAnswerFile_Task(ManagedObjectReference self, ManagedObjectReference host, AnswerFileCreateSpec configSpec);

    System.Threading.Tasks.Task UpdateAssignableHardwareConfig(ManagedObjectReference self, HostAssignableHardwareConfig config);

    System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateAssignedLicense(ManagedObjectReference self, string entity, string licenseKey, string? entityDisplayName);

    System.Threading.Tasks.Task UpdateAuthorizationRole(ManagedObjectReference self, int roleId, string newName, string[]? privIds);

    System.Threading.Tasks.Task UpdateBootDevice(ManagedObjectReference self, string key);

    System.Threading.Tasks.Task UpdateChildResourceConfiguration(ManagedObjectReference self, ResourceConfigSpec[] spec);

    System.Threading.Tasks.Task UpdateClusterProfile(ManagedObjectReference self, ClusterProfileConfigSpec config);

    System.Threading.Tasks.Task UpdateConfig(ManagedObjectReference self, string? name, ResourceConfigSpec? config);

    System.Threading.Tasks.Task UpdateConsoleIpRouteConfig(ManagedObjectReference self, HostIpRouteConfig config);

    System.Threading.Tasks.Task UpdateCounterLevelMapping(ManagedObjectReference self, PerformanceManagerCounterLevelMapping[] counterLevelMap);

    System.Threading.Tasks.Task UpdateDateTime(ManagedObjectReference self, DateTime dateTime);

    System.Threading.Tasks.Task UpdateDateTimeConfig(ManagedObjectReference self, HostDateTimeConfig config);

    System.Threading.Tasks.Task UpdateDefaultPolicy(ManagedObjectReference self, HostFirewallDefaultPolicy defaultPolicy);

    System.Threading.Tasks.Task UpdateDiskPartitions(ManagedObjectReference self, string devicePath, HostDiskPartitionSpec spec);

    System.Threading.Tasks.Task UpdateDnsConfig(ManagedObjectReference self, HostDnsConfig config);

    System.Threading.Tasks.Task UpdateDvsCapability(ManagedObjectReference self, DVSCapability capability);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateDVSHealthCheckConfig_Task(ManagedObjectReference self, DVSHealthCheckConfig[] healthCheckConfig);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateDVSLacpGroupConfig_Task(ManagedObjectReference self, VMwareDvsLacpGroupSpec[] lacpGroupSpec);

    System.Threading.Tasks.Task UpdateExtension(ManagedObjectReference self, Extension extension);

    System.Threading.Tasks.Task UpdateFlags(ManagedObjectReference self, HostFlagInfo flagInfo);

    System.Threading.Tasks.Task UpdateGraphicsConfig(ManagedObjectReference self, HostGraphicsConfig config);

    System.Threading.Tasks.Task UpdateHostImageAcceptanceLevel(ManagedObjectReference self, string newAcceptanceLevel);

    System.Threading.Tasks.Task UpdateHostProfile(ManagedObjectReference self, HostProfileConfigSpec config);

    System.Threading.Tasks.Task UpdateHostSpecification(ManagedObjectReference self, ManagedObjectReference host, HostSpecification hostSpec);

    System.Threading.Tasks.Task UpdateHostSubSpecification(ManagedObjectReference self, ManagedObjectReference host, HostSubSpecification hostSubSpec);

    System.Threading.Tasks.Task UpdateHppMultipathLunPolicy(ManagedObjectReference self, string lunId, HostMultipathInfoHppLogicalUnitPolicy policy);

    System.Threading.Tasks.Task UpdateInternetScsiAdvancedOptions(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaParamValue[] options);

    System.Threading.Tasks.Task UpdateInternetScsiAlias(ManagedObjectReference self, string iScsiHbaDevice, string iScsiAlias);

    System.Threading.Tasks.Task UpdateInternetScsiAuthenticationProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaAuthenticationProperties authenticationProperties, HostInternetScsiHbaTargetSet? targetSet);

    System.Threading.Tasks.Task UpdateInternetScsiDigestProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaDigestProperties digestProperties);

    System.Threading.Tasks.Task UpdateInternetScsiDiscoveryProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaDiscoveryProperties discoveryProperties);

    System.Threading.Tasks.Task UpdateInternetScsiIPProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaIPProperties ipProperties);

    System.Threading.Tasks.Task UpdateInternetScsiName(ManagedObjectReference self, string iScsiHbaDevice, string iScsiName);

    System.Threading.Tasks.Task UpdateIpConfig(ManagedObjectReference self, HostIpConfig ipConfig);

    System.Threading.Tasks.Task UpdateIpmi(ManagedObjectReference self, HostIpmiInfo ipmiInfo);

    System.Threading.Tasks.Task UpdateIpPool(ManagedObjectReference self, ManagedObjectReference dc, IpPool pool);

    System.Threading.Tasks.Task UpdateIpRouteConfig(ManagedObjectReference self, HostIpRouteConfig config);

    System.Threading.Tasks.Task UpdateIpRouteTableConfig(ManagedObjectReference self, HostIpRouteTableConfig config);

    System.Threading.Tasks.Task UpdateKmipServer(ManagedObjectReference self, KmipServerSpec server);

    System.Threading.Tasks.Task UpdateKmsSignedCsrClientCert(ManagedObjectReference self, KeyProviderId cluster, string certificate);

    System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateLicense(ManagedObjectReference self, string licenseKey, KeyValue[]? labels);

    System.Threading.Tasks.Task UpdateLicenseLabel(ManagedObjectReference self, string licenseKey, string labelKey, string labelValue);

    System.Threading.Tasks.Task UpdateLinkedChildren(ManagedObjectReference self, VirtualAppLinkInfo[]? addChangeSet, ManagedObjectReference[]? removeSet);

    System.Threading.Tasks.Task UpdateLocalSwapDatastore(ManagedObjectReference self, ManagedObjectReference? datastore);

    System.Threading.Tasks.Task UpdateLockdownExceptions(ManagedObjectReference self, string[]? users);

    System.Threading.Tasks.Task UpdateModuleOptionString(ManagedObjectReference self, string name, string options);

    System.Threading.Tasks.Task<HostNetworkConfigResult?> UpdateNetworkConfig(ManagedObjectReference self, HostNetworkConfig config, string changeMode);

    System.Threading.Tasks.Task UpdateNetworkResourcePool(ManagedObjectReference self, DVSNetworkResourcePoolConfigSpec[] configSpec);

    System.Threading.Tasks.Task UpdateOptions(ManagedObjectReference self, OptionValue[] changedValue);

    System.Threading.Tasks.Task UpdatePassthruConfig(ManagedObjectReference self, HostPciPassthruConfig[] config);

    System.Threading.Tasks.Task UpdatePerfInterval(ManagedObjectReference self, PerfInterval interval);

    System.Threading.Tasks.Task UpdatePhysicalNicLinkSpeed(ManagedObjectReference self, string device, PhysicalNicLinkInfo? linkSpeed);

    System.Threading.Tasks.Task UpdatePortGroup(ManagedObjectReference self, string pgName, HostPortGroupSpec portgrp);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateProductLockerLocation_Task(ManagedObjectReference self, string path);

    System.Threading.Tasks.Task UpdateProgress(ManagedObjectReference self, int percentDone);

    System.Threading.Tasks.Task UpdateReferenceHost(ManagedObjectReference self, ManagedObjectReference? host);

    System.Threading.Tasks.Task UpdateRuleset(ManagedObjectReference self, string id, HostFirewallRulesetRulesetSpec spec);

    System.Threading.Tasks.Task UpdateScsiLunDisplayName(ManagedObjectReference self, string lunUuid, string displayName);

    System.Threading.Tasks.Task UpdateSelfSignedClientCert(ManagedObjectReference self, KeyProviderId cluster, string certificate);

    System.Threading.Tasks.Task UpdateServiceConsoleVirtualNic(ManagedObjectReference self, string device, HostVirtualNicSpec nic);

    System.Threading.Tasks.Task UpdateServiceMessage(ManagedObjectReference self, string message);

    System.Threading.Tasks.Task UpdateServicePolicy(ManagedObjectReference self, string id, string policy);

    System.Threading.Tasks.Task UpdateSoftwareInternetScsiEnabled(ManagedObjectReference self, bool enabled);

    System.Threading.Tasks.Task UpdateSystemResources(ManagedObjectReference self, HostSystemResourceInfo resourceInfo);

    System.Threading.Tasks.Task UpdateSystemSwapConfiguration(ManagedObjectReference self, HostSystemSwapConfiguration sysSwapConfig);

    System.Threading.Tasks.Task UpdateSystemUsers(ManagedObjectReference self, string[]? users);

    System.Threading.Tasks.Task UpdateUser(ManagedObjectReference self, HostAccountSpec user);

    System.Threading.Tasks.Task UpdateVAppConfig(ManagedObjectReference self, VAppConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVirtualMachineFiles_Task(ManagedObjectReference self, DatastoreMountPathDatastorePair[] mountPathDatastoreMapping);

    System.Threading.Tasks.Task UpdateVirtualNic(ManagedObjectReference self, string device, HostVirtualNicSpec nic);

    System.Threading.Tasks.Task UpdateVirtualSwitch(ManagedObjectReference self, string vswitchName, HostVirtualSwitchSpec spec);

    System.Threading.Tasks.Task UpdateVmfsUnmapBandwidth(ManagedObjectReference self, string vmfsUuid, VmfsUnmapBandwidthSpec unmapBandwidthSpec);

    System.Threading.Tasks.Task UpdateVmfsUnmapPriority(ManagedObjectReference self, string vmfsUuid, string unmapPriority);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVsan_Task(ManagedObjectReference self, VsanHostConfigInfo config);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVStorageInfrastructureObjectPolicy_Task(ManagedObjectReference self, vslmInfrastructureObjectPolicySpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVStorageObjectCrypto_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VirtualMachineProfileSpec[]? profile, DiskCryptoSpec? disksCrypto);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVStorageObjectPolicy_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VirtualMachineProfileSpec[]? profile);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVVolVirtualMachineFiles_Task(ManagedObjectReference self, DatastoreVVolContainerFailoverPair[]? failoverPair);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpgradeIoFilter_Task(ManagedObjectReference self, string filterId, ManagedObjectReference compRes, string vibUrl, IoFilterManagerSslTrust? vibSslTrust);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpgradeTools_Task(ManagedObjectReference self, string? installerOptions);

    System.Threading.Tasks.Task<ManagedObjectReference?> UpgradeVM_Task(ManagedObjectReference self, string? version);

    System.Threading.Tasks.Task UpgradeVmfs(ManagedObjectReference self, string vmfsPath);

    System.Threading.Tasks.Task UpgradeVmLayout(ManagedObjectReference self);

    System.Threading.Tasks.Task<HostVsanInternalSystemVsanObjectOperationResult[]?> UpgradeVsanObjects(ManagedObjectReference self, string[] uuids, int newVersion);

    System.Threading.Tasks.Task UploadClientCert(ManagedObjectReference self, KeyProviderId cluster, string certificate, string privateKey);

    System.Threading.Tasks.Task UploadKmipServerCert(ManagedObjectReference self, KeyProviderId cluster, string certificate);

    System.Threading.Tasks.Task ValidateCredentialsInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth);

    System.Threading.Tasks.Task<ClusterComputeResourceValidationResultBase[]?> ValidateHCIConfiguration(ManagedObjectReference self, ClusterComputeResourceHCIConfigSpec? hciConfigSpec, ManagedObjectReference[]? hosts);

    System.Threading.Tasks.Task<OvfValidateHostResult?> ValidateHost(ManagedObjectReference self, string ovfDescriptor, ManagedObjectReference host, OvfValidateHostParams vhp);

    System.Threading.Tasks.Task<ManagedObjectReference?> ValidateHostProfileComposition_Task(ManagedObjectReference self, ManagedObjectReference source, ManagedObjectReference[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toReplaceWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied, bool errorOnly, bool errorOnlySpecified);

    System.Threading.Tasks.Task<Event[]?> ValidateMigration(ManagedObjectReference self, ManagedObjectReference[] vm, VirtualMachinePowerState state, bool stateSpecified, string[]? testType, ManagedObjectReference? pool, ManagedObjectReference? host);

    System.Threading.Tasks.Task<LocalizedMethodFault?> ValidateStoragePodConfig(ManagedObjectReference self, ManagedObjectReference pod, StorageDrsConfigSpec spec);

    System.Threading.Tasks.Task<ManagedObjectReference?> VCenterUpdateVStorageObjectMetadataEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, KeyValue[]? metadata, string[]? deleteKeys);

    System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectCreateSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string description);

    System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectCreateSnapshotEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string description);

    System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectDeleteSnapshotEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectDeleteSnapshotEx2_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId);

    System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectExtendDiskEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, long newCapacityInMB);

    System.Threading.Tasks.Task<DiskChangeInfo?> VstorageObjectVCenterQueryChangedDiskAreas(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId, long startOffset, string changeId);

    System.Threading.Tasks.Task<UpdateSet?> WaitForUpdates(ManagedObjectReference self, string? version);

    System.Threading.Tasks.Task<UpdateSet?> WaitForUpdatesEx(ManagedObjectReference self, string? version, WaitOptions? options);

    System.Threading.Tasks.Task<CustomizationSpecItem?> XmlToCustomizationSpecItem(ManagedObjectReference self, string specItemXml);

    System.Threading.Tasks.Task<ManagedObjectReference?> ZeroFillVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter);

}

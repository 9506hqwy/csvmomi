namespace CsVmomi;

#pragma warning disable SA1402 // File may only contain a single type

public partial class Alarm : ExtensibleManagedObject
{
    protected Alarm(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<AlarmInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<AlarmInfo>("info");
        return obj!;
    }

    public async System.Threading.Tasks.Task ReconfigureAlarm(AlarmSpec spec)
    {
        await this.Session.VimClient.ReconfigureAlarm(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task RemoveAlarm()
    {
        await this.Session.VimClient.RemoveAlarm(this.VimReference);
    }
}

public partial class AlarmManager : ManagedObject
{
    protected AlarmManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<AlarmExpression[]?> GetPropertyDefaultExpression()
    {
        var obj = await this.GetProperty<AlarmExpression[]>("defaultExpression");
        return obj;
    }

    public async System.Threading.Tasks.Task<AlarmDescription> GetPropertyDescription()
    {
        var obj = await this.GetProperty<AlarmDescription>("description");
        return obj!;
    }

    public async System.Threading.Tasks.Task AcknowledgeAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.VimClient.AcknowledgeAlarm(this.VimReference, alarm.VimReference, entity.VimReference);
    }

    public async System.Threading.Tasks.Task<bool> AreAlarmActionsEnabled(ManagedEntity entity)
    {
        return await this.Session.VimClient.AreAlarmActionsEnabled(this.VimReference, entity.VimReference);
    }

    public async System.Threading.Tasks.Task ClearTriggeredAlarms(AlarmFilterSpec filter)
    {
        await this.Session.VimClient.ClearTriggeredAlarms(this.VimReference, filter);
    }

    public async System.Threading.Tasks.Task<Alarm?> CreateAlarm(ManagedEntity entity, AlarmSpec spec)
    {
        var res = await this.Session.VimClient.CreateAlarm(this.VimReference, entity.VimReference, spec);
        return ManagedObject.Create<Alarm>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.VimClient.DisableAlarm(this.VimReference, alarm.VimReference, entity.VimReference);
    }

    public async System.Threading.Tasks.Task EnableAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.VimClient.EnableAlarm(this.VimReference, alarm.VimReference, entity.VimReference);
    }

    public async System.Threading.Tasks.Task EnableAlarmActions(ManagedEntity entity, bool enabled)
    {
        await this.Session.VimClient.EnableAlarmActions(this.VimReference, entity.VimReference, enabled);
    }

    public async System.Threading.Tasks.Task<Alarm[]?> GetAlarm(ManagedEntity? entity)
    {
        var res = await this.Session.VimClient.GetAlarm(this.VimReference, entity?.VimReference);
        return res?.Select(r => ManagedObject.Create<Alarm>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<AlarmState[]?> GetAlarmState(ManagedEntity entity)
    {
        return await this.Session.VimClient.GetAlarmState(this.VimReference, entity.VimReference);
    }
}

public partial class AuthorizationManager : ManagedObject
{
    protected AuthorizationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<AuthorizationDescription> GetPropertyDescription()
    {
        var obj = await this.GetProperty<AuthorizationDescription>("description");
        return obj!;
    }

    public async System.Threading.Tasks.Task<AuthorizationPrivilege[]?> GetPropertyPrivilegeList()
    {
        var obj = await this.GetProperty<AuthorizationPrivilege[]>("privilegeList");
        return obj;
    }

    public async System.Threading.Tasks.Task<AuthorizationRole[]?> GetPropertyRoleList()
    {
        var obj = await this.GetProperty<AuthorizationRole[]>("roleList");
        return obj;
    }

    public async System.Threading.Tasks.Task<int> AddAuthorizationRole(string name, string[]? privIds)
    {
        return await this.Session.VimClient.AddAuthorizationRole(this.VimReference, name, privIds);
    }

    public async System.Threading.Tasks.Task<UserPrivilegeResult[]?> FetchUserPrivilegeOnEntities(ManagedEntity[] entities, string userName)
    {
        return await this.Session.VimClient.FetchUserPrivilegeOnEntities(this.VimReference, entities.Select(m => m.VimReference).ToArray(), userName);
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]?> HasPrivilegeOnEntities(ManagedEntity[] entity, string sessionId, string[]? privId)
    {
        return await this.Session.VimClient.HasPrivilegeOnEntities(this.VimReference, entity.Select(m => m.VimReference).ToArray(), sessionId, privId);
    }

    public async System.Threading.Tasks.Task<bool[]?> HasPrivilegeOnEntity(ManagedEntity entity, string sessionId, string[]? privId)
    {
        return await this.Session.VimClient.HasPrivilegeOnEntity(this.VimReference, entity.VimReference, sessionId, privId);
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]?> HasUserPrivilegeOnEntities(ManagedObject[] entities, string userName, string[]? privId)
    {
        return await this.Session.VimClient.HasUserPrivilegeOnEntities(this.VimReference, entities.Select(m => m.VimReference).ToArray(), userName, privId);
    }

    public async System.Threading.Tasks.Task MergePermissions(int srcRoleId, int dstRoleId)
    {
        await this.Session.VimClient.MergePermissions(this.VimReference, srcRoleId, dstRoleId);
    }

    public async System.Threading.Tasks.Task RemoveAuthorizationRole(int roleId, bool failIfUsed)
    {
        await this.Session.VimClient.RemoveAuthorizationRole(this.VimReference, roleId, failIfUsed);
    }

    public async System.Threading.Tasks.Task RemoveEntityPermission(ManagedEntity entity, string user, bool isGroup)
    {
        await this.Session.VimClient.RemoveEntityPermission(this.VimReference, entity.VimReference, user, isGroup);
    }

    public async System.Threading.Tasks.Task ResetEntityPermissions(ManagedEntity entity, Permission[]? permission)
    {
        await this.Session.VimClient.ResetEntityPermissions(this.VimReference, entity.VimReference, permission);
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveAllPermissions()
    {
        return await this.Session.VimClient.RetrieveAllPermissions(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveEntityPermissions(ManagedEntity entity, bool inherited)
    {
        return await this.Session.VimClient.RetrieveEntityPermissions(this.VimReference, entity.VimReference, inherited);
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveRolePermissions(int roleId)
    {
        return await this.Session.VimClient.RetrieveRolePermissions(this.VimReference, roleId);
    }

    public async System.Threading.Tasks.Task SetEntityPermissions(ManagedEntity entity, Permission[]? permission)
    {
        await this.Session.VimClient.SetEntityPermissions(this.VimReference, entity.VimReference, permission);
    }

    public async System.Threading.Tasks.Task UpdateAuthorizationRole(int roleId, string newName, string[]? privIds)
    {
        await this.Session.VimClient.UpdateAuthorizationRole(this.VimReference, roleId, newName, privIds);
    }
}

public partial class CertificateManager : ManagedObject
{
    protected CertificateManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> CertMgrRefreshCACertificatesAndCRLs_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.CertMgrRefreshCACertificatesAndCRLs_Task(this.VimReference, host.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CertMgrRefreshCertificates_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.CertMgrRefreshCertificates_Task(this.VimReference, host.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CertMgrRevokeCertificates_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.CertMgrRevokeCertificates_Task(this.VimReference, host.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class ClusterComputeResource : ComputeResource
{
    protected ClusterComputeResource(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ClusterActionHistory[]?> GetPropertyActionHistory()
    {
        var obj = await this.GetProperty<ClusterActionHistory[]>("actionHistory");
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterConfigInfo> GetPropertyConfiguration()
    {
        var obj = await this.GetProperty<ClusterConfigInfo>("configuration");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ClusterDrsFaults[]?> GetPropertyDrsFault()
    {
        var obj = await this.GetProperty<ClusterDrsFaults[]>("drsFault");
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterDrsRecommendation[]?> GetPropertyDrsRecommendation()
    {
        var obj = await this.GetProperty<ClusterDrsRecommendation[]>("drsRecommendation");
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceHCIConfigInfo?> GetPropertyHciConfig()
    {
        var obj = await this.GetProperty<ClusterComputeResourceHCIConfigInfo>("hciConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterDrsMigration[]?> GetPropertyMigrationHistory()
    {
        var obj = await this.GetProperty<ClusterDrsMigration[]>("migrationHistory");
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterRecommendation[]?> GetPropertyRecommendation()
    {
        var obj = await this.GetProperty<ClusterRecommendation[]>("recommendation");
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceSummary> GetPropertySummaryEx()
    {
        var obj = await this.GetProperty<ClusterComputeResourceSummary>("summaryEx");
        return obj!;
    }

    public async System.Threading.Tasks.Task AbandonHciWorkflow()
    {
        await this.Session.VimClient.AbandonHciWorkflow(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> AddHost_Task(HostConnectSpec spec, bool asConnected, ResourcePool? resourcePool, string? license)
    {
        var res = await this.Session.VimClient.AddHost_Task(this.VimReference, spec, asConnected, resourcePool?.VimReference, license);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ApplyRecommendation(string key)
    {
        await this.Session.VimClient.ApplyRecommendation(this.VimReference, key);
    }

    public async System.Threading.Tasks.Task CancelRecommendation(string key)
    {
        await this.Session.VimClient.CancelRecommendation(this.VimReference, key);
    }

    public async System.Threading.Tasks.Task<ClusterEnterMaintenanceResult?> ClusterEnterMaintenanceMode(HostSystem[] host, OptionValue[]? option)
    {
        return await this.Session.VimClient.ClusterEnterMaintenanceMode(this.VimReference, host.Select(m => m.VimReference).ToArray(), option);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureHCI_Task(ClusterComputeResourceHCIConfigSpec clusterSpec, ClusterComputeResourceHostConfigurationInput[]? hostInputs)
    {
        var res = await this.Session.VimClient.ConfigureHCI_Task(this.VimReference, clusterSpec, hostInputs);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterEVCManager?> EvcManager()
    {
        var res = await this.Session.VimClient.EvcManager(this.VimReference);
        return ManagedObject.Create<ClusterEVCManager>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ExtendHCI_Task(ClusterComputeResourceHostConfigurationInput[]? hostInputs, SDDCBase? vSanConfigSpec)
    {
        var res = await this.Session.VimClient.ExtendHCI_Task(this.VimReference, hostInputs, vSanConfigSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterRuleInfo[]?> FindRulesForVm(VirtualMachine vm)
    {
        return await this.Session.VimClient.FindRulesForVm(this.VimReference, vm.VimReference);
    }

    public async System.Threading.Tasks.Task<ClusterResourceUsageSummary?> GetResourceUsage()
    {
        return await this.Session.VimClient.GetResourceUsage(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetSystemVMsRestrictedDatastores()
    {
        var res = await this.Session.VimClient.GetSystemVMsRestrictedDatastores(this.VimReference);
        return res?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Task?> MoveHostInto_Task(HostSystem host, ResourcePool? resourcePool)
    {
        var res = await this.Session.VimClient.MoveHostInto_Task(this.VimReference, host.VimReference, resourcePool?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveInto_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.MoveInto_Task(this.VimReference, host.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<PlacementResult?> PlaceVm(PlacementSpec placementSpec)
    {
        return await this.Session.VimClient.PlaceVm(this.VimReference, placementSpec);
    }

    public async System.Threading.Tasks.Task<ClusterHostRecommendation[]?> RecommendHostsForVm(VirtualMachine vm, ResourcePool? pool)
    {
        return await this.Session.VimClient.RecommendHostsForVm(this.VimReference, vm.VimReference, pool?.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureCluster_Task(ClusterConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ReconfigureCluster_Task(this.VimReference, spec, modify);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshRecommendation()
    {
        await this.Session.VimClient.RefreshRecommendation(this.VimReference);
    }

    public async System.Threading.Tasks.Task<ClusterDasAdvancedRuntimeInfo?> RetrieveDasAdvancedRuntimeInfo()
    {
        return await this.Session.VimClient.RetrieveDasAdvancedRuntimeInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task SetCryptoMode(string cryptoMode)
    {
        await this.Session.VimClient.SetCryptoMode(this.VimReference, cryptoMode);
    }

    public async System.Threading.Tasks.Task<Task?> StampAllRulesWithUuid_Task()
    {
        var res = await this.Session.VimClient.StampAllRulesWithUuid_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceValidationResultBase[]?> ValidateHCIConfiguration(ClusterComputeResourceHCIConfigSpec? hciConfigSpec, HostSystem[]? hosts)
    {
        return await this.Session.VimClient.ValidateHCIConfiguration(this.VimReference, hciConfigSpec, hosts?.Select(m => m.VimReference).ToArray());
    }
}

public partial class ClusterEVCManager : ExtensibleManagedObject
{
    protected ClusterEVCManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ClusterEVCManagerEVCState> GetPropertyEvcState()
    {
        var obj = await this.GetProperty<ClusterEVCManagerEVCState>("evcState");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource> GetPropertyManagedCluster()
    {
        var managedCluster = await this.GetProperty<ManagedObjectReference>("managedCluster");
        return ManagedObject.Create<ClusterComputeResource>(managedCluster, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Task?> CheckAddHostEvc_Task(HostConnectSpec cnxSpec)
    {
        var res = await this.Session.VimClient.CheckAddHostEvc_Task(this.VimReference, cnxSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckConfigureEvcMode_Task(string evcModeKey, string? evcGraphicsModeKey)
    {
        var res = await this.Session.VimClient.CheckConfigureEvcMode_Task(this.VimReference, evcModeKey, evcGraphicsModeKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureEvcMode_Task(string evcModeKey, string? evcGraphicsModeKey)
    {
        var res = await this.Session.VimClient.ConfigureEvcMode_Task(this.VimReference, evcModeKey, evcGraphicsModeKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DisableEvcMode_Task()
    {
        var res = await this.Session.VimClient.DisableEvcMode_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class ClusterProfile : Profile
{
    protected ClusterProfile(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task UpdateClusterProfile(ClusterProfileConfigSpec config)
    {
        await this.Session.VimClient.UpdateClusterProfile(this.VimReference, config);
    }
}

public partial class ClusterProfileManager : ProfileManager
{
    protected ClusterProfileManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class ComputeResource : ManagedEntity
{
    protected ComputeResource(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyConfigManagerEnabled()
    {
        var obj = await this.GetProperty<bool>("configManagerEnabled");
        return obj;
    }

    public async System.Threading.Tasks.Task<ComputeResourceConfigInfo> GetPropertyConfigurationEx()
    {
        var obj = await this.GetProperty<ComputeResourceConfigInfo>("configurationEx");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore?
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<EnvironmentBrowser?> GetPropertyEnvironmentBrowser()
    {
        var environmentBrowser = await this.GetProperty<ManagedObjectReference>("environmentBrowser");
        return ManagedObject.Create<EnvironmentBrowser>(environmentBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> GetPropertyHost()
    {
        var host = await this.GetProperty<ManagedObjectReference[]>("host");
        return host?
            .Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyLifecycleManaged()
    {
        var obj = await this.GetProperty<bool>("lifecycleManaged");
        return obj;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network?
            .Select(r => ManagedObject.Create<Network>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ResourcePool?> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference>("resourcePool");
        return ManagedObject.Create<ResourcePool>(resourcePool, this.Session);
    }

    public async System.Threading.Tasks.Task<ComputeResourceSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<ComputeResourceSummary>("summary");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureComputeResource_Task(ComputeResourceConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ReconfigureComputeResource_Task(this.VimReference, spec, modify);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class ContainerView : ManagedObjectView
{
    protected ContainerView(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ManagedEntity> GetPropertyContainer()
    {
        var container = await this.GetProperty<ManagedObjectReference>("container");
        return ManagedObject.Create<ManagedEntity>(container, this.Session)!;
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyRecursive()
    {
        var obj = await this.GetProperty<bool>("recursive");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyType()
    {
        var obj = await this.GetProperty<string[]>("type");
        return obj;
    }
}

public partial class CryptoManager : ManagedObject
{
    protected CryptoManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyEnabled()
    {
        var obj = await this.GetProperty<bool>("enabled");
        return obj!;
    }

    public async System.Threading.Tasks.Task AddKey(CryptoKeyPlain key)
    {
        await this.Session.VimClient.AddKey(this.VimReference, key);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]?> AddKeys(CryptoKeyPlain[]? keys)
    {
        return await this.Session.VimClient.AddKeys(this.VimReference, keys);
    }

    public async System.Threading.Tasks.Task<CryptoKeyId[]?> ListKeys(int? limit)
    {
        return await this.Session.VimClient.ListKeys(this.VimReference, limit ?? default, limit.HasValue);
    }

    public async System.Threading.Tasks.Task RemoveKey(CryptoKeyId key, bool force)
    {
        await this.Session.VimClient.RemoveKey(this.VimReference, key, force);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]?> RemoveKeys(CryptoKeyId[]? keys, bool force)
    {
        return await this.Session.VimClient.RemoveKeys(this.VimReference, keys, force);
    }
}

public partial class CryptoManagerHost : CryptoManager
{
    protected CryptoManagerHost(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> ChangeKey_Task(CryptoKeyPlain newKey)
    {
        var res = await this.Session.VimClient.ChangeKey_Task(this.VimReference, newKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostDisable()
    {
        await this.Session.VimClient.CryptoManagerHostDisable(this.VimReference);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostEnable(CryptoKeyPlain initialKey)
    {
        await this.Session.VimClient.CryptoManagerHostEnable(this.VimReference, initialKey);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostPrepare()
    {
        await this.Session.VimClient.CryptoManagerHostPrepare(this.VimReference);
    }
}

public partial class CryptoManagerHostKMS : CryptoManagerHost
{
    protected CryptoManagerHostKMS(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class CryptoManagerKmip : CryptoManager
{
    protected CryptoManagerKmip(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]?> GetPropertyKmipServers()
    {
        var obj = await this.GetProperty<KmipClusterInfo[]>("kmipServers");
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GenerateClientCsr(KeyProviderId cluster)
    {
        return await this.Session.VimClient.GenerateClientCsr(this.VimReference, cluster);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult?> GenerateKey(KeyProviderId? keyProvider)
    {
        return await this.Session.VimClient.GenerateKey(this.VimReference, keyProvider);
    }

    public async System.Threading.Tasks.Task<string?> GenerateSelfSignedClientCert(KeyProviderId cluster)
    {
        return await this.Session.VimClient.GenerateSelfSignedClientCert(this.VimReference, cluster);
    }

    public async System.Threading.Tasks.Task<KeyProviderId?> GetDefaultKmsCluster(ManagedEntity? entity, bool? defaultsToParent)
    {
        return await this.Session.VimClient.GetDefaultKmsCluster(this.VimReference, entity?.VimReference, defaultsToParent ?? default, defaultsToParent.HasValue);
    }

    public async System.Threading.Tasks.Task<bool> IsKmsClusterActive(KeyProviderId? cluster)
    {
        return await this.Session.VimClient.IsKmsClusterActive(this.VimReference, cluster);
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmipServers(int? limit)
    {
        return await this.Session.VimClient.ListKmipServers(this.VimReference, limit ?? default, limit.HasValue);
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmsClusters(bool? includeKmsServers, int? managementTypeFilter, int? statusFilter)
    {
        return await this.Session.VimClient.ListKmsClusters(this.VimReference, includeKmsServers ?? default, includeKmsServers.HasValue, managementTypeFilter ?? default, managementTypeFilter.HasValue, statusFilter ?? default, statusFilter.HasValue);
    }

    public async System.Threading.Tasks.Task MarkDefault(KeyProviderId clusterId)
    {
        await this.Session.VimClient.MarkDefault(this.VimReference, clusterId);
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipCryptoKeyStatus[]?> QueryCryptoKeyStatus(CryptoKeyId[]? keyIds, int checkKeyBitMap)
    {
        return await this.Session.VimClient.QueryCryptoKeyStatus(this.VimReference, keyIds, checkKeyBitMap);
    }

    public async System.Threading.Tasks.Task RegisterKmipServer(KmipServerSpec server)
    {
        await this.Session.VimClient.RegisterKmipServer(this.VimReference, server);
    }

    public async System.Threading.Tasks.Task RegisterKmsCluster(KeyProviderId clusterId, string? managementType)
    {
        await this.Session.VimClient.RegisterKmsCluster(this.VimReference, clusterId, managementType);
    }

    public async System.Threading.Tasks.Task RemoveKmipServer(KeyProviderId clusterId, string serverName)
    {
        await this.Session.VimClient.RemoveKmipServer(this.VimReference, clusterId, serverName);
    }

    public async System.Threading.Tasks.Task<string?> RetrieveClientCert(KeyProviderId cluster)
    {
        return await this.Session.VimClient.RetrieveClientCert(this.VimReference, cluster);
    }

    public async System.Threading.Tasks.Task<string?> RetrieveClientCsr(KeyProviderId cluster)
    {
        return await this.Session.VimClient.RetrieveClientCsr(this.VimReference, cluster);
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipServerCertInfo?> RetrieveKmipServerCert(KeyProviderId keyProvider, KmipServerInfo server)
    {
        return await this.Session.VimClient.RetrieveKmipServerCert(this.VimReference, keyProvider, server);
    }

    public async System.Threading.Tasks.Task<Task?> RetrieveKmipServersStatus_Task(KmipClusterInfo[]? clusters)
    {
        var res = await this.Session.VimClient.RetrieveKmipServersStatus_Task(this.VimReference, clusters);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string?> RetrieveSelfSignedClientCert(KeyProviderId cluster)
    {
        return await this.Session.VimClient.RetrieveSelfSignedClientCert(this.VimReference, cluster);
    }

    public async System.Threading.Tasks.Task SetDefaultKmsCluster(ManagedEntity? entity, KeyProviderId? clusterId)
    {
        await this.Session.VimClient.SetDefaultKmsCluster(this.VimReference, entity?.VimReference, clusterId);
    }

    public async System.Threading.Tasks.Task UnregisterKmsCluster(KeyProviderId clusterId)
    {
        await this.Session.VimClient.UnregisterKmsCluster(this.VimReference, clusterId);
    }

    public async System.Threading.Tasks.Task UpdateKmipServer(KmipServerSpec server)
    {
        await this.Session.VimClient.UpdateKmipServer(this.VimReference, server);
    }

    public async System.Threading.Tasks.Task UpdateKmsSignedCsrClientCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.VimClient.UpdateKmsSignedCsrClientCert(this.VimReference, cluster, certificate);
    }

    public async System.Threading.Tasks.Task UpdateSelfSignedClientCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.VimClient.UpdateSelfSignedClientCert(this.VimReference, cluster, certificate);
    }

    public async System.Threading.Tasks.Task UploadClientCert(KeyProviderId cluster, string certificate, string privateKey)
    {
        await this.Session.VimClient.UploadClientCert(this.VimReference, cluster, certificate, privateKey);
    }

    public async System.Threading.Tasks.Task UploadKmipServerCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.VimClient.UploadKmipServerCert(this.VimReference, cluster, certificate);
    }
}

public partial class CustomFieldsManager : ManagedObject
{
    protected CustomFieldsManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<CustomFieldDef[]?> GetPropertyField()
    {
        var obj = await this.GetProperty<CustomFieldDef[]>("field");
        return obj;
    }

    public async System.Threading.Tasks.Task<CustomFieldDef?> AddCustomFieldDef(string name, string? moType, PrivilegePolicyDef? fieldDefPolicy, PrivilegePolicyDef? fieldPolicy)
    {
        return await this.Session.VimClient.AddCustomFieldDef(this.VimReference, name, moType, fieldDefPolicy, fieldPolicy);
    }

    public async System.Threading.Tasks.Task RemoveCustomFieldDef(int key)
    {
        await this.Session.VimClient.RemoveCustomFieldDef(this.VimReference, key);
    }

    public async System.Threading.Tasks.Task RenameCustomFieldDef(int key, string name)
    {
        await this.Session.VimClient.RenameCustomFieldDef(this.VimReference, key, name);
    }

    public async System.Threading.Tasks.Task SetField(ManagedEntity entity, int key, string value)
    {
        await this.Session.VimClient.SetField(this.VimReference, entity.VimReference, key, value);
    }
}

public partial class CustomizationSpecManager : ManagedObject
{
    protected CustomizationSpecManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<byte[]?> GetPropertyEncryptionKey()
    {
        var obj = await this.GetProperty<byte[]>("encryptionKey");
        return obj;
    }

    public async System.Threading.Tasks.Task<CustomizationSpecInfo[]?> GetPropertyInfo()
    {
        var obj = await this.GetProperty<CustomizationSpecInfo[]>("info");
        return obj;
    }

    public async System.Threading.Tasks.Task CheckCustomizationResources(string guestOs)
    {
        await this.Session.VimClient.CheckCustomizationResources(this.VimReference, guestOs);
    }

    public async System.Threading.Tasks.Task CreateCustomizationSpec(CustomizationSpecItem item)
    {
        await this.Session.VimClient.CreateCustomizationSpec(this.VimReference, item);
    }

    public async System.Threading.Tasks.Task<string?> CustomizationSpecItemToXml(CustomizationSpecItem item)
    {
        return await this.Session.VimClient.CustomizationSpecItemToXml(this.VimReference, item);
    }

    public async System.Threading.Tasks.Task DeleteCustomizationSpec(string name)
    {
        await this.Session.VimClient.DeleteCustomizationSpec(this.VimReference, name);
    }

    public async System.Threading.Tasks.Task<bool> DoesCustomizationSpecExist(string name)
    {
        return await this.Session.VimClient.DoesCustomizationSpecExist(this.VimReference, name);
    }

    public async System.Threading.Tasks.Task DuplicateCustomizationSpec(string name, string newName)
    {
        await this.Session.VimClient.DuplicateCustomizationSpec(this.VimReference, name, newName);
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem?> GetCustomizationSpec(string name)
    {
        return await this.Session.VimClient.GetCustomizationSpec(this.VimReference, name);
    }

    public async System.Threading.Tasks.Task OverwriteCustomizationSpec(CustomizationSpecItem item)
    {
        await this.Session.VimClient.OverwriteCustomizationSpec(this.VimReference, item);
    }

    public async System.Threading.Tasks.Task RenameCustomizationSpec(string name, string newName)
    {
        await this.Session.VimClient.RenameCustomizationSpec(this.VimReference, name, newName);
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem?> XmlToCustomizationSpecItem(string specItemXml)
    {
        return await this.Session.VimClient.XmlToCustomizationSpecItem(this.VimReference, specItemXml);
    }
}

public partial class Datacenter : ManagedEntity
{
    protected Datacenter(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<DatacenterConfigInfo> GetPropertyConfiguration()
    {
        var obj = await this.GetProperty<DatacenterConfigInfo>("configuration");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore?
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyDatastoreFolder()
    {
        var datastoreFolder = await this.GetProperty<ManagedObjectReference>("datastoreFolder");
        return ManagedObject.Create<Folder>(datastoreFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyHostFolder()
    {
        var hostFolder = await this.GetProperty<ManagedObjectReference>("hostFolder");
        return ManagedObject.Create<Folder>(hostFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network?
            .Select(r => ManagedObject.Create<Network>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyNetworkFolder()
    {
        var networkFolder = await this.GetProperty<ManagedObjectReference>("networkFolder");
        return ManagedObject.Create<Folder>(networkFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyVmFolder()
    {
        var vmFolder = await this.GetProperty<ManagedObjectReference>("vmFolder");
        return ManagedObject.Create<Folder>(vmFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<DatacenterBasicConnectInfo[]?> BatchQueryConnectInfo(HostConnectSpec[]? hostSpecs)
    {
        return await this.Session.VimClient.BatchQueryConnectInfo(this.VimReference, hostSpecs);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOnMultiVM_Task(VirtualMachine[] vm, OptionValue[]? option)
    {
        var res = await this.Session.VimClient.PowerOnMultiVM_Task(this.VimReference, vm.Select(m => m.VimReference).ToArray(), option);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfo(string hostname, int port, string username, string password, string? sslThumbprint)
    {
        return await this.Session.VimClient.QueryConnectionInfo(this.VimReference, hostname, port, username, password, sslThumbprint);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfoViaSpec(HostConnectSpec spec)
    {
        return await this.Session.VimClient.QueryConnectionInfoViaSpec(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryDatacenterConfigOptionDescriptor()
    {
        return await this.Session.VimClient.QueryDatacenterConfigOptionDescriptor(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDatacenter_Task(DatacenterConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ReconfigureDatacenter_Task(this.VimReference, spec, modify);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class Datastore : ManagedEntity
{
    protected Datastore(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostDatastoreBrowser> GetPropertyBrowser()
    {
        var browser = await this.GetProperty<ManagedObjectReference>("browser");
        return ManagedObject.Create<HostDatastoreBrowser>(browser, this.Session)!;
    }

    public async System.Threading.Tasks.Task<DatastoreCapability> GetPropertyCapability()
    {
        var obj = await this.GetProperty<DatastoreCapability>("capability");
        return obj!;
    }

    public async System.Threading.Tasks.Task<DatastoreHostMount[]?> GetPropertyHost()
    {
        var obj = await this.GetProperty<DatastoreHostMount[]>("host");
        return obj;
    }

    public async System.Threading.Tasks.Task<DatastoreInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<DatastoreInfo>("info");
        return obj!;
    }

    public async System.Threading.Tasks.Task<StorageIORMInfo?> GetPropertyIormConfiguration()
    {
        var obj = await this.GetProperty<StorageIORMInfo>("iormConfiguration");
        return obj;
    }

    public async System.Threading.Tasks.Task<DatastoreSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<DatastoreSummary>("summary");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm?
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult?> DatastoreEnterMaintenanceMode()
    {
        return await this.Session.VimClient.DatastoreEnterMaintenanceMode(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> DatastoreExitMaintenanceMode_Task()
    {
        var res = await this.Session.VimClient.DatastoreExitMaintenanceMode_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyDatastore()
    {
        await this.Session.VimClient.DestroyDatastore(this.VimReference);
    }

    public async System.Threading.Tasks.Task RefreshDatastore()
    {
        await this.Session.VimClient.RefreshDatastore(this.VimReference);
    }

    public async System.Threading.Tasks.Task RefreshDatastoreStorageInfo()
    {
        await this.Session.VimClient.RefreshDatastoreStorageInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task RenameDatastore(string newName)
    {
        await this.Session.VimClient.RenameDatastore(this.VimReference, newName);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVirtualMachineFiles_Task(DatastoreMountPathDatastorePair[] mountPathDatastoreMapping)
    {
        var res = await this.Session.VimClient.UpdateVirtualMachineFiles_Task(this.VimReference, mountPathDatastoreMapping);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVVolVirtualMachineFiles_Task(DatastoreVVolContainerFailoverPair[]? failoverPair)
    {
        var res = await this.Session.VimClient.UpdateVVolVirtualMachineFiles_Task(this.VimReference, failoverPair);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class DatastoreNamespaceManager : ManagedObject
{
    protected DatastoreNamespaceManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string?> ConvertNamespacePathToUuidPath(Datacenter? datacenter, string namespaceUrl)
    {
        return await this.Session.VimClient.ConvertNamespacePathToUuidPath(this.VimReference, datacenter?.VimReference, namespaceUrl);
    }

    public async System.Threading.Tasks.Task<string?> CreateDirectory(Datastore datastore, string? displayName, string? policy, long? size)
    {
        return await this.Session.VimClient.CreateDirectory(this.VimReference, datastore.VimReference, displayName, policy, size ?? default, size.HasValue);
    }

    public async System.Threading.Tasks.Task DeleteDirectory(Datacenter? datacenter, string datastorePath)
    {
        await this.Session.VimClient.DeleteDirectory(this.VimReference, datacenter?.VimReference, datastorePath);
    }
}

public partial class DiagnosticManager : ManagedObject
{
    protected DiagnosticManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerLogHeader?> BrowseDiagnosticLog(HostSystem? host, string key, int? start, int? lines)
    {
        return await this.Session.VimClient.BrowseDiagnosticLog(this.VimReference, host?.VimReference, key, start ?? default, start.HasValue, lines ?? default, lines.HasValue);
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerAuditRecordResult?> FetchAuditRecords(string? token)
    {
        return await this.Session.VimClient.FetchAuditRecords(this.VimReference, token);
    }

    public async System.Threading.Tasks.Task<Task?> GenerateLogBundles_Task(bool includeDefault, HostSystem[]? host)
    {
        var res = await this.Session.VimClient.GenerateLogBundles_Task(this.VimReference, includeDefault, host?.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerLogDescriptor[]?> QueryDescriptions(HostSystem? host)
    {
        return await this.Session.VimClient.QueryDescriptions(this.VimReference, host?.VimReference);
    }
}

public partial class DistributedVirtualPortgroup : Network
{
    protected DistributedVirtualPortgroup(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<DVPortgroupConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<DVPortgroupConfigInfo>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyKey()
    {
        var obj = await this.GetProperty<string>("key");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyPortKeys()
    {
        var obj = await this.GetProperty<string[]>("portKeys");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> DVPortgroupRollback_Task(EntityBackupConfig? entityBackup)
    {
        var res = await this.Session.VimClient.DVPortgroupRollback_Task(this.VimReference, entityBackup);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDVPortgroup_Task(DVPortgroupConfigSpec spec)
    {
        var res = await this.Session.VimClient.ReconfigureDVPortgroup_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class DistributedVirtualSwitch : ManagedEntity
{
    protected DistributedVirtualSwitch(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<DVSCapability> GetPropertyCapability()
    {
        var obj = await this.GetProperty<DVSCapability>("capability");
        return obj!;
    }

    public async System.Threading.Tasks.Task<DVSConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<DVSConfigInfo>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<DVSNetworkResourcePool[]?> GetPropertyNetworkResourcePool()
    {
        var obj = await this.GetProperty<DVSNetworkResourcePool[]>("networkResourcePool");
        return obj;
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup[]?> GetPropertyPortgroup()
    {
        var portgroup = await this.GetProperty<ManagedObjectReference[]>("portgroup");
        return portgroup?
            .Select(r => ManagedObject.Create<DistributedVirtualPortgroup>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<DVSRuntimeInfo?> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<DVSRuntimeInfo>("runtime");
        return obj;
    }

    public async System.Threading.Tasks.Task<DVSSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<DVSSummary>("summary");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyUuid()
    {
        var obj = await this.GetProperty<string>("uuid");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> AddDVPortgroup_Task(DVPortgroupConfigSpec[] spec)
    {
        var res = await this.Session.VimClient.AddDVPortgroup_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task AddNetworkResourcePool(DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        await this.Session.VimClient.AddNetworkResourcePool(this.VimReference, configSpec);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDVPortgroup_Task(DVPortgroupConfigSpec spec)
    {
        var res = await this.Session.VimClient.CreateDVPortgroup_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DvsReconfigureVmVnicNetworkResourcePool_Task(DvsVmVnicResourcePoolConfigSpec[] configSpec)
    {
        var res = await this.Session.VimClient.DvsReconfigureVmVnicNetworkResourcePool_Task(this.VimReference, configSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DVSRollback_Task(EntityBackupConfig? entityBackup)
    {
        var res = await this.Session.VimClient.DVSRollback_Task(this.VimReference, entityBackup);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task EnableNetworkResourceManagement(bool enable)
    {
        await this.Session.VimClient.EnableNetworkResourceManagement(this.VimReference, enable);
    }

    public async System.Threading.Tasks.Task<string[]?> FetchDVPortKeys(DistributedVirtualSwitchPortCriteria? criteria)
    {
        return await this.Session.VimClient.FetchDVPortKeys(this.VimReference, criteria);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPort[]?> FetchDVPorts(DistributedVirtualSwitchPortCriteria? criteria)
    {
        return await this.Session.VimClient.FetchDVPorts(this.VimReference, criteria);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup?> LookupDvPortGroup(string portgroupKey)
    {
        var res = await this.Session.VimClient.LookupDvPortGroup(this.VimReference, portgroupKey);
        return ManagedObject.Create<DistributedVirtualPortgroup>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MergeDvs_Task(DistributedVirtualSwitch dvs)
    {
        var res = await this.Session.VimClient.MergeDvs_Task(this.VimReference, dvs.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveDVPort_Task(string[] portKey, string? destinationPortgroupKey)
    {
        var res = await this.Session.VimClient.MoveDVPort_Task(this.VimReference, portKey, destinationPortgroupKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PerformDvsProductSpecOperation_Task(string operation, DistributedVirtualSwitchProductSpec? productSpec)
    {
        var res = await this.Session.VimClient.PerformDvsProductSpecOperation_Task(this.VimReference, operation, productSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int[]?> QueryUsedVlanIdInDvs()
    {
        return await this.Session.VimClient.QueryUsedVlanIdInDvs(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDVPort_Task(DVPortConfigSpec[] port)
    {
        var res = await this.Session.VimClient.ReconfigureDVPort_Task(this.VimReference, port);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDvs_Task(DVSConfigSpec spec)
    {
        var res = await this.Session.VimClient.ReconfigureDvs_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RectifyDvsHost_Task(HostSystem[]? hosts)
    {
        var res = await this.Session.VimClient.RectifyDvsHost_Task(this.VimReference, hosts?.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshDVPortState(string[]? portKeys)
    {
        await this.Session.VimClient.RefreshDVPortState(this.VimReference, portKeys);
    }

    public async System.Threading.Tasks.Task RemoveNetworkResourcePool(string[] key)
    {
        await this.Session.VimClient.RemoveNetworkResourcePool(this.VimReference, key);
    }

    public async System.Threading.Tasks.Task UpdateDvsCapability(DVSCapability capability)
    {
        await this.Session.VimClient.UpdateDvsCapability(this.VimReference, capability);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateDVSHealthCheckConfig_Task(DVSHealthCheckConfig[] healthCheckConfig)
    {
        var res = await this.Session.VimClient.UpdateDVSHealthCheckConfig_Task(this.VimReference, healthCheckConfig);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateNetworkResourcePool(DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        await this.Session.VimClient.UpdateNetworkResourcePool(this.VimReference, configSpec);
    }
}

public partial class DistributedVirtualSwitchManager : ManagedObject
{
    protected DistributedVirtualSwitchManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> DVSManagerExportEntity_Task(SelectionSet[] selectionSet)
    {
        var res = await this.Session.VimClient.DVSManagerExportEntity_Task(this.VimReference, selectionSet);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DVSManagerImportEntity_Task(EntityBackupConfig[] entityBackup, string importType)
    {
        var res = await this.Session.VimClient.DVSManagerImportEntity_Task(this.VimReference, entityBackup, importType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup?> DVSManagerLookupDvPortGroup(string switchUuid, string portgroupKey)
    {
        var res = await this.Session.VimClient.DVSManagerLookupDvPortGroup(this.VimReference, switchUuid, portgroupKey);
        return ManagedObject.Create<DistributedVirtualPortgroup>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchProductSpec[]?> QueryAvailableDvsSpec(bool? recommended)
    {
        return await this.Session.VimClient.QueryAvailableDvsSpec(this.VimReference, recommended ?? default, recommended.HasValue);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryCompatibleHostForExistingDvs(ManagedEntity container, bool recursive, DistributedVirtualSwitch dvs)
    {
        var res = await this.Session.VimClient.QueryCompatibleHostForExistingDvs(this.VimReference, container.VimReference, recursive, dvs.VimReference);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryCompatibleHostForNewDvs(ManagedEntity container, bool recursive, DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        var res = await this.Session.VimClient.QueryCompatibleHostForNewDvs(this.VimReference, container.VimReference, recursive, switchProductSpec);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<DVSManagerPhysicalNicsList[]?> QueryCompatibleVmnicsFromHosts(HostSystem[]? hosts, DistributedVirtualSwitch dvs)
    {
        return await this.Session.VimClient.QueryCompatibleVmnicsFromHosts(this.VimReference, hosts?.Select(m => m.VimReference).ToArray(), dvs.VimReference);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitch?> QueryDvsByUuid(string uuid)
    {
        var res = await this.Session.VimClient.QueryDvsByUuid(this.VimReference, uuid);
        return ManagedObject.Create<DistributedVirtualSwitch>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchManagerCompatibilityResult[]?> QueryDvsCheckCompatibility(DistributedVirtualSwitchManagerHostContainer hostContainer, DistributedVirtualSwitchManagerDvsProductSpec? dvsProductSpec, DistributedVirtualSwitchManagerHostDvsFilterSpec[]? hostFilterSpec)
    {
        return await this.Session.VimClient.QueryDvsCheckCompatibility(this.VimReference, hostContainer, dvsProductSpec, hostFilterSpec);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchHostProductSpec[]?> QueryDvsCompatibleHostSpec(DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        return await this.Session.VimClient.QueryDvsCompatibleHostSpec(this.VimReference, switchProductSpec);
    }

    public async System.Threading.Tasks.Task<DVSManagerDvsConfigTarget?> QueryDvsConfigTarget(HostSystem? host, DistributedVirtualSwitch? dvs)
    {
        return await this.Session.VimClient.QueryDvsConfigTarget(this.VimReference, host?.VimReference, dvs?.VimReference);
    }

    public async System.Threading.Tasks.Task<DVSFeatureCapability?> QueryDvsFeatureCapability(DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        return await this.Session.VimClient.QueryDvsFeatureCapability(this.VimReference, switchProductSpec);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchNetworkOffloadSpec[]?> QuerySupportedNetworkOffloadSpec(DistributedVirtualSwitchProductSpec switchProductSpec)
    {
        return await this.Session.VimClient.QuerySupportedNetworkOffloadSpec(this.VimReference, switchProductSpec);
    }

    public async System.Threading.Tasks.Task<Task?> RectifyDvsOnHost_Task(HostSystem[] hosts)
    {
        var res = await this.Session.VimClient.RectifyDvsOnHost_Task(this.VimReference, hosts.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class EnvironmentBrowser : ManagedObject
{
    protected EnvironmentBrowser(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostDatastoreBrowser?> GetPropertyDatastoreBrowser()
    {
        var datastoreBrowser = await this.GetProperty<ManagedObjectReference>("datastoreBrowser");
        return ManagedObject.Create<HostDatastoreBrowser>(datastoreBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOption(string? key, HostSystem? host)
    {
        return await this.Session.VimClient.QueryConfigOption(this.VimReference, key, host?.VimReference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryConfigOptionDescriptor()
    {
        return await this.Session.VimClient.QueryConfigOptionDescriptor(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOptionEx(EnvironmentBrowserConfigOptionQuerySpec? spec)
    {
        return await this.Session.VimClient.QueryConfigOptionEx(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task<ConfigTarget?> QueryConfigTarget(HostSystem? host)
    {
        return await this.Session.VimClient.QueryConfigTarget(this.VimReference, host?.VimReference);
    }

    public async System.Threading.Tasks.Task<HostCapability?> QueryTargetCapabilities(HostSystem? host)
    {
        return await this.Session.VimClient.QueryTargetCapabilities(this.VimReference, host?.VimReference);
    }
}

public partial class EventHistoryCollector : HistoryCollector
{
    protected EventHistoryCollector(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Event[]?> GetPropertyLatestPage()
    {
        var obj = await this.GetProperty<Event[]>("latestPage");
        return obj;
    }

    public async System.Threading.Tasks.Task<Event[]?> ReadNextEvents(int maxCount)
    {
        return await this.Session.VimClient.ReadNextEvents(this.VimReference, maxCount);
    }

    public async System.Threading.Tasks.Task<Event[]?> ReadPreviousEvents(int maxCount)
    {
        return await this.Session.VimClient.ReadPreviousEvents(this.VimReference, maxCount);
    }
}

public partial class EventManager : ManagedObject
{
    protected EventManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<EventDescription> GetPropertyDescription()
    {
        var obj = await this.GetProperty<EventDescription>("description");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Event?> GetPropertyLatestEvent()
    {
        var obj = await this.GetProperty<Event>("latestEvent");
        return obj;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyMaxCollector()
    {
        var obj = await this.GetProperty<int>("maxCollector");
        return obj!;
    }

    public async System.Threading.Tasks.Task<EventHistoryCollector?> CreateCollectorForEvents(EventFilterSpec filter)
    {
        var res = await this.Session.VimClient.CreateCollectorForEvents(this.VimReference, filter);
        return ManagedObject.Create<EventHistoryCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task LogUserEvent(ManagedEntity entity, string msg)
    {
        await this.Session.VimClient.LogUserEvent(this.VimReference, entity.VimReference, msg);
    }

    public async System.Threading.Tasks.Task PostEvent(Event eventToPost, TaskInfo? taskInfo)
    {
        await this.Session.VimClient.PostEvent(this.VimReference, eventToPost, taskInfo);
    }

    public async System.Threading.Tasks.Task<Event[]?> QueryEvents(EventFilterSpec filter)
    {
        return await this.Session.VimClient.QueryEvents(this.VimReference, filter);
    }

    public async System.Threading.Tasks.Task<EventArgDesc[]?> RetrieveArgumentDescription(string eventTypeId)
    {
        return await this.Session.VimClient.RetrieveArgumentDescription(this.VimReference, eventTypeId);
    }
}

public partial class ExtensibleManagedObject : ManagedObject
{
    protected ExtensibleManagedObject(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<CustomFieldDef[]?> GetPropertyAvailableField()
    {
        var obj = await this.GetProperty<CustomFieldDef[]>("availableField");
        return obj;
    }

    public async System.Threading.Tasks.Task<CustomFieldValue[]?> GetPropertyValue()
    {
        var obj = await this.GetProperty<CustomFieldValue[]>("value");
        return obj;
    }

    public async System.Threading.Tasks.Task SetCustomValue(string key, string value)
    {
        await this.Session.VimClient.SetCustomValue(this.VimReference, key, value);
    }
}

public partial class ExtensionManager : ManagedObject
{
    protected ExtensionManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Extension[]?> GetPropertyExtensionList()
    {
        var obj = await this.GetProperty<Extension[]>("extensionList");
        return obj;
    }

    public async System.Threading.Tasks.Task<Extension?> FindExtension(string extensionKey)
    {
        return await this.Session.VimClient.FindExtension(this.VimReference, extensionKey);
    }

    public async System.Threading.Tasks.Task<string?> GetPublicKey()
    {
        return await this.Session.VimClient.GetPublicKey(this.VimReference);
    }

    public async System.Threading.Tasks.Task<ExtensionManagerIpAllocationUsage[]?> QueryExtensionIpAllocationUsage(string[]? extensionKeys)
    {
        return await this.Session.VimClient.QueryExtensionIpAllocationUsage(this.VimReference, extensionKeys);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> QueryManagedBy(string extensionKey)
    {
        var res = await this.Session.VimClient.QueryManagedBy(this.VimReference, extensionKey);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task RegisterExtension(Extension extension)
    {
        await this.Session.VimClient.RegisterExtension(this.VimReference, extension);
    }

    public async System.Threading.Tasks.Task SetExtensionCertificate(string extensionKey, string? certificatePem)
    {
        await this.Session.VimClient.SetExtensionCertificate(this.VimReference, extensionKey, certificatePem);
    }

    public async System.Threading.Tasks.Task SetPublicKey(string extensionKey, string publicKey)
    {
        await this.Session.VimClient.SetPublicKey(this.VimReference, extensionKey, publicKey);
    }

    public async System.Threading.Tasks.Task UnregisterExtension(string extensionKey)
    {
        await this.Session.VimClient.UnregisterExtension(this.VimReference, extensionKey);
    }

    public async System.Threading.Tasks.Task UpdateExtension(Extension extension)
    {
        await this.Session.VimClient.UpdateExtension(this.VimReference, extension);
    }
}

public partial class FailoverClusterConfigurator : ManagedObject
{
    protected FailoverClusterConfigurator(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyDisabledConfigureMethod()
    {
        var obj = await this.GetProperty<string[]>("disabledConfigureMethod");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureVcha_Task(VchaClusterConfigSpec configSpec)
    {
        var res = await this.Session.VimClient.ConfigureVcha_Task(this.VimReference, configSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreatePassiveNode_Task(PassiveNodeDeploymentSpec passiveDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var res = await this.Session.VimClient.CreatePassiveNode_Task(this.VimReference, passiveDeploymentSpec, sourceVcSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateWitnessNode_Task(NodeDeploymentSpec witnessDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var res = await this.Session.VimClient.CreateWitnessNode_Task(this.VimReference, witnessDeploymentSpec, sourceVcSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeployVcha_Task(VchaClusterDeploymentSpec deploymentSpec)
    {
        var res = await this.Session.VimClient.DeployVcha_Task(this.VimReference, deploymentSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DestroyVcha_Task()
    {
        var res = await this.Session.VimClient.DestroyVcha_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VchaClusterConfigInfo?> GetVchaConfig()
    {
        return await this.Session.VimClient.GetVchaConfig(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> PrepareVcha_Task(VchaClusterNetworkSpec networkSpec)
    {
        var res = await this.Session.VimClient.PrepareVcha_Task(this.VimReference, networkSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class FailoverClusterManager : ManagedObject
{
    protected FailoverClusterManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyDisabledClusterMethod()
    {
        var obj = await this.GetProperty<string[]>("disabledClusterMethod");
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GetClusterMode()
    {
        return await this.Session.VimClient.GetClusterMode(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VchaClusterHealth?> GetVchaClusterHealth()
    {
        return await this.Session.VimClient.GetVchaClusterHealth(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> InitiateFailover_Task(bool planned)
    {
        var res = await this.Session.VimClient.InitiateFailover_Task(this.VimReference, planned);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SetClusterMode_Task(string mode)
    {
        var res = await this.Session.VimClient.SetClusterMode_Task(this.VimReference, mode);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class FileManager : ManagedObject
{
    protected FileManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task ChangeOwner(string name, Datacenter? datacenter, string owner)
    {
        await this.Session.VimClient.ChangeOwner(this.VimReference, name, datacenter?.VimReference, owner);
    }

    public async System.Threading.Tasks.Task<Task?> CopyDatastoreFile_Task(string sourceName, Datacenter? sourceDatacenter, string destinationName, Datacenter? destinationDatacenter, bool? force)
    {
        var res = await this.Session.VimClient.CopyDatastoreFile_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destinationName, destinationDatacenter?.VimReference, force ?? default, force.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteDatastoreFile_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.DeleteDatastoreFile_Task(this.VimReference, name, datacenter?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MakeDirectory(string name, Datacenter? datacenter, bool? createParentDirectories)
    {
        await this.Session.VimClient.MakeDirectory(this.VimReference, name, datacenter?.VimReference, createParentDirectories ?? default, createParentDirectories.HasValue);
    }

    public async System.Threading.Tasks.Task<Task?> MoveDatastoreFile_Task(string sourceName, Datacenter? sourceDatacenter, string destinationName, Datacenter? destinationDatacenter, bool? force)
    {
        var res = await this.Session.VimClient.MoveDatastoreFile_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destinationName, destinationDatacenter?.VimReference, force ?? default, force.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class Folder : ManagedEntity
{
    protected Folder(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> GetPropertyChildEntity()
    {
        var childEntity = await this.GetProperty<ManagedObjectReference[]>("childEntity");
        return childEntity?
            .Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyChildType()
    {
        var obj = await this.GetProperty<string[]>("childType");
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyNamespace()
    {
        var obj = await this.GetProperty<string>("namespace");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> AddStandaloneHost_Task(HostConnectSpec spec, ComputeResourceConfigSpec? compResSpec, bool addConnected, string? license)
    {
        var res = await this.Session.VimClient.AddStandaloneHost_Task(this.VimReference, spec, compResSpec, addConnected, license);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> BatchAddHostsToCluster_Task(ClusterComputeResource cluster, FolderNewHostSpec[]? newHosts, HostSystem[]? existingHosts, ComputeResourceConfigSpec? compResSpec, string? desiredState)
    {
        var res = await this.Session.VimClient.BatchAddHostsToCluster_Task(this.VimReference, cluster.VimReference, newHosts, existingHosts?.Select(m => m.VimReference).ToArray(), compResSpec, desiredState);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> BatchAddStandaloneHosts_Task(FolderNewHostSpec[]? newHosts, ComputeResourceConfigSpec? compResSpec, bool addConnected)
    {
        var res = await this.Session.VimClient.BatchAddStandaloneHosts_Task(this.VimReference, newHosts, compResSpec, addConnected);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource?> CreateCluster(string name, ClusterConfigSpec spec)
    {
        var res = await this.Session.VimClient.CreateCluster(this.VimReference, name, spec);
        return ManagedObject.Create<ClusterComputeResource>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource?> CreateClusterEx(string name, ClusterConfigSpecEx spec)
    {
        var res = await this.Session.VimClient.CreateClusterEx(this.VimReference, name, spec);
        return ManagedObject.Create<ClusterComputeResource>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datacenter?> CreateDatacenter(string name)
    {
        var res = await this.Session.VimClient.CreateDatacenter(this.VimReference, name);
        return ManagedObject.Create<Datacenter>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDVS_Task(DVSCreateSpec spec)
    {
        var res = await this.Session.VimClient.CreateDVS_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Folder?> CreateFolder(string name)
    {
        var res = await this.Session.VimClient.CreateFolder(this.VimReference, name);
        return ManagedObject.Create<Folder>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<StoragePod?> CreateStoragePod(string name)
    {
        var res = await this.Session.VimClient.CreateStoragePod(this.VimReference, name);
        return ManagedObject.Create<StoragePod>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateVM_Task(VirtualMachineConfigSpec config, ResourcePool pool, HostSystem? host)
    {
        var res = await this.Session.VimClient.CreateVM_Task(this.VimReference, config, pool.VimReference, host?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveIntoFolder_Task(ManagedEntity[] list)
    {
        var res = await this.Session.VimClient.MoveIntoFolder_Task(this.VimReference, list.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RegisterVM_Task(string path, string? name, bool asTemplate, ResourcePool? pool, HostSystem? host)
    {
        var res = await this.Session.VimClient.RegisterVM_Task(this.VimReference, path, name, asTemplate, pool?.VimReference, host?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnregisterAndDestroy_Task()
    {
        var res = await this.Session.VimClient.UnregisterAndDestroy_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class GuestAliasManager : ManagedObject
{
    protected GuestAliasManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task AddGuestAlias(VirtualMachine vm, GuestAuthentication auth, string username, bool mapCert, string base64Cert, GuestAuthAliasInfo aliasInfo)
    {
        await this.Session.VimClient.AddGuestAlias(this.VimReference, vm.VimReference, auth, username, mapCert, base64Cert, aliasInfo);
    }

    public async System.Threading.Tasks.Task<GuestAliases[]?> ListGuestAliases(VirtualMachine vm, GuestAuthentication auth, string username)
    {
        return await this.Session.VimClient.ListGuestAliases(this.VimReference, vm.VimReference, auth, username);
    }

    public async System.Threading.Tasks.Task<GuestMappedAliases[]?> ListGuestMappedAliases(VirtualMachine vm, GuestAuthentication auth)
    {
        return await this.Session.VimClient.ListGuestMappedAliases(this.VimReference, vm.VimReference, auth);
    }

    public async System.Threading.Tasks.Task RemoveGuestAlias(VirtualMachine vm, GuestAuthentication auth, string username, string base64Cert, GuestAuthSubject subject)
    {
        await this.Session.VimClient.RemoveGuestAlias(this.VimReference, vm.VimReference, auth, username, base64Cert, subject);
    }

    public async System.Threading.Tasks.Task RemoveGuestAliasByCert(VirtualMachine vm, GuestAuthentication auth, string username, string base64Cert)
    {
        await this.Session.VimClient.RemoveGuestAliasByCert(this.VimReference, vm.VimReference, auth, username, base64Cert);
    }
}

public partial class GuestAuthManager : ManagedObject
{
    protected GuestAuthManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<GuestAuthentication?> AcquireCredentialsInGuest(VirtualMachine vm, GuestAuthentication requestedAuth, long? sessionID)
    {
        return await this.Session.VimClient.AcquireCredentialsInGuest(this.VimReference, vm.VimReference, requestedAuth, sessionID ?? default, sessionID.HasValue);
    }

    public async System.Threading.Tasks.Task ReleaseCredentialsInGuest(VirtualMachine vm, GuestAuthentication auth)
    {
        await this.Session.VimClient.ReleaseCredentialsInGuest(this.VimReference, vm.VimReference, auth);
    }

    public async System.Threading.Tasks.Task ValidateCredentialsInGuest(VirtualMachine vm, GuestAuthentication auth)
    {
        await this.Session.VimClient.ValidateCredentialsInGuest(this.VimReference, vm.VimReference, auth);
    }
}

public partial class GuestFileManager : ManagedObject
{
    protected GuestFileManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task ChangeFileAttributesInGuest(VirtualMachine vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes)
    {
        await this.Session.VimClient.ChangeFileAttributesInGuest(this.VimReference, vm.VimReference, auth, guestFilePath, fileAttributes);
    }

    public async System.Threading.Tasks.Task<string?> CreateTemporaryDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath)
    {
        return await this.Session.VimClient.CreateTemporaryDirectoryInGuest(this.VimReference, vm.VimReference, auth, prefix, suffix, directoryPath);
    }

    public async System.Threading.Tasks.Task<string?> CreateTemporaryFileInGuest(VirtualMachine vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath)
    {
        return await this.Session.VimClient.CreateTemporaryFileInGuest(this.VimReference, vm.VimReference, auth, prefix, suffix, directoryPath);
    }

    public async System.Threading.Tasks.Task DeleteDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string directoryPath, bool recursive)
    {
        await this.Session.VimClient.DeleteDirectoryInGuest(this.VimReference, vm.VimReference, auth, directoryPath, recursive);
    }

    public async System.Threading.Tasks.Task DeleteFileInGuest(VirtualMachine vm, GuestAuthentication auth, string filePath)
    {
        await this.Session.VimClient.DeleteFileInGuest(this.VimReference, vm.VimReference, auth, filePath);
    }

    public async System.Threading.Tasks.Task<FileTransferInformation?> InitiateFileTransferFromGuest(VirtualMachine vm, GuestAuthentication auth, string guestFilePath)
    {
        return await this.Session.VimClient.InitiateFileTransferFromGuest(this.VimReference, vm.VimReference, auth, guestFilePath);
    }

    public async System.Threading.Tasks.Task<string?> InitiateFileTransferToGuest(VirtualMachine vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes, long fileSize, bool overwrite)
    {
        return await this.Session.VimClient.InitiateFileTransferToGuest(this.VimReference, vm.VimReference, auth, guestFilePath, fileAttributes, fileSize, overwrite);
    }

    public async System.Threading.Tasks.Task<GuestListFileInfo?> ListFilesInGuest(VirtualMachine vm, GuestAuthentication auth, string filePath, int? index, int? maxResults, string? matchPattern)
    {
        return await this.Session.VimClient.ListFilesInGuest(this.VimReference, vm.VimReference, auth, filePath, index ?? default, index.HasValue, maxResults ?? default, maxResults.HasValue, matchPattern);
    }

    public async System.Threading.Tasks.Task MakeDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string directoryPath, bool createParentDirectories)
    {
        await this.Session.VimClient.MakeDirectoryInGuest(this.VimReference, vm.VimReference, auth, directoryPath, createParentDirectories);
    }

    public async System.Threading.Tasks.Task MoveDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string srcDirectoryPath, string dstDirectoryPath)
    {
        await this.Session.VimClient.MoveDirectoryInGuest(this.VimReference, vm.VimReference, auth, srcDirectoryPath, dstDirectoryPath);
    }

    public async System.Threading.Tasks.Task MoveFileInGuest(VirtualMachine vm, GuestAuthentication auth, string srcFilePath, string dstFilePath, bool overwrite)
    {
        await this.Session.VimClient.MoveFileInGuest(this.VimReference, vm.VimReference, auth, srcFilePath, dstFilePath, overwrite);
    }
}

public partial class GuestOperationsManager : ManagedObject
{
    protected GuestOperationsManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<GuestAliasManager?> GetPropertyAliasManager()
    {
        var aliasManager = await this.GetProperty<ManagedObjectReference>("aliasManager");
        return ManagedObject.Create<GuestAliasManager>(aliasManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestAuthManager?> GetPropertyAuthManager()
    {
        var authManager = await this.GetProperty<ManagedObjectReference>("authManager");
        return ManagedObject.Create<GuestAuthManager>(authManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestFileManager?> GetPropertyFileManager()
    {
        var fileManager = await this.GetProperty<ManagedObjectReference>("fileManager");
        return ManagedObject.Create<GuestFileManager>(fileManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestWindowsRegistryManager?> GetPropertyGuestWindowsRegistryManager()
    {
        var guestWindowsRegistryManager = await this.GetProperty<ManagedObjectReference>("guestWindowsRegistryManager");
        return ManagedObject.Create<GuestWindowsRegistryManager>(guestWindowsRegistryManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestProcessManager?> GetPropertyProcessManager()
    {
        var processManager = await this.GetProperty<ManagedObjectReference>("processManager");
        return ManagedObject.Create<GuestProcessManager>(processManager, this.Session);
    }
}

public partial class GuestProcessManager : ManagedObject
{
    protected GuestProcessManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<GuestProcessInfo[]?> ListProcessesInGuest(VirtualMachine vm, GuestAuthentication auth, long[]? pids)
    {
        return await this.Session.VimClient.ListProcessesInGuest(this.VimReference, vm.VimReference, auth, pids);
    }

    public async System.Threading.Tasks.Task<string[]?> ReadEnvironmentVariableInGuest(VirtualMachine vm, GuestAuthentication auth, string[]? names)
    {
        return await this.Session.VimClient.ReadEnvironmentVariableInGuest(this.VimReference, vm.VimReference, auth, names);
    }

    public async System.Threading.Tasks.Task<long> StartProgramInGuest(VirtualMachine vm, GuestAuthentication auth, GuestProgramSpec spec)
    {
        return await this.Session.VimClient.StartProgramInGuest(this.VimReference, vm.VimReference, auth, spec);
    }

    public async System.Threading.Tasks.Task TerminateProcessInGuest(VirtualMachine vm, GuestAuthentication auth, long pid)
    {
        await this.Session.VimClient.TerminateProcessInGuest(this.VimReference, vm.VimReference, auth, pid);
    }
}

public partial class GuestWindowsRegistryManager : ManagedObject
{
    protected GuestWindowsRegistryManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task CreateRegistryKeyInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool isVolatile, string? classType)
    {
        await this.Session.VimClient.CreateRegistryKeyInGuest(this.VimReference, vm.VimReference, auth, keyName, isVolatile, classType);
    }

    public async System.Threading.Tasks.Task DeleteRegistryKeyInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive)
    {
        await this.Session.VimClient.DeleteRegistryKeyInGuest(this.VimReference, vm.VimReference, auth, keyName, recursive);
    }

    public async System.Threading.Tasks.Task DeleteRegistryValueInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegValueNameSpec valueName)
    {
        await this.Session.VimClient.DeleteRegistryValueInGuest(this.VimReference, vm.VimReference, auth, valueName);
    }

    public async System.Threading.Tasks.Task<GuestRegKeyRecordSpec[]?> ListRegistryKeysInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive, string? matchPattern)
    {
        return await this.Session.VimClient.ListRegistryKeysInGuest(this.VimReference, vm.VimReference, auth, keyName, recursive, matchPattern);
    }

    public async System.Threading.Tasks.Task<GuestRegValueSpec[]?> ListRegistryValuesInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool expandStrings, string? matchPattern)
    {
        return await this.Session.VimClient.ListRegistryValuesInGuest(this.VimReference, vm.VimReference, auth, keyName, expandStrings, matchPattern);
    }

    public async System.Threading.Tasks.Task SetRegistryValueInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegValueSpec value)
    {
        await this.Session.VimClient.SetRegistryValueInGuest(this.VimReference, vm.VimReference, auth, value);
    }
}

public partial class HealthUpdateManager : ManagedObject
{
    protected HealthUpdateManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string?> AddFilter(string providerId, string filterName, string[]? infoIds)
    {
        return await this.Session.VimClient.AddFilter(this.VimReference, providerId, filterName, infoIds);
    }

    public async System.Threading.Tasks.Task AddFilterEntities(string filterId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.AddFilterEntities(this.VimReference, filterId, entities?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task AddMonitoredEntities(string providerId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.AddMonitoredEntities(this.VimReference, providerId, entities?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<bool> HasMonitoredEntity(string providerId, ManagedEntity entity)
    {
        return await this.Session.VimClient.HasMonitoredEntity(this.VimReference, providerId, entity.VimReference);
    }

    public async System.Threading.Tasks.Task<bool> HasProvider(string id)
    {
        return await this.Session.VimClient.HasProvider(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task PostHealthUpdates(string providerId, HealthUpdate[]? updates)
    {
        await this.Session.VimClient.PostHealthUpdates(this.VimReference, providerId, updates);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> QueryFilterEntities(string filterId)
    {
        var res = await this.Session.VimClient.QueryFilterEntities(this.VimReference, filterId);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string[]?> QueryFilterInfoIds(string filterId)
    {
        return await this.Session.VimClient.QueryFilterInfoIds(this.VimReference, filterId);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryFilterList(string providerId)
    {
        return await this.Session.VimClient.QueryFilterList(this.VimReference, providerId);
    }

    public async System.Threading.Tasks.Task<string?> QueryFilterName(string filterId)
    {
        return await this.Session.VimClient.QueryFilterName(this.VimReference, filterId);
    }

    public async System.Threading.Tasks.Task<HealthUpdateInfo[]?> QueryHealthUpdateInfos(string providerId)
    {
        return await this.Session.VimClient.QueryHealthUpdateInfos(this.VimReference, providerId);
    }

    public async System.Threading.Tasks.Task<HealthUpdate[]?> QueryHealthUpdates(string providerId)
    {
        return await this.Session.VimClient.QueryHealthUpdates(this.VimReference, providerId);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> QueryMonitoredEntities(string providerId)
    {
        var res = await this.Session.VimClient.QueryMonitoredEntities(this.VimReference, providerId);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string[]?> QueryProviderList()
    {
        return await this.Session.VimClient.QueryProviderList(this.VimReference);
    }

    public async System.Threading.Tasks.Task<string?> QueryProviderName(string id)
    {
        return await this.Session.VimClient.QueryProviderName(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryUnmonitoredHosts(string providerId, ClusterComputeResource cluster)
    {
        var res = await this.Session.VimClient.QueryUnmonitoredHosts(this.VimReference, providerId, cluster.VimReference);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string?> RegisterHealthUpdateProvider(string name, HealthUpdateInfo[]? healthUpdateInfo)
    {
        return await this.Session.VimClient.RegisterHealthUpdateProvider(this.VimReference, name, healthUpdateInfo);
    }

    public async System.Threading.Tasks.Task RemoveFilter(string filterId)
    {
        await this.Session.VimClient.RemoveFilter(this.VimReference, filterId);
    }

    public async System.Threading.Tasks.Task RemoveFilterEntities(string filterId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.RemoveFilterEntities(this.VimReference, filterId, entities?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task RemoveMonitoredEntities(string providerId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.RemoveMonitoredEntities(this.VimReference, providerId, entities?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task UnregisterHealthUpdateProvider(string providerId)
    {
        await this.Session.VimClient.UnregisterHealthUpdateProvider(this.VimReference, providerId);
    }
}

public partial class HistoryCollector : ManagedObject
{
    protected HistoryCollector(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<object> GetPropertyFilter()
    {
        var obj = await this.GetProperty<object>("filter");
        return obj!;
    }

    public async System.Threading.Tasks.Task DestroyCollector()
    {
        await this.Session.VimClient.DestroyCollector(this.VimReference);
    }

    public async System.Threading.Tasks.Task ResetCollector()
    {
        await this.Session.VimClient.ResetCollector(this.VimReference);
    }

    public async System.Threading.Tasks.Task RewindCollector()
    {
        await this.Session.VimClient.RewindCollector(this.VimReference);
    }

    public async System.Threading.Tasks.Task SetCollectorPageSize(int maxCount)
    {
        await this.Session.VimClient.SetCollectorPageSize(this.VimReference, maxCount);
    }
}

public partial class HostAccessManager : ManagedObject
{
    protected HostAccessManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostLockdownMode> GetPropertyLockdownMode()
    {
        var obj = await this.GetProperty<HostLockdownMode>("lockdownMode");
        return obj!;
    }

    public async System.Threading.Tasks.Task ChangeAccessMode(string principal, bool isGroup, HostAccessMode accessMode)
    {
        await this.Session.VimClient.ChangeAccessMode(this.VimReference, principal, isGroup, accessMode);
    }

    public async System.Threading.Tasks.Task ChangeLockdownMode(HostLockdownMode mode)
    {
        await this.Session.VimClient.ChangeLockdownMode(this.VimReference, mode);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryLockdownExceptions()
    {
        return await this.Session.VimClient.QueryLockdownExceptions(this.VimReference);
    }

    public async System.Threading.Tasks.Task<string[]?> QuerySystemUsers()
    {
        return await this.Session.VimClient.QuerySystemUsers(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostAccessControlEntry[]?> RetrieveHostAccessControlEntries()
    {
        return await this.Session.VimClient.RetrieveHostAccessControlEntries(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateLockdownExceptions(string[]? users)
    {
        await this.Session.VimClient.UpdateLockdownExceptions(this.VimReference, users);
    }

    public async System.Threading.Tasks.Task UpdateSystemUsers(string[]? users)
    {
        await this.Session.VimClient.UpdateSystemUsers(this.VimReference, users);
    }
}

public partial class HostActiveDirectoryAuthentication : HostDirectoryStore
{
    protected HostActiveDirectoryAuthentication(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task DisableSmartCardAuthentication()
    {
        await this.Session.VimClient.DisableSmartCardAuthentication(this.VimReference);
    }

    public async System.Threading.Tasks.Task EnableSmartCardAuthentication()
    {
        await this.Session.VimClient.EnableSmartCardAuthentication(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ImportCertificateForCAM_Task(string certPath, string camServer)
    {
        var res = await this.Session.VimClient.ImportCertificateForCAM_Task(this.VimReference, certPath, camServer);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task InstallSmartCardTrustAnchor(string cert)
    {
        await this.Session.VimClient.InstallSmartCardTrustAnchor(this.VimReference, cert);
    }

    public async System.Threading.Tasks.Task<Task?> JoinDomain_Task(string domainName, string userName, string password)
    {
        var res = await this.Session.VimClient.JoinDomain_Task(this.VimReference, domainName, userName, password);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> JoinDomainWithCAM_Task(string domainName, string camServer)
    {
        var res = await this.Session.VimClient.JoinDomainWithCAM_Task(this.VimReference, domainName, camServer);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> LeaveCurrentDomain_Task(bool force)
    {
        var res = await this.Session.VimClient.LeaveCurrentDomain_Task(this.VimReference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string[]?> ListSmartCardTrustAnchors()
    {
        return await this.Session.VimClient.ListSmartCardTrustAnchors(this.VimReference);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchor(string issuer, string serial)
    {
        await this.Session.VimClient.RemoveSmartCardTrustAnchor(this.VimReference, issuer, serial);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchorByFingerprint(string fingerprint, string digest)
    {
        await this.Session.VimClient.RemoveSmartCardTrustAnchorByFingerprint(this.VimReference, fingerprint, digest);
    }

    public async System.Threading.Tasks.Task ReplaceSmartCardTrustAnchors(string[]? certs)
    {
        await this.Session.VimClient.ReplaceSmartCardTrustAnchors(this.VimReference, certs);
    }
}

public partial class HostAssignableHardwareManager : ManagedObject
{
    protected HostAssignableHardwareManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostAssignableHardwareBinding[]?> GetPropertyBinding()
    {
        var obj = await this.GetProperty<HostAssignableHardwareBinding[]>("binding");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostAssignableHardwareConfig> GetPropertyConfig()
    {
        var obj = await this.GetProperty<HostAssignableHardwareConfig>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<byte[]?> DownloadDescriptionTree()
    {
        return await this.Session.VimClient.DownloadDescriptionTree(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineDynamicPassthroughInfo[]?> RetrieveDynamicPassthroughInfo()
    {
        return await this.Session.VimClient.RetrieveDynamicPassthroughInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVendorDeviceGroupInfo[]?> RetrieveVendorDeviceGroupInfo()
    {
        return await this.Session.VimClient.RetrieveVendorDeviceGroupInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateAssignableHardwareConfig(HostAssignableHardwareConfig config)
    {
        await this.Session.VimClient.UpdateAssignableHardwareConfig(this.VimReference, config);
    }
}

public partial class HostAuthenticationManager : ManagedObject
{
    protected HostAuthenticationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostAuthenticationManagerInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<HostAuthenticationManagerInfo>("info");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostAuthenticationStore[]> GetPropertySupportedStore()
    {
        var supportedStore = await this.GetProperty<ManagedObjectReference[]>("supportedStore");
        return supportedStore!
            .Select(r => ManagedObject.Create<HostAuthenticationStore>(r, this.Session)!)
            .ToArray();
    }
}

public partial class HostAuthenticationStore : ManagedObject
{
    protected HostAuthenticationStore(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostAuthenticationStoreInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<HostAuthenticationStoreInfo>("info");
        return obj!;
    }
}

public partial class HostAutoStartManager : ManagedObject
{
    protected HostAutoStartManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostAutoStartManagerConfig> GetPropertyConfig()
    {
        var obj = await this.GetProperty<HostAutoStartManagerConfig>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task AutoStartPowerOff()
    {
        await this.Session.VimClient.AutoStartPowerOff(this.VimReference);
    }

    public async System.Threading.Tasks.Task AutoStartPowerOn()
    {
        await this.Session.VimClient.AutoStartPowerOn(this.VimReference);
    }

    public async System.Threading.Tasks.Task ReconfigureAutostart(HostAutoStartManagerConfig spec)
    {
        await this.Session.VimClient.ReconfigureAutostart(this.VimReference, spec);
    }
}

public partial class HostBootDeviceSystem : ManagedObject
{
    protected HostBootDeviceSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostBootDeviceInfo?> QueryBootDevices()
    {
        return await this.Session.VimClient.QueryBootDevices(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateBootDevice(string key)
    {
        await this.Session.VimClient.UpdateBootDevice(this.VimReference, key);
    }
}

public partial class HostCacheConfigurationManager : ManagedObject
{
    protected HostCacheConfigurationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostCacheConfigurationInfo[]?> GetPropertyCacheConfigurationInfo()
    {
        var obj = await this.GetProperty<HostCacheConfigurationInfo[]>("cacheConfigurationInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureHostCache_Task(HostCacheConfigurationSpec spec)
    {
        var res = await this.Session.VimClient.ConfigureHostCache_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class HostCertificateManager : ManagedObject
{
    protected HostCertificateManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostCertificateManagerCertificateInfo> GetPropertyCertificateInfo()
    {
        var obj = await this.GetProperty<HostCertificateManagerCertificateInfo>("certificateInfo");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequest(bool useIpAddressAsCommonName)
    {
        return await this.Session.VimClient.GenerateCertificateSigningRequest(this.VimReference, useIpAddressAsCommonName);
    }

    public async System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequestByDn(string distinguishedName)
    {
        return await this.Session.VimClient.GenerateCertificateSigningRequestByDn(this.VimReference, distinguishedName);
    }

    public async System.Threading.Tasks.Task InstallServerCertificate(string cert)
    {
        await this.Session.VimClient.InstallServerCertificate(this.VimReference, cert);
    }

    public async System.Threading.Tasks.Task<string[]?> ListCACertificateRevocationLists()
    {
        return await this.Session.VimClient.ListCACertificateRevocationLists(this.VimReference);
    }

    public async System.Threading.Tasks.Task<string[]?> ListCACertificates()
    {
        return await this.Session.VimClient.ListCACertificates(this.VimReference);
    }

    public async System.Threading.Tasks.Task ReplaceCACertificatesAndCRLs(string[] caCert, string[]? caCrl)
    {
        await this.Session.VimClient.ReplaceCACertificatesAndCRLs(this.VimReference, caCert, caCrl);
    }
}

public partial class HostCpuSchedulerSystem : ExtensibleManagedObject
{
    protected HostCpuSchedulerSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostHyperThreadScheduleInfo?> GetPropertyHyperthreadInfo()
    {
        var obj = await this.GetProperty<HostHyperThreadScheduleInfo>("hyperthreadInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task DisableHyperThreading()
    {
        await this.Session.VimClient.DisableHyperThreading(this.VimReference);
    }

    public async System.Threading.Tasks.Task EnableHyperThreading()
    {
        await this.Session.VimClient.EnableHyperThreading(this.VimReference);
    }
}

public partial class HostDatastoreBrowser : ManagedObject
{
    protected HostDatastoreBrowser(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore?
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<FileQuery[]?> GetPropertySupportedType()
    {
        var obj = await this.GetProperty<FileQuery[]>("supportedType");
        return obj;
    }

    public async System.Threading.Tasks.Task DeleteFile(string datastorePath)
    {
        await this.Session.VimClient.DeleteFile(this.VimReference, datastorePath);
    }

    public async System.Threading.Tasks.Task<Task?> SearchDatastore_Task(string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec)
    {
        var res = await this.Session.VimClient.SearchDatastore_Task(this.VimReference, datastorePath, searchSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SearchDatastoreSubFolders_Task(string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec)
    {
        var res = await this.Session.VimClient.SearchDatastoreSubFolders_Task(this.VimReference, datastorePath, searchSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class HostDatastoreSystem : ManagedObject
{
    protected HostDatastoreSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostDatastoreSystemCapabilities> GetPropertyCapabilities()
    {
        var obj = await this.GetProperty<HostDatastoreSystemCapabilities>("capabilities");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore?
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task ConfigureDatastorePrincipal(string userName, string? password)
    {
        await this.Session.VimClient.ConfigureDatastorePrincipal(this.VimReference, userName, password);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateLocalDatastore(string name, string path)
    {
        var res = await this.Session.VimClient.CreateLocalDatastore(this.VimReference, name, path);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateNasDatastore(HostNasVolumeSpec spec)
    {
        var res = await this.Session.VimClient.CreateNasDatastore(this.VimReference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateVmfsDatastore(VmfsDatastoreCreateSpec spec)
    {
        var res = await this.Session.VimClient.CreateVmfsDatastore(this.VimReference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateVvolDatastore(HostDatastoreSystemVvolDatastoreSpec spec)
    {
        var res = await this.Session.VimClient.CreateVvolDatastore(this.VimReference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableClusteredVmdkSupport(Datastore datastore)
    {
        await this.Session.VimClient.DisableClusteredVmdkSupport(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task EnableClusteredVmdkSupport(Datastore datastore)
    {
        await this.Session.VimClient.EnableClusteredVmdkSupport(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<Datastore?> ExpandVmfsDatastore(Datastore datastore, VmfsDatastoreExpandSpec spec)
    {
        var res = await this.Session.VimClient.ExpandVmfsDatastore(this.VimReference, datastore.VimReference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> ExtendVmfsDatastore(Datastore datastore, VmfsDatastoreExtendSpec spec)
    {
        var res = await this.Session.VimClient.ExtendVmfsDatastore(this.VimReference, datastore.VimReference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableDisksForVmfs(Datastore? datastore)
    {
        return await this.Session.VimClient.QueryAvailableDisksForVmfs(this.VimReference, datastore?.VimReference);
    }

    public async System.Threading.Tasks.Task<long> QueryMaxQueueDepth(Datastore datastore)
    {
        return await this.Session.VimClient.QueryMaxQueueDepth(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolumes()
    {
        return await this.Session.VimClient.QueryUnresolvedVmfsVolumes(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreCreateOptions(string devicePath, int? vmfsMajorVersion)
    {
        return await this.Session.VimClient.QueryVmfsDatastoreCreateOptions(this.VimReference, devicePath, vmfsMajorVersion ?? default, vmfsMajorVersion.HasValue);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExpandOptions(Datastore datastore)
    {
        return await this.Session.VimClient.QueryVmfsDatastoreExpandOptions(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExtendOptions(Datastore datastore, string devicePath, bool? suppressExpandCandidates)
    {
        return await this.Session.VimClient.QueryVmfsDatastoreExtendOptions(this.VimReference, datastore.VimReference, devicePath, suppressExpandCandidates ?? default, suppressExpandCandidates.HasValue);
    }

    public async System.Threading.Tasks.Task RemoveDatastore(Datastore datastore)
    {
        await this.Session.VimClient.RemoveDatastore(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveDatastoreEx_Task(Datastore[] datastore)
    {
        var res = await this.Session.VimClient.RemoveDatastoreEx_Task(this.VimReference, datastore.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ResignatureUnresolvedVmfsVolume_Task(HostUnresolvedVmfsResignatureSpec resolutionSpec)
    {
        var res = await this.Session.VimClient.ResignatureUnresolvedVmfsVolume_Task(this.VimReference, resolutionSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task SetMaxQueueDepth(Datastore datastore, long maxQdepth)
    {
        await this.Session.VimClient.SetMaxQueueDepth(this.VimReference, datastore.VimReference, maxQdepth);
    }

    public async System.Threading.Tasks.Task UpdateLocalSwapDatastore(Datastore? datastore)
    {
        await this.Session.VimClient.UpdateLocalSwapDatastore(this.VimReference, datastore?.VimReference);
    }
}

public partial class HostDateTimeSystem : ManagedObject
{
    protected HostDateTimeSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostDateTimeInfo> GetPropertyDateTimeInfo()
    {
        var obj = await this.GetProperty<HostDateTimeInfo>("dateTimeInfo");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemTimeZone[]?> QueryAvailableTimeZones()
    {
        return await this.Session.VimClient.QueryAvailableTimeZones(this.VimReference);
    }

    public async System.Threading.Tasks.Task<DateTime> QueryDateTime()
    {
        return await this.Session.VimClient.QueryDateTime(this.VimReference);
    }

    public async System.Threading.Tasks.Task RefreshDateTimeSystem()
    {
        await this.Session.VimClient.RefreshDateTimeSystem(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemServiceTestResult?> TestTimeService()
    {
        return await this.Session.VimClient.TestTimeService(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateDateTime(DateTime dateTime)
    {
        await this.Session.VimClient.UpdateDateTime(this.VimReference, dateTime);
    }

    public async System.Threading.Tasks.Task UpdateDateTimeConfig(HostDateTimeConfig config)
    {
        await this.Session.VimClient.UpdateDateTimeConfig(this.VimReference, config);
    }
}

public partial class HostDiagnosticSystem : ManagedObject
{
    protected HostDiagnosticSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartition?> GetPropertyActivePartition()
    {
        var obj = await this.GetProperty<HostDiagnosticPartition>("activePartition");
        return obj;
    }

    public async System.Threading.Tasks.Task CreateDiagnosticPartition(HostDiagnosticPartitionCreateSpec spec)
    {
        await this.Session.VimClient.CreateDiagnosticPartition(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartition[]?> QueryAvailablePartition()
    {
        return await this.Session.VimClient.QueryAvailablePartition(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateDescription?> QueryPartitionCreateDesc(string diskUuid, string diagnosticType)
    {
        return await this.Session.VimClient.QueryPartitionCreateDesc(this.VimReference, diskUuid, diagnosticType);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateOption[]?> QueryPartitionCreateOptions(string storageType, string diagnosticType)
    {
        return await this.Session.VimClient.QueryPartitionCreateOptions(this.VimReference, storageType, diagnosticType);
    }

    public async System.Threading.Tasks.Task SelectActivePartition(HostScsiDiskPartition? partition)
    {
        await this.Session.VimClient.SelectActivePartition(this.VimReference, partition);
    }
}

public partial class HostDirectoryStore : HostAuthenticationStore
{
    protected HostDirectoryStore(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class HostEsxAgentHostManager : ManagedObject
{
    protected HostEsxAgentHostManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostEsxAgentHostManagerConfigInfo> GetPropertyConfigInfo()
    {
        var obj = await this.GetProperty<HostEsxAgentHostManagerConfigInfo>("configInfo");
        return obj!;
    }

    public async System.Threading.Tasks.Task EsxAgentHostManagerUpdateConfig(HostEsxAgentHostManagerConfigInfo configInfo)
    {
        await this.Session.VimClient.EsxAgentHostManagerUpdateConfig(this.VimReference, configInfo);
    }
}

public partial class HostFirewallSystem : ExtensibleManagedObject
{
    protected HostFirewallSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostFirewallInfo?> GetPropertyFirewallInfo()
    {
        var obj = await this.GetProperty<HostFirewallInfo>("firewallInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task DisableRuleset(string id)
    {
        await this.Session.VimClient.DisableRuleset(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task EnableRuleset(string id)
    {
        await this.Session.VimClient.EnableRuleset(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task RefreshFirewall()
    {
        await this.Session.VimClient.RefreshFirewall(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateDefaultPolicy(HostFirewallDefaultPolicy defaultPolicy)
    {
        await this.Session.VimClient.UpdateDefaultPolicy(this.VimReference, defaultPolicy);
    }

    public async System.Threading.Tasks.Task UpdateRuleset(string id, HostFirewallRulesetRulesetSpec spec)
    {
        await this.Session.VimClient.UpdateRuleset(this.VimReference, id, spec);
    }
}

public partial class HostFirmwareSystem : ManagedObject
{
    protected HostFirmwareSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string?> BackupFirmwareConfiguration()
    {
        return await this.Session.VimClient.BackupFirmwareConfiguration(this.VimReference);
    }

    public async System.Threading.Tasks.Task<string?> QueryFirmwareConfigUploadURL()
    {
        return await this.Session.VimClient.QueryFirmwareConfigUploadURL(this.VimReference);
    }

    public async System.Threading.Tasks.Task ResetFirmwareToFactoryDefaults()
    {
        await this.Session.VimClient.ResetFirmwareToFactoryDefaults(this.VimReference);
    }

    public async System.Threading.Tasks.Task RestoreFirmwareConfiguration(bool force)
    {
        await this.Session.VimClient.RestoreFirmwareConfiguration(this.VimReference, force);
    }
}

public partial class HostGraphicsManager : ExtensibleManagedObject
{
    protected HostGraphicsManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostGraphicsConfig?> GetPropertyGraphicsConfig()
    {
        var obj = await this.GetProperty<HostGraphicsConfig>("graphicsConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostGraphicsInfo[]?> GetPropertyGraphicsInfo()
    {
        var obj = await this.GetProperty<HostGraphicsInfo[]>("graphicsInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostSharedGpuCapabilities[]?> GetPropertySharedGpuCapabilities()
    {
        var obj = await this.GetProperty<HostSharedGpuCapabilities[]>("sharedGpuCapabilities");
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertySharedPassthruGpuTypes()
    {
        var obj = await this.GetProperty<string[]>("sharedPassthruGpuTypes");
        return obj;
    }

    public async System.Threading.Tasks.Task<bool> IsSharedGraphicsActive()
    {
        return await this.Session.VimClient.IsSharedGraphicsActive(this.VimReference);
    }

    public async System.Threading.Tasks.Task RefreshGraphicsManager()
    {
        await this.Session.VimClient.RefreshGraphicsManager(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuDeviceInfo[]?> RetrieveVgpuDeviceInfo()
    {
        return await this.Session.VimClient.RetrieveVgpuDeviceInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuProfileInfo[]?> RetrieveVgpuProfileInfo()
    {
        return await this.Session.VimClient.RetrieveVgpuProfileInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateGraphicsConfig(HostGraphicsConfig config)
    {
        await this.Session.VimClient.UpdateGraphicsConfig(this.VimReference, config);
    }
}

public partial class HostHealthStatusSystem : ManagedObject
{
    protected HostHealthStatusSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HealthSystemRuntime> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<HealthSystemRuntime>("runtime");
        return obj!;
    }

    public async System.Threading.Tasks.Task ClearSystemEventLog()
    {
        await this.Session.VimClient.ClearSystemEventLog(this.VimReference);
    }

    public async System.Threading.Tasks.Task<SystemEventInfo[]?> FetchSystemEventLog()
    {
        return await this.Session.VimClient.FetchSystemEventLog(this.VimReference);
    }

    public async System.Threading.Tasks.Task RefreshHealthStatusSystem()
    {
        await this.Session.VimClient.RefreshHealthStatusSystem(this.VimReference);
    }

    public async System.Threading.Tasks.Task ResetSystemHealthInfo()
    {
        await this.Session.VimClient.ResetSystemHealthInfo(this.VimReference);
    }
}

public partial class HostImageConfigManager : ManagedObject
{
    protected HostImageConfigManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<SoftwarePackage[]?> FetchSoftwarePackages()
    {
        return await this.Session.VimClient.FetchSoftwarePackages(this.VimReference);
    }

    public async System.Threading.Tasks.Task<string?> HostImageConfigGetAcceptance()
    {
        return await this.Session.VimClient.HostImageConfigGetAcceptance(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostImageProfileSummary?> HostImageConfigGetProfile()
    {
        return await this.Session.VimClient.HostImageConfigGetProfile(this.VimReference);
    }

    public async System.Threading.Tasks.Task<DateTime> InstallDate()
    {
        return await this.Session.VimClient.InstallDate(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateHostImageAcceptanceLevel(string newAcceptanceLevel)
    {
        await this.Session.VimClient.UpdateHostImageAcceptanceLevel(this.VimReference, newAcceptanceLevel);
    }
}

public partial class HostKernelModuleSystem : ManagedObject
{
    protected HostKernelModuleSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string?> QueryConfiguredModuleOptionString(string name)
    {
        return await this.Session.VimClient.QueryConfiguredModuleOptionString(this.VimReference, name);
    }

    public async System.Threading.Tasks.Task<KernelModuleInfo[]?> QueryModules()
    {
        return await this.Session.VimClient.QueryModules(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateModuleOptionString(string name, string options)
    {
        await this.Session.VimClient.UpdateModuleOptionString(this.VimReference, name, options);
    }
}

public partial class HostLocalAccountManager : ManagedObject
{
    protected HostLocalAccountManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task AssignUserToGroup(string user, string group)
    {
        await this.Session.VimClient.AssignUserToGroup(this.VimReference, user, group);
    }

    public async System.Threading.Tasks.Task ChangePassword(string user, string oldPassword, string newPassword)
    {
        await this.Session.VimClient.ChangePassword(this.VimReference, user, oldPassword, newPassword);
    }

    public async System.Threading.Tasks.Task CreateGroup(HostAccountSpec group)
    {
        await this.Session.VimClient.CreateGroup(this.VimReference, group);
    }

    public async System.Threading.Tasks.Task CreateUser(HostAccountSpec user)
    {
        await this.Session.VimClient.CreateUser(this.VimReference, user);
    }

    public async System.Threading.Tasks.Task RemoveGroup(string groupName)
    {
        await this.Session.VimClient.RemoveGroup(this.VimReference, groupName);
    }

    public async System.Threading.Tasks.Task RemoveUser(string userName)
    {
        await this.Session.VimClient.RemoveUser(this.VimReference, userName);
    }

    public async System.Threading.Tasks.Task UnassignUserFromGroup(string user, string group)
    {
        await this.Session.VimClient.UnassignUserFromGroup(this.VimReference, user, group);
    }

    public async System.Threading.Tasks.Task UpdateUser(HostAccountSpec user)
    {
        await this.Session.VimClient.UpdateUser(this.VimReference, user);
    }
}

public partial class HostLocalAuthentication : HostAuthenticationStore
{
    protected HostLocalAuthentication(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class HostMemorySystem : ExtensibleManagedObject
{
    protected HostMemorySystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ServiceConsoleReservationInfo?> GetPropertyConsoleReservationInfo()
    {
        var obj = await this.GetProperty<ServiceConsoleReservationInfo>("consoleReservationInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineMemoryReservationInfo?> GetPropertyVirtualMachineReservationInfo()
    {
        var obj = await this.GetProperty<VirtualMachineMemoryReservationInfo>("virtualMachineReservationInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task ReconfigureServiceConsoleReservation(long cfgBytes)
    {
        await this.Session.VimClient.ReconfigureServiceConsoleReservation(this.VimReference, cfgBytes);
    }

    public async System.Threading.Tasks.Task ReconfigureVirtualMachineReservation(VirtualMachineMemoryReservationSpec spec)
    {
        await this.Session.VimClient.ReconfigureVirtualMachineReservation(this.VimReference, spec);
    }
}

public partial class HostNetworkSystem : ExtensibleManagedObject
{
    protected HostNetworkSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostNetCapabilities?> GetPropertyCapabilities()
    {
        var obj = await this.GetProperty<HostNetCapabilities>("capabilities");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostIpRouteConfig?> GetPropertyConsoleIpRouteConfig()
    {
        var obj = await this.GetProperty<HostIpRouteConfig>("consoleIpRouteConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostDnsConfig?> GetPropertyDnsConfig()
    {
        var obj = await this.GetProperty<HostDnsConfig>("dnsConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostIpRouteConfig?> GetPropertyIpRouteConfig()
    {
        var obj = await this.GetProperty<HostIpRouteConfig>("ipRouteConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostNetworkConfig?> GetPropertyNetworkConfig()
    {
        var obj = await this.GetProperty<HostNetworkConfig>("networkConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostNetworkInfo?> GetPropertyNetworkInfo()
    {
        var obj = await this.GetProperty<HostNetworkInfo>("networkInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostNetOffloadCapabilities?> GetPropertyOffloadCapabilities()
    {
        var obj = await this.GetProperty<HostNetOffloadCapabilities>("offloadCapabilities");
        return obj;
    }

    public async System.Threading.Tasks.Task AddPortGroup(HostPortGroupSpec portgrp)
    {
        await this.Session.VimClient.AddPortGroup(this.VimReference, portgrp);
    }

    public async System.Threading.Tasks.Task<string?> AddServiceConsoleVirtualNic(string portgroup, HostVirtualNicSpec nic)
    {
        return await this.Session.VimClient.AddServiceConsoleVirtualNic(this.VimReference, portgroup, nic);
    }

    public async System.Threading.Tasks.Task<string?> AddVirtualNic(string portgroup, HostVirtualNicSpec nic)
    {
        return await this.Session.VimClient.AddVirtualNic(this.VimReference, portgroup, nic);
    }

    public async System.Threading.Tasks.Task AddVirtualSwitch(string vswitchName, HostVirtualSwitchSpec? spec)
    {
        await this.Session.VimClient.AddVirtualSwitch(this.VimReference, vswitchName, spec);
    }

    public async System.Threading.Tasks.Task<PhysicalNicHintInfo[]?> QueryNetworkHint(string[]? device)
    {
        return await this.Session.VimClient.QueryNetworkHint(this.VimReference, device);
    }

    public async System.Threading.Tasks.Task RefreshNetworkSystem()
    {
        await this.Session.VimClient.RefreshNetworkSystem(this.VimReference);
    }

    public async System.Threading.Tasks.Task RemovePortGroup(string pgName)
    {
        await this.Session.VimClient.RemovePortGroup(this.VimReference, pgName);
    }

    public async System.Threading.Tasks.Task RemoveServiceConsoleVirtualNic(string device)
    {
        await this.Session.VimClient.RemoveServiceConsoleVirtualNic(this.VimReference, device);
    }

    public async System.Threading.Tasks.Task RemoveVirtualNic(string device)
    {
        await this.Session.VimClient.RemoveVirtualNic(this.VimReference, device);
    }

    public async System.Threading.Tasks.Task RemoveVirtualSwitch(string vswitchName)
    {
        await this.Session.VimClient.RemoveVirtualSwitch(this.VimReference, vswitchName);
    }

    public async System.Threading.Tasks.Task RestartServiceConsoleVirtualNic(string device)
    {
        await this.Session.VimClient.RestartServiceConsoleVirtualNic(this.VimReference, device);
    }

    public async System.Threading.Tasks.Task UpdateConsoleIpRouteConfig(HostIpRouteConfig config)
    {
        await this.Session.VimClient.UpdateConsoleIpRouteConfig(this.VimReference, config);
    }

    public async System.Threading.Tasks.Task UpdateDnsConfig(HostDnsConfig config)
    {
        await this.Session.VimClient.UpdateDnsConfig(this.VimReference, config);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteConfig(HostIpRouteConfig config)
    {
        await this.Session.VimClient.UpdateIpRouteConfig(this.VimReference, config);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteTableConfig(HostIpRouteTableConfig config)
    {
        await this.Session.VimClient.UpdateIpRouteTableConfig(this.VimReference, config);
    }

    public async System.Threading.Tasks.Task<HostNetworkConfigResult?> UpdateNetworkConfig(HostNetworkConfig config, string changeMode)
    {
        return await this.Session.VimClient.UpdateNetworkConfig(this.VimReference, config, changeMode);
    }

    public async System.Threading.Tasks.Task UpdatePhysicalNicLinkSpeed(string device, PhysicalNicLinkInfo? linkSpeed)
    {
        await this.Session.VimClient.UpdatePhysicalNicLinkSpeed(this.VimReference, device, linkSpeed);
    }

    public async System.Threading.Tasks.Task UpdatePortGroup(string pgName, HostPortGroupSpec portgrp)
    {
        await this.Session.VimClient.UpdatePortGroup(this.VimReference, pgName, portgrp);
    }

    public async System.Threading.Tasks.Task UpdateServiceConsoleVirtualNic(string device, HostVirtualNicSpec nic)
    {
        await this.Session.VimClient.UpdateServiceConsoleVirtualNic(this.VimReference, device, nic);
    }

    public async System.Threading.Tasks.Task UpdateVirtualNic(string device, HostVirtualNicSpec nic)
    {
        await this.Session.VimClient.UpdateVirtualNic(this.VimReference, device, nic);
    }

    public async System.Threading.Tasks.Task UpdateVirtualSwitch(string vswitchName, HostVirtualSwitchSpec spec)
    {
        await this.Session.VimClient.UpdateVirtualSwitch(this.VimReference, vswitchName, spec);
    }
}

public partial class HostNvdimmSystem : ManagedObject
{
    protected HostNvdimmSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<NvdimmSystemInfo> GetPropertyNvdimmSystemInfo()
    {
        var obj = await this.GetProperty<NvdimmSystemInfo>("nvdimmSystemInfo");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> CreateNvdimmNamespace_Task(NvdimmNamespaceCreateSpec createSpec)
    {
        var res = await this.Session.VimClient.CreateNvdimmNamespace_Task(this.VimReference, createSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateNvdimmPMemNamespace_Task(NvdimmPMemNamespaceCreateSpec createSpec)
    {
        var res = await this.Session.VimClient.CreateNvdimmPMemNamespace_Task(this.VimReference, createSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteNvdimmBlockNamespaces_Task()
    {
        var res = await this.Session.VimClient.DeleteNvdimmBlockNamespaces_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteNvdimmNamespace_Task(NvdimmNamespaceDeleteSpec deleteSpec)
    {
        var res = await this.Session.VimClient.DeleteNvdimmNamespace_Task(this.VimReference, deleteSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class HostPatchManager : ManagedObject
{
    protected HostPatchManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> CheckHostPatch_Task(string[]? metaUrls, string[]? bundleUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.CheckHostPatch_Task(this.VimReference, metaUrls, bundleUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InstallHostPatch_Task(HostPatchManagerLocator repository, string updateID, bool? force)
    {
        var res = await this.Session.VimClient.InstallHostPatch_Task(this.VimReference, repository, updateID, force ?? default, force.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InstallHostPatchV2_Task(string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.InstallHostPatchV2_Task(this.VimReference, metaUrls, bundleUrls, vibUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> QueryHostPatch_Task(HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.QueryHostPatch_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ScanHostPatch_Task(HostPatchManagerLocator repository, string[]? updateID)
    {
        var res = await this.Session.VimClient.ScanHostPatch_Task(this.VimReference, repository, updateID);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ScanHostPatchV2_Task(string[]? metaUrls, string[]? bundleUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.ScanHostPatchV2_Task(this.VimReference, metaUrls, bundleUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StageHostPatch_Task(string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.StageHostPatch_Task(this.VimReference, metaUrls, bundleUrls, vibUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UninstallHostPatch_Task(string[]? bulletinIds, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.UninstallHostPatch_Task(this.VimReference, bulletinIds, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class HostPciPassthruSystem : ExtensibleManagedObject
{
    protected HostPciPassthruSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostPciPassthruInfo[]> GetPropertyPciPassthruInfo()
    {
        var obj = await this.GetProperty<HostPciPassthruInfo[]>("pciPassthruInfo");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostSriovDevicePoolInfo[]?> GetPropertySriovDevicePoolInfo()
    {
        var obj = await this.GetProperty<HostSriovDevicePoolInfo[]>("sriovDevicePoolInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task Refresh()
    {
        await this.Session.VimClient.Refresh(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdatePassthruConfig(HostPciPassthruConfig[] config)
    {
        await this.Session.VimClient.UpdatePassthruConfig(this.VimReference, config);
    }
}

public partial class HostPowerSystem : ManagedObject
{
    protected HostPowerSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PowerSystemCapability> GetPropertyCapability()
    {
        var obj = await this.GetProperty<PowerSystemCapability>("capability");
        return obj!;
    }

    public async System.Threading.Tasks.Task<PowerSystemInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<PowerSystemInfo>("info");
        return obj!;
    }

    public async System.Threading.Tasks.Task ConfigurePowerPolicy(int key)
    {
        await this.Session.VimClient.ConfigurePowerPolicy(this.VimReference, key);
    }
}

public partial class HostProfile : Profile
{
    protected HostProfile(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostSystem?> GetPropertyReferenceHost()
    {
        var referenceHost = await this.GetProperty<ManagedObjectReference>("referenceHost");
        return ManagedObject.Create<HostSystem>(referenceHost, this.Session);
    }

    public async System.Threading.Tasks.Task<HostProfileValidationFailureInfo?> GetPropertyValidationFailureInfo()
    {
        var obj = await this.GetProperty<HostProfileValidationFailureInfo>("validationFailureInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyValidationState()
    {
        var obj = await this.GetProperty<string>("validationState");
        return obj;
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyValidationStateUpdateTime()
    {
        var obj = await this.GetProperty<DateTime>("validationStateUpdateTime");
        return obj;
    }

    public async System.Threading.Tasks.Task<ProfileExecuteResult?> ExecuteHostProfile(HostSystem host, ProfileDeferredPolicyOptionParameter[]? deferredParam)
    {
        return await this.Session.VimClient.ExecuteHostProfile(this.VimReference, host.VimReference, deferredParam);
    }

    public async System.Threading.Tasks.Task HostProfileResetValidationState()
    {
        await this.Session.VimClient.HostProfileResetValidationState(this.VimReference);
    }

    public async System.Threading.Tasks.Task UpdateHostProfile(HostProfileConfigSpec config)
    {
        await this.Session.VimClient.UpdateHostProfile(this.VimReference, config);
    }

    public async System.Threading.Tasks.Task UpdateReferenceHost(HostSystem? host)
    {
        await this.Session.VimClient.UpdateReferenceHost(this.VimReference, host?.VimReference);
    }
}

public partial class HostProfileManager : ProfileManager
{
    protected HostProfileManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> ApplyEntitiesConfig_Task(ApplyHostProfileConfigurationSpec[]? applyConfigSpecs)
    {
        var res = await this.Session.VimClient.ApplyEntitiesConfig_Task(this.VimReference, applyConfigSpecs);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ApplyHostConfig_Task(HostSystem host, HostConfigSpec configSpec, ProfileDeferredPolicyOptionParameter[]? userInput)
    {
        var res = await this.Session.VimClient.ApplyHostConfig_Task(this.VimReference, host.VimReference, configSpec, userInput);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckAnswerFileStatus_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.CheckAnswerFileStatus_Task(this.VimReference, host.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CompositeHostProfile_Task(Profile source, Profile[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toBeReplacedWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied)
    {
        var res = await this.Session.VimClient.CompositeHostProfile_Task(this.VimReference, source.VimReference, targets?.Select(m => m.VimReference).ToArray(), toBeMerged, toBeReplacedWith, toBeDeleted, enableStatusToBeCopied);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ApplyProfile?> CreateDefaultProfile(string profileType, string? profileTypeName, Profile? profile)
    {
        return await this.Session.VimClient.CreateDefaultProfile(this.VimReference, profileType, profileTypeName, profile?.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ExportAnswerFile_Task(HostSystem host)
    {
        var res = await this.Session.VimClient.ExportAnswerFile_Task(this.VimReference, host.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostProfileManagerConfigTaskList?> GenerateConfigTaskList(HostConfigSpec configSpec, HostSystem host)
    {
        return await this.Session.VimClient.GenerateConfigTaskList(this.VimReference, configSpec, host.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> GenerateHostConfigTaskSpec_Task(StructuredCustomizations[]? hostsInfo)
    {
        var res = await this.Session.VimClient.GenerateHostConfigTaskSpec_Task(this.VimReference, hostsInfo);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> GenerateHostProfileTaskList_Task(HostConfigSpec configSpec, HostSystem host)
    {
        var res = await this.Session.VimClient.GenerateHostProfileTaskList_Task(this.VimReference, configSpec, host.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult[]?> QueryAnswerFileStatus(HostSystem[] host)
    {
        return await this.Session.VimClient.QueryAnswerFileStatus(this.VimReference, host.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<ProfileMetadata[]?> QueryHostProfileMetadata(string[]? profileName, Profile? profile)
    {
        return await this.Session.VimClient.QueryHostProfileMetadata(this.VimReference, profileName, profile?.VimReference);
    }

    public async System.Threading.Tasks.Task<ProfileProfileStructure?> QueryProfileStructure(Profile? profile)
    {
        return await this.Session.VimClient.QueryProfileStructure(this.VimReference, profile?.VimReference);
    }

    public async System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFile(HostSystem host)
    {
        return await this.Session.VimClient.RetrieveAnswerFile(this.VimReference, host.VimReference);
    }

    public async System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFileForProfile(HostSystem host, HostApplyProfile applyProfile)
    {
        return await this.Session.VimClient.RetrieveAnswerFileForProfile(this.VimReference, host.VimReference, applyProfile);
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizations(HostSystem[]? hosts)
    {
        return await this.Session.VimClient.RetrieveHostCustomizations(this.VimReference, hosts?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizationsForProfile(HostSystem[]? hosts, HostApplyProfile applyProfile)
    {
        return await this.Session.VimClient.RetrieveHostCustomizationsForProfile(this.VimReference, hosts?.Select(m => m.VimReference).ToArray(), applyProfile);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateAnswerFile_Task(HostSystem host, AnswerFileCreateSpec configSpec)
    {
        var res = await this.Session.VimClient.UpdateAnswerFile_Task(this.VimReference, host.VimReference, configSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateHostCustomizations_Task(HostProfileManagerHostToConfigSpecMap[]? hostToConfigSpecMap)
    {
        var res = await this.Session.VimClient.UpdateHostCustomizations_Task(this.VimReference, hostToConfigSpecMap);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ValidateHostProfileComposition_Task(Profile source, Profile[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toReplaceWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied, bool? errorOnly)
    {
        var res = await this.Session.VimClient.ValidateHostProfileComposition_Task(this.VimReference, source.VimReference, targets?.Select(m => m.VimReference).ToArray(), toBeMerged, toReplaceWith, toBeDeleted, enableStatusToBeCopied, errorOnly ?? default, errorOnly.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class HostServiceSystem : ExtensibleManagedObject
{
    protected HostServiceSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostServiceInfo> GetPropertyServiceInfo()
    {
        var obj = await this.GetProperty<HostServiceInfo>("serviceInfo");
        return obj!;
    }

    public async System.Threading.Tasks.Task RefreshServices()
    {
        await this.Session.VimClient.RefreshServices(this.VimReference);
    }

    public async System.Threading.Tasks.Task RestartService(string id)
    {
        await this.Session.VimClient.RestartService(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task StartService(string id)
    {
        await this.Session.VimClient.StartService(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task StopService(string id)
    {
        await this.Session.VimClient.StopService(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task UninstallService(string id)
    {
        await this.Session.VimClient.UninstallService(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task UpdateServicePolicy(string id, string policy)
    {
        await this.Session.VimClient.UpdateServicePolicy(this.VimReference, id, policy);
    }
}

public partial class HostSnmpSystem : ManagedObject
{
    protected HostSnmpSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostSnmpConfigSpec> GetPropertyConfiguration()
    {
        var obj = await this.GetProperty<HostSnmpConfigSpec>("configuration");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostSnmpSystemAgentLimits> GetPropertyLimits()
    {
        var obj = await this.GetProperty<HostSnmpSystemAgentLimits>("limits");
        return obj!;
    }

    public async System.Threading.Tasks.Task ReconfigureSnmpAgent(HostSnmpConfigSpec spec)
    {
        await this.Session.VimClient.ReconfigureSnmpAgent(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task SendTestNotification()
    {
        await this.Session.VimClient.SendTestNotification(this.VimReference);
    }
}

public partial class HostSpecificationManager : ManagedObject
{
    protected HostSpecificationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task DeleteHostSpecification(HostSystem host)
    {
        await this.Session.VimClient.DeleteHostSpecification(this.VimReference, host.VimReference);
    }

    public async System.Threading.Tasks.Task DeleteHostSubSpecification(HostSystem host, string subSpecName)
    {
        await this.Session.VimClient.DeleteHostSubSpecification(this.VimReference, host.VimReference, subSpecName);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> HostSpecGetUpdatedHosts(string? startChangeID, string? endChangeID)
    {
        var res = await this.Session.VimClient.HostSpecGetUpdatedHosts(this.VimReference, startChangeID, endChangeID);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<HostSpecification?> RetrieveHostSpecification(HostSystem host, bool fromHost)
    {
        return await this.Session.VimClient.RetrieveHostSpecification(this.VimReference, host.VimReference, fromHost);
    }

    public async System.Threading.Tasks.Task UpdateHostSpecification(HostSystem host, HostSpecification hostSpec)
    {
        await this.Session.VimClient.UpdateHostSpecification(this.VimReference, host.VimReference, hostSpec);
    }

    public async System.Threading.Tasks.Task UpdateHostSubSpecification(HostSystem host, HostSubSpecification hostSubSpec)
    {
        await this.Session.VimClient.UpdateHostSubSpecification(this.VimReference, host.VimReference, hostSubSpec);
    }
}

public partial class HostStorageSystem : ExtensibleManagedObject
{
    protected HostStorageSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostFileSystemVolumeInfo> GetPropertyFileSystemVolumeInfo()
    {
        var obj = await this.GetProperty<HostFileSystemVolumeInfo>("fileSystemVolumeInfo");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostMultipathStateInfo?> GetPropertyMultipathStateInfo()
    {
        var obj = await this.GetProperty<HostMultipathStateInfo>("multipathStateInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostStorageDeviceInfo?> GetPropertyStorageDeviceInfo()
    {
        var obj = await this.GetProperty<HostStorageDeviceInfo>("storageDeviceInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertySystemFile()
    {
        var obj = await this.GetProperty<string[]>("systemFile");
        return obj;
    }

    public async System.Threading.Tasks.Task AddInternetScsiSendTargets(string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets)
    {
        await this.Session.VimClient.AddInternetScsiSendTargets(this.VimReference, iScsiHbaDevice, targets);
    }

    public async System.Threading.Tasks.Task AddInternetScsiStaticTargets(string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        await this.Session.VimClient.AddInternetScsiStaticTargets(this.VimReference, iScsiHbaDevice, targets);
    }

    public async System.Threading.Tasks.Task AttachScsiLun(string lunUuid)
    {
        await this.Session.VimClient.AttachScsiLun(this.VimReference, lunUuid);
    }

    public async System.Threading.Tasks.Task<Task?> AttachScsiLunEx_Task(string[] lunUuid)
    {
        var res = await this.Session.VimClient.AttachScsiLunEx_Task(this.VimReference, lunUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task AttachVmfsExtent(string vmfsPath, HostScsiDiskPartition extent)
    {
        await this.Session.VimClient.AttachVmfsExtent(this.VimReference, vmfsPath, extent);
    }

    public async System.Threading.Tasks.Task ChangeNFSUserPassword(string password)
    {
        await this.Session.VimClient.ChangeNFSUserPassword(this.VimReference, password);
    }

    public async System.Threading.Tasks.Task ClearNFSUser()
    {
        await this.Session.VimClient.ClearNFSUser(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfo(string devicePath, HostDiskPartitionLayout layout, string? partitionFormat)
    {
        return await this.Session.VimClient.ComputeDiskPartitionInfo(this.VimReference, devicePath, layout, partitionFormat);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfoForResize(HostScsiDiskPartition partition, HostDiskPartitionBlockRange blockRange, string? partitionFormat)
    {
        return await this.Session.VimClient.ComputeDiskPartitionInfoForResize(this.VimReference, partition, blockRange, partitionFormat);
    }

    public async System.Threading.Tasks.Task ConnectNvmeController(HostNvmeConnectSpec connectSpec)
    {
        await this.Session.VimClient.ConnectNvmeController(this.VimReference, connectSpec);
    }

    public async System.Threading.Tasks.Task<Task?> ConnectNvmeControllerEx_Task(HostNvmeConnectSpec[]? connectSpec)
    {
        var res = await this.Session.VimClient.ConnectNvmeControllerEx_Task(this.VimReference, connectSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CreateNvmeOverRdmaAdapter(string rdmaDeviceName)
    {
        await this.Session.VimClient.CreateNvmeOverRdmaAdapter(this.VimReference, rdmaDeviceName);
    }

    public async System.Threading.Tasks.Task CreateSoftwareAdapter(HostHbaCreateSpec spec)
    {
        await this.Session.VimClient.CreateSoftwareAdapter(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task DeleteScsiLunState(string lunCanonicalName)
    {
        await this.Session.VimClient.DeleteScsiLunState(this.VimReference, lunCanonicalName);
    }

    public async System.Threading.Tasks.Task DeleteVffsVolumeState(string vffsUuid)
    {
        await this.Session.VimClient.DeleteVffsVolumeState(this.VimReference, vffsUuid);
    }

    public async System.Threading.Tasks.Task DeleteVmfsVolumeState(string vmfsUuid)
    {
        await this.Session.VimClient.DeleteVmfsVolumeState(this.VimReference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task DestroyVffs(string vffsPath)
    {
        await this.Session.VimClient.DestroyVffs(this.VimReference, vffsPath);
    }

    public async System.Threading.Tasks.Task DetachScsiLun(string lunUuid)
    {
        await this.Session.VimClient.DetachScsiLun(this.VimReference, lunUuid);
    }

    public async System.Threading.Tasks.Task<Task?> DetachScsiLunEx_Task(string[] lunUuid)
    {
        var res = await this.Session.VimClient.DetachScsiLunEx_Task(this.VimReference, lunUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableMultipathPath(string pathName)
    {
        await this.Session.VimClient.DisableMultipathPath(this.VimReference, pathName);
    }

    public async System.Threading.Tasks.Task DisconnectNvmeController(HostNvmeDisconnectSpec disconnectSpec)
    {
        await this.Session.VimClient.DisconnectNvmeController(this.VimReference, disconnectSpec);
    }

    public async System.Threading.Tasks.Task<Task?> DisconnectNvmeControllerEx_Task(HostNvmeDisconnectSpec[]? disconnectSpec)
    {
        var res = await this.Session.VimClient.DisconnectNvmeControllerEx_Task(this.VimReference, disconnectSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DiscoverFcoeHbas(FcoeConfigFcoeSpecification fcoeSpec)
    {
        await this.Session.VimClient.DiscoverFcoeHbas(this.VimReference, fcoeSpec);
    }

    public async System.Threading.Tasks.Task<HostNvmeDiscoveryLog?> DiscoverNvmeControllers(HostNvmeDiscoverSpec discoverSpec)
    {
        return await this.Session.VimClient.DiscoverNvmeControllers(this.VimReference, discoverSpec);
    }

    public async System.Threading.Tasks.Task EnableMultipathPath(string pathName)
    {
        await this.Session.VimClient.EnableMultipathPath(this.VimReference, pathName);
    }

    public async System.Threading.Tasks.Task ExpandVmfsExtent(string vmfsPath, HostScsiDiskPartition extent)
    {
        await this.Session.VimClient.ExpandVmfsExtent(this.VimReference, vmfsPath, extent);
    }

    public async System.Threading.Tasks.Task ExtendVffs(string vffsPath, string devicePath, HostDiskPartitionSpec? spec)
    {
        await this.Session.VimClient.ExtendVffs(this.VimReference, vffsPath, devicePath, spec);
    }

    public async System.Threading.Tasks.Task<HostVffsVolume?> FormatVffs(HostVffsSpec createSpec)
    {
        return await this.Session.VimClient.FormatVffs(this.VimReference, createSpec);
    }

    public async System.Threading.Tasks.Task<HostVmfsVolume?> FormatVmfs(HostVmfsSpec createSpec)
    {
        return await this.Session.VimClient.FormatVmfs(this.VimReference, createSpec);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsLocal_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsLocal_Task(this.VimReference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsNonLocal_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsNonLocal_Task(this.VimReference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsNonSsd_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsNonSsd_Task(this.VimReference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsSsd_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsSsd_Task(this.VimReference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MarkForRemoval(string hbaName, bool remove)
    {
        await this.Session.VimClient.MarkForRemoval(this.VimReference, hbaName, remove);
    }

    public async System.Threading.Tasks.Task MarkPerenniallyReserved(string lunUuid, bool state)
    {
        await this.Session.VimClient.MarkPerenniallyReserved(this.VimReference, lunUuid, state);
    }

    public async System.Threading.Tasks.Task<Task?> MarkPerenniallyReservedEx_Task(string[]? lunUuid, bool state)
    {
        var res = await this.Session.VimClient.MarkPerenniallyReservedEx_Task(this.VimReference, lunUuid, state);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MountVffsVolume(string vffsUuid)
    {
        await this.Session.VimClient.MountVffsVolume(this.VimReference, vffsUuid);
    }

    public async System.Threading.Tasks.Task MountVmfsVolume(string vmfsUuid)
    {
        await this.Session.VimClient.MountVmfsVolume(this.VimReference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task<Task?> MountVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.VimClient.MountVmfsVolumeEx_Task(this.VimReference, vmfsUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableSsds(string? vffsPath)
    {
        return await this.Session.VimClient.QueryAvailableSsds(this.VimReference, vffsPath);
    }

    public async System.Threading.Tasks.Task<HostNasVolumeUserInfo?> QueryNFSUser()
    {
        return await this.Session.VimClient.QueryNFSUser(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostPathSelectionPolicyOption[]?> QueryPathSelectionPolicyOptions()
    {
        return await this.Session.VimClient.QueryPathSelectionPolicyOptions(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostStorageArrayTypePolicyOption[]?> QueryStorageArrayTypePolicyOptions()
    {
        return await this.Session.VimClient.QueryStorageArrayTypePolicyOptions(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolume()
    {
        return await this.Session.VimClient.QueryUnresolvedVmfsVolume(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VmfsConfigOption[]?> QueryVmfsConfigOption()
    {
        return await this.Session.VimClient.QueryVmfsConfigOption(this.VimReference);
    }

    public async System.Threading.Tasks.Task RefreshStorageSystem()
    {
        await this.Session.VimClient.RefreshStorageSystem(this.VimReference);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiSendTargets(string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets, bool? force)
    {
        await this.Session.VimClient.RemoveInternetScsiSendTargets(this.VimReference, iScsiHbaDevice, targets, force ?? default, force.HasValue);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiStaticTargets(string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        await this.Session.VimClient.RemoveInternetScsiStaticTargets(this.VimReference, iScsiHbaDevice, targets);
    }

    public async System.Threading.Tasks.Task RemoveNvmeOverRdmaAdapter(string hbaDeviceName)
    {
        await this.Session.VimClient.RemoveNvmeOverRdmaAdapter(this.VimReference, hbaDeviceName);
    }

    public async System.Threading.Tasks.Task RemoveSoftwareAdapter(string hbaDeviceName)
    {
        await this.Session.VimClient.RemoveSoftwareAdapter(this.VimReference, hbaDeviceName);
    }

    public async System.Threading.Tasks.Task RescanAllHba()
    {
        await this.Session.VimClient.RescanAllHba(this.VimReference);
    }

    public async System.Threading.Tasks.Task RescanHba(string hbaDevice)
    {
        await this.Session.VimClient.RescanHba(this.VimReference, hbaDevice);
    }

    public async System.Threading.Tasks.Task RescanVffs()
    {
        await this.Session.VimClient.RescanVffs(this.VimReference);
    }

    public async System.Threading.Tasks.Task RescanVmfs()
    {
        await this.Session.VimClient.RescanVmfs(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsResolutionResult[]?> ResolveMultipleUnresolvedVmfsVolumes(HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        return await this.Session.VimClient.ResolveMultipleUnresolvedVmfsVolumes(this.VimReference, resolutionSpec);
    }

    public async System.Threading.Tasks.Task<Task?> ResolveMultipleUnresolvedVmfsVolumesEx_Task(HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        var res = await this.Session.VimClient.ResolveMultipleUnresolvedVmfsVolumesEx_Task(this.VimReference, resolutionSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo[]?> RetrieveDiskPartitionInfo(string[] devicePath)
    {
        return await this.Session.VimClient.RetrieveDiskPartitionInfo(this.VimReference, devicePath);
    }

    public async System.Threading.Tasks.Task SetMultipathLunPolicy(string lunId, HostMultipathInfoLogicalUnitPolicy policy)
    {
        await this.Session.VimClient.SetMultipathLunPolicy(this.VimReference, lunId, policy);
    }

    public async System.Threading.Tasks.Task SetNFSUser(string user, string password)
    {
        await this.Session.VimClient.SetNFSUser(this.VimReference, user, password);
    }

    public async System.Threading.Tasks.Task<Task?> TurnDiskLocatorLedOff_Task(string[] scsiDiskUuids)
    {
        var res = await this.Session.VimClient.TurnDiskLocatorLedOff_Task(this.VimReference, scsiDiskUuids);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> TurnDiskLocatorLedOn_Task(string[] scsiDiskUuids)
    {
        var res = await this.Session.VimClient.TurnDiskLocatorLedOn_Task(this.VimReference, scsiDiskUuids);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnmapVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.VimClient.UnmapVmfsVolumeEx_Task(this.VimReference, vmfsUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UnmountForceMountedVmfsVolume(string vmfsUuid)
    {
        await this.Session.VimClient.UnmountForceMountedVmfsVolume(this.VimReference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task UnmountVffsVolume(string vffsUuid)
    {
        await this.Session.VimClient.UnmountVffsVolume(this.VimReference, vffsUuid);
    }

    public async System.Threading.Tasks.Task UnmountVmfsVolume(string vmfsUuid)
    {
        await this.Session.VimClient.UnmountVmfsVolume(this.VimReference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task<Task?> UnmountVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.VimClient.UnmountVmfsVolumeEx_Task(this.VimReference, vmfsUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateDiskPartitions(string devicePath, HostDiskPartitionSpec spec)
    {
        await this.Session.VimClient.UpdateDiskPartitions(this.VimReference, devicePath, spec);
    }

    public async System.Threading.Tasks.Task UpdateHppMultipathLunPolicy(string lunId, HostMultipathInfoHppLogicalUnitPolicy policy)
    {
        await this.Session.VimClient.UpdateHppMultipathLunPolicy(this.VimReference, lunId, policy);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAdvancedOptions(string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaParamValue[] options)
    {
        await this.Session.VimClient.UpdateInternetScsiAdvancedOptions(this.VimReference, iScsiHbaDevice, targetSet, options);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAlias(string iScsiHbaDevice, string iScsiAlias)
    {
        await this.Session.VimClient.UpdateInternetScsiAlias(this.VimReference, iScsiHbaDevice, iScsiAlias);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAuthenticationProperties(string iScsiHbaDevice, HostInternetScsiHbaAuthenticationProperties authenticationProperties, HostInternetScsiHbaTargetSet? targetSet)
    {
        await this.Session.VimClient.UpdateInternetScsiAuthenticationProperties(this.VimReference, iScsiHbaDevice, authenticationProperties, targetSet);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDigestProperties(string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaDigestProperties digestProperties)
    {
        await this.Session.VimClient.UpdateInternetScsiDigestProperties(this.VimReference, iScsiHbaDevice, targetSet, digestProperties);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDiscoveryProperties(string iScsiHbaDevice, HostInternetScsiHbaDiscoveryProperties discoveryProperties)
    {
        await this.Session.VimClient.UpdateInternetScsiDiscoveryProperties(this.VimReference, iScsiHbaDevice, discoveryProperties);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiIPProperties(string iScsiHbaDevice, HostInternetScsiHbaIPProperties ipProperties)
    {
        await this.Session.VimClient.UpdateInternetScsiIPProperties(this.VimReference, iScsiHbaDevice, ipProperties);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiName(string iScsiHbaDevice, string iScsiName)
    {
        await this.Session.VimClient.UpdateInternetScsiName(this.VimReference, iScsiHbaDevice, iScsiName);
    }

    public async System.Threading.Tasks.Task UpdateScsiLunDisplayName(string lunUuid, string displayName)
    {
        await this.Session.VimClient.UpdateScsiLunDisplayName(this.VimReference, lunUuid, displayName);
    }

    public async System.Threading.Tasks.Task UpdateSoftwareInternetScsiEnabled(bool enabled)
    {
        await this.Session.VimClient.UpdateSoftwareInternetScsiEnabled(this.VimReference, enabled);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapBandwidth(string vmfsUuid, VmfsUnmapBandwidthSpec unmapBandwidthSpec)
    {
        await this.Session.VimClient.UpdateVmfsUnmapBandwidth(this.VimReference, vmfsUuid, unmapBandwidthSpec);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapPriority(string vmfsUuid, string unmapPriority)
    {
        await this.Session.VimClient.UpdateVmfsUnmapPriority(this.VimReference, vmfsUuid, unmapPriority);
    }

    public async System.Threading.Tasks.Task UpgradeVmfs(string vmfsPath)
    {
        await this.Session.VimClient.UpgradeVmfs(this.VimReference, vmfsPath);
    }

    public async System.Threading.Tasks.Task UpgradeVmLayout()
    {
        await this.Session.VimClient.UpgradeVmLayout(this.VimReference);
    }
}

public partial class HostSystem : ManagedEntity
{
    protected HostSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult?> GetPropertyAnswerFileValidationResult()
    {
        var obj = await this.GetProperty<AnswerFileStatusResult>("answerFileValidationResult");
        return obj;
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult?> GetPropertyAnswerFileValidationState()
    {
        var obj = await this.GetProperty<AnswerFileStatusResult>("answerFileValidationState");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostCapability?> GetPropertyCapability()
    {
        var obj = await this.GetProperty<HostCapability>("capability");
        return obj;
    }

    public async System.Threading.Tasks.Task<ComplianceResult?> GetPropertyComplianceCheckResult()
    {
        var obj = await this.GetProperty<ComplianceResult>("complianceCheckResult");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostSystemComplianceCheckState?> GetPropertyComplianceCheckState()
    {
        var obj = await this.GetProperty<HostSystemComplianceCheckState>("complianceCheckState");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostConfigInfo?> GetPropertyConfig()
    {
        var obj = await this.GetProperty<HostConfigInfo>("config");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostConfigManager> GetPropertyConfigManager()
    {
        var obj = await this.GetProperty<HostConfigManager>("configManager");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore?
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<HostDatastoreBrowser> GetPropertyDatastoreBrowser()
    {
        var datastoreBrowser = await this.GetProperty<ManagedObjectReference>("datastoreBrowser");
        return ManagedObject.Create<HostDatastoreBrowser>(datastoreBrowser, this.Session)!;
    }

    public async System.Threading.Tasks.Task<HostHardwareInfo?> GetPropertyHardware()
    {
        var obj = await this.GetProperty<HostHardwareInfo>("hardware");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostLicensableResourceInfo> GetPropertyLicensableResource()
    {
        var obj = await this.GetProperty<HostLicensableResourceInfo>("licensableResource");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network?
            .Select(r => ManagedObject.Create<Network>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ApplyHostProfileConfigurationSpec?> GetPropertyPrecheckRemediationResult()
    {
        var obj = await this.GetProperty<ApplyHostProfileConfigurationSpec>("precheckRemediationResult");
        return obj;
    }

    public async System.Threading.Tasks.Task<ApplyHostProfileConfigurationResult?> GetPropertyRemediationResult()
    {
        var obj = await this.GetProperty<ApplyHostProfileConfigurationResult>("remediationResult");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostSystemRemediationState?> GetPropertyRemediationState()
    {
        var obj = await this.GetProperty<HostSystemRemediationState>("remediationState");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<HostRuntimeInfo>("runtime");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostListSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<HostListSummary>("summary");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostSystemResourceInfo?> GetPropertySystemResources()
    {
        var obj = await this.GetProperty<HostSystemResourceInfo>("systemResources");
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm?
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<HostServiceTicket?> AcquireCimServicesTicket()
    {
        return await this.Session.VimClient.AcquireCimServicesTicket(this.VimReference);
    }

    public async System.Threading.Tasks.Task ConfigureCryptoKey(CryptoKeyId? keyId)
    {
        await this.Session.VimClient.ConfigureCryptoKey(this.VimReference, keyId);
    }

    public async System.Threading.Tasks.Task<Task?> DisconnectHost_Task()
    {
        var res = await this.Session.VimClient.DisconnectHost_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task EnableCrypto(CryptoKeyPlain keyPlain)
    {
        await this.Session.VimClient.EnableCrypto(this.VimReference, keyPlain);
    }

    public async System.Threading.Tasks.Task EnterLockdownMode()
    {
        await this.Session.VimClient.EnterLockdownMode(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> EnterMaintenanceMode_Task(int timeout, bool? evacuatePoweredOffVms, HostMaintenanceSpec? maintenanceSpec)
    {
        var res = await this.Session.VimClient.EnterMaintenanceMode_Task(this.VimReference, timeout, evacuatePoweredOffVms ?? default, evacuatePoweredOffVms.HasValue, maintenanceSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ExitLockdownMode()
    {
        await this.Session.VimClient.ExitLockdownMode(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ExitMaintenanceMode_Task(int timeout)
    {
        var res = await this.Session.VimClient.ExitMaintenanceMode_Task(this.VimReference, timeout);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerDownHostToStandBy_Task(int timeoutSec, bool? evacuatePoweredOffVms)
    {
        var res = await this.Session.VimClient.PowerDownHostToStandBy_Task(this.VimReference, timeoutSec, evacuatePoweredOffVms ?? default, evacuatePoweredOffVms.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerUpHostFromStandBy_Task(int timeoutSec)
    {
        var res = await this.Session.VimClient.PowerUpHostFromStandBy_Task(this.VimReference, timeoutSec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task PrepareCrypto()
    {
        await this.Session.VimClient.PrepareCrypto(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryHostConnectionInfo()
    {
        return await this.Session.VimClient.QueryHostConnectionInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverhead(long memorySize, int? videoRamSize, int numVcpus)
    {
        return await this.Session.VimClient.QueryMemoryOverhead(this.VimReference, memorySize, videoRamSize ?? default, videoRamSize.HasValue, numVcpus);
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverheadEx(VirtualMachineConfigInfo vmConfigInfo)
    {
        return await this.Session.VimClient.QueryMemoryOverheadEx(this.VimReference, vmConfigInfo);
    }

    public async System.Threading.Tasks.Task<string?> QueryProductLockerLocation()
    {
        return await this.Session.VimClient.QueryProductLockerLocation(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostTpmAttestationReport?> QueryTpmAttestationReport()
    {
        return await this.Session.VimClient.QueryTpmAttestationReport(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> RebootHost_Task(bool force)
    {
        var res = await this.Session.VimClient.RebootHost_Task(this.VimReference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureHostForDAS_Task()
    {
        var res = await this.Session.VimClient.ReconfigureHostForDAS_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconnectHost_Task(HostConnectSpec? cnxSpec, HostSystemReconnectSpec? reconnectSpec)
    {
        var res = await this.Session.VimClient.ReconnectHost_Task(this.VimReference, cnxSpec, reconnectSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<long> RetrieveFreeEpcMemory()
    {
        return await this.Session.VimClient.RetrieveFreeEpcMemory(this.VimReference);
    }

    public async System.Threading.Tasks.Task<long> RetrieveHardwareUptime()
    {
        return await this.Session.VimClient.RetrieveHardwareUptime(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ShutdownHost_Task(bool force)
    {
        var res = await this.Session.VimClient.ShutdownHost_Task(this.VimReference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateFlags(HostFlagInfo flagInfo)
    {
        await this.Session.VimClient.UpdateFlags(this.VimReference, flagInfo);
    }

    public async System.Threading.Tasks.Task UpdateIpmi(HostIpmiInfo ipmiInfo)
    {
        await this.Session.VimClient.UpdateIpmi(this.VimReference, ipmiInfo);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateProductLockerLocation_Task(string path)
    {
        var res = await this.Session.VimClient.UpdateProductLockerLocation_Task(this.VimReference, path);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateSystemResources(HostSystemResourceInfo resourceInfo)
    {
        await this.Session.VimClient.UpdateSystemResources(this.VimReference, resourceInfo);
    }

    public async System.Threading.Tasks.Task UpdateSystemSwapConfiguration(HostSystemSwapConfiguration sysSwapConfig)
    {
        await this.Session.VimClient.UpdateSystemSwapConfiguration(this.VimReference, sysSwapConfig);
    }
}

public partial class HostVFlashManager : ManagedObject
{
    protected HostVFlashManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostVFlashManagerVFlashConfigInfo?> GetPropertyVFlashConfigInfo()
    {
        var obj = await this.GetProperty<HostVFlashManagerVFlashConfigInfo>("vFlashConfigInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureVFlashResourceEx_Task(string[]? devicePath)
    {
        var res = await this.Session.VimClient.ConfigureVFlashResourceEx_Task(this.VimReference, devicePath);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HostConfigureVFlashResource(HostVFlashManagerVFlashResourceConfigSpec spec)
    {
        await this.Session.VimClient.HostConfigureVFlashResource(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task HostConfigVFlashCache(HostVFlashManagerVFlashCacheConfigSpec spec)
    {
        await this.Session.VimClient.HostConfigVFlashCache(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task<VirtualDiskVFlashCacheConfigInfo?> HostGetVFlashModuleDefaultConfig(string vFlashModule)
    {
        return await this.Session.VimClient.HostGetVFlashModuleDefaultConfig(this.VimReference, vFlashModule);
    }

    public async System.Threading.Tasks.Task HostRemoveVFlashResource()
    {
        await this.Session.VimClient.HostRemoveVFlashResource(this.VimReference);
    }
}

public partial class HostVirtualNicManager : ExtensibleManagedObject
{
    protected HostVirtualNicManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostVirtualNicManagerInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<HostVirtualNicManagerInfo>("info");
        return obj!;
    }

    public async System.Threading.Tasks.Task DeselectVnicForNicType(string nicType, string device)
    {
        await this.Session.VimClient.DeselectVnicForNicType(this.VimReference, nicType, device);
    }

    public async System.Threading.Tasks.Task<VirtualNicManagerNetConfig?> QueryNetConfig(string nicType)
    {
        return await this.Session.VimClient.QueryNetConfig(this.VimReference, nicType);
    }

    public async System.Threading.Tasks.Task SelectVnicForNicType(string nicType, string device)
    {
        await this.Session.VimClient.SelectVnicForNicType(this.VimReference, nicType, device);
    }
}

public partial class HostVMotionSystem : ExtensibleManagedObject
{
    protected HostVMotionSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostIpConfig?> GetPropertyIpConfig()
    {
        var obj = await this.GetProperty<HostIpConfig>("ipConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<HostVMotionNetConfig?> GetPropertyNetConfig()
    {
        var obj = await this.GetProperty<HostVMotionNetConfig>("netConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task DeselectVnic()
    {
        await this.Session.VimClient.DeselectVnic(this.VimReference);
    }

    public async System.Threading.Tasks.Task SelectVnic(string device)
    {
        await this.Session.VimClient.SelectVnic(this.VimReference, device);
    }

    public async System.Threading.Tasks.Task UpdateIpConfig(HostIpConfig ipConfig)
    {
        await this.Session.VimClient.UpdateIpConfig(this.VimReference, ipConfig);
    }
}

public partial class HostVsanInternalSystem : ManagedObject
{
    protected HostVsanInternalSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string[]?> AbdicateDomOwnership(string[] uuids)
    {
        return await this.Session.VimClient.AbdicateDomOwnership(this.VimReference, uuids);
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> CanProvisionObjects(VsanNewPolicyBatch[] npbs, bool? ignoreSatisfiability)
    {
        return await this.Session.VimClient.CanProvisionObjects(this.VimReference, npbs, ignoreSatisfiability ?? default, ignoreSatisfiability.HasValue);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemDeleteVsanObjectsResult[]?> DeleteVsanObjects(string[] uuids, bool? force)
    {
        return await this.Session.VimClient.DeleteVsanObjects(this.VimReference, uuids, force ?? default, force.HasValue);
    }

    public async System.Threading.Tasks.Task<string?> GetVsanObjExtAttrs(string[] uuids)
    {
        return await this.Session.VimClient.GetVsanObjExtAttrs(this.VimReference, uuids);
    }

    public async System.Threading.Tasks.Task<string?> QueryCmmds(HostVsanInternalSystemCmmdsQuery[] queries)
    {
        return await this.Session.VimClient.QueryCmmds(this.VimReference, queries);
    }

    public async System.Threading.Tasks.Task<string?> QueryObjectsOnPhysicalVsanDisk(string[] disks)
    {
        return await this.Session.VimClient.QueryObjectsOnPhysicalVsanDisk(this.VimReference, disks);
    }

    public async System.Threading.Tasks.Task<string?> QueryPhysicalVsanDisks(string[]? props)
    {
        return await this.Session.VimClient.QueryPhysicalVsanDisks(this.VimReference, props);
    }

    public async System.Threading.Tasks.Task<string?> QuerySyncingVsanObjects(string[]? uuids)
    {
        return await this.Session.VimClient.QuerySyncingVsanObjects(this.VimReference, uuids);
    }

    public async System.Threading.Tasks.Task<string?> QueryVsanObjects(string[]? uuids)
    {
        return await this.Session.VimClient.QueryVsanObjects(this.VimReference, uuids);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryVsanObjectUuidsByFilter(string[]? uuids, int? limit, int? version)
    {
        return await this.Session.VimClient.QueryVsanObjectUuidsByFilter(this.VimReference, uuids, limit ?? default, limit.HasValue, version ?? default, version.HasValue);
    }

    public async System.Threading.Tasks.Task<string?> QueryVsanStatistics(string[] labels)
    {
        return await this.Session.VimClient.QueryVsanStatistics(this.VimReference, labels);
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> ReconfigurationSatisfiable(VsanPolicyChangeBatch[] pcbs, bool? ignoreSatisfiability)
    {
        return await this.Session.VimClient.ReconfigurationSatisfiable(this.VimReference, pcbs, ignoreSatisfiability ?? default, ignoreSatisfiability.HasValue);
    }

    public async System.Threading.Tasks.Task ReconfigureDomObject(string uuid, string policy)
    {
        await this.Session.VimClient.ReconfigureDomObject(this.VimReference, uuid, policy);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanPhysicalDiskDiagnosticsResult[]?> RunVsanPhysicalDiskDiagnostics(string[]? disks)
    {
        return await this.Session.VimClient.RunVsanPhysicalDiskDiagnostics(this.VimReference, disks);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanObjectOperationResult[]?> UpgradeVsanObjects(string[] uuids, int newVersion)
    {
        return await this.Session.VimClient.UpgradeVsanObjects(this.VimReference, uuids, newVersion);
    }
}

public partial class HostVsanSystem : ManagedObject
{
    protected HostVsanSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<VsanHostConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<VsanHostConfigInfo>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> AddDisks_Task(HostScsiDisk[] disk)
    {
        var res = await this.Session.VimClient.AddDisks_Task(this.VimReference, disk);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> EvacuateVsanNode_Task(HostMaintenanceSpec maintenanceSpec, int timeout)
    {
        var res = await this.Session.VimClient.EvacuateVsanNode_Task(this.VimReference, maintenanceSpec, timeout);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InitializeDisks_Task(VsanHostDiskMapping[] mapping)
    {
        var res = await this.Session.VimClient.InitializeDisks_Task(this.VimReference, mapping);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VsanHostDiskResult[]?> QueryDisksForVsan(string[]? canonicalName)
    {
        return await this.Session.VimClient.QueryDisksForVsan(this.VimReference, canonicalName);
    }

    public async System.Threading.Tasks.Task<VsanHostClusterStatus?> QueryHostStatus()
    {
        return await this.Session.VimClient.QueryHostStatus(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> RecommissionVsanNode_Task()
    {
        var res = await this.Session.VimClient.RecommissionVsanNode_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveDisk_Task(HostScsiDisk[] disk, HostMaintenanceSpec? maintenanceSpec, int? timeout)
    {
        var res = await this.Session.VimClient.RemoveDisk_Task(this.VimReference, disk, maintenanceSpec, timeout ?? default, timeout.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveDiskMapping_Task(VsanHostDiskMapping[] mapping, HostMaintenanceSpec? maintenanceSpec, int? timeout)
    {
        var res = await this.Session.VimClient.RemoveDiskMapping_Task(this.VimReference, mapping, maintenanceSpec, timeout ?? default, timeout.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnmountDiskMapping_Task(VsanHostDiskMapping[] mapping)
    {
        var res = await this.Session.VimClient.UnmountDiskMapping_Task(this.VimReference, mapping);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVsan_Task(VsanHostConfigInfo config)
    {
        var res = await this.Session.VimClient.UpdateVsan_Task(this.VimReference, config);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class HostVStorageObjectManager : VStorageObjectManagerBase
{
    protected HostVStorageObjectManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task HostClearVStorageObjectControlFlags(ID id, Datastore datastore, string[]? controlFlags)
    {
        await this.Session.VimClient.HostClearVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task?> HostCloneVStorageObject_Task(ID id, Datastore datastore, VslmCloneSpec spec)
    {
        var res = await this.Session.VimClient.HostCloneVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostCreateDisk_Task(VslmCreateSpec spec)
    {
        var res = await this.Session.VimClient.HostCreateDisk_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostDeleteVStorageObject_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.HostDeleteVStorageObject_Task(this.VimReference, id, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostDeleteVStorageObjectEx_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.HostDeleteVStorageObjectEx_Task(this.VimReference, id, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostExtendDisk_Task(ID id, Datastore datastore, long newCapacityInMB)
    {
        var res = await this.Session.VimClient.HostExtendDisk_Task(this.VimReference, id, datastore.VimReference, newCapacityInMB);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostInflateDisk_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.HostInflateDisk_Task(this.VimReference, id, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ID[]?> HostListVStorageObject(Datastore datastore)
    {
        return await this.Session.VimClient.HostListVStorageObject(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> HostReconcileDatastoreInventory_Task(Datastore datastore)
    {
        var res = await this.Session.VimClient.HostReconcileDatastoreInventory_Task(this.VimReference, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> HostRegisterDisk(string path, string? name)
    {
        return await this.Session.VimClient.HostRegisterDisk(this.VimReference, path, name);
    }

    public async System.Threading.Tasks.Task<Task?> HostRelocateVStorageObject_Task(ID id, Datastore datastore, VslmRelocateSpec spec)
    {
        var res = await this.Session.VimClient.HostRelocateVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HostRenameVStorageObject(ID id, Datastore datastore, string name)
    {
        await this.Session.VimClient.HostRenameVStorageObject(this.VimReference, id, datastore.VimReference, name);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> HostRetrieveVStorageInfrastructureObjectPolicy(Datastore datastore)
    {
        return await this.Session.VimClient.HostRetrieveVStorageInfrastructureObjectPolicy(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> HostRetrieveVStorageObject(ID id, Datastore datastore, string[]? diskInfoFlags)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObject(this.VimReference, id, datastore.VimReference, diskInfoFlags);
    }

    public async System.Threading.Tasks.Task<KeyValue[]?> HostRetrieveVStorageObjectMetadata(ID id, Datastore datastore, ID? snapshotId, string? prefix)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObjectMetadata(this.VimReference, id, datastore.VimReference, snapshotId, prefix);
    }

    public async System.Threading.Tasks.Task<string?> HostRetrieveVStorageObjectMetadataValue(ID id, Datastore datastore, ID? snapshotId, string key)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObjectMetadataValue(this.VimReference, id, datastore.VimReference, snapshotId, key);
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> HostRetrieveVStorageObjectState(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObjectState(this.VimReference, id, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task HostScheduleReconcileDatastoreInventory(Datastore datastore)
    {
        await this.Session.VimClient.HostScheduleReconcileDatastoreInventory(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task HostSetVStorageObjectControlFlags(ID id, Datastore datastore, string[]? controlFlags)
    {
        await this.Session.VimClient.HostSetVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task?> HostUpdateVStorageObjectMetadata_Task(ID id, Datastore datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var res = await this.Session.VimClient.HostUpdateVStorageObjectMetadata_Task(this.VimReference, id, datastore.VimReference, metadata, deleteKeys);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostUpdateVStorageObjectMetadataEx_Task(ID id, Datastore datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var res = await this.Session.VimClient.HostUpdateVStorageObjectMetadataEx_Task(this.VimReference, id, datastore.VimReference, metadata, deleteKeys);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectCreateDiskFromSnapshot_Task(ID id, Datastore datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path, string? provisioningType)
    {
        var res = await this.Session.VimClient.HostVStorageObjectCreateDiskFromSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId, name, profile, crypto, path, provisioningType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectCreateSnapshot_Task(ID id, Datastore datastore, string description)
    {
        var res = await this.Session.VimClient.HostVStorageObjectCreateSnapshot_Task(this.VimReference, id, datastore.VimReference, description);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectDeleteSnapshot_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.HostVStorageObjectDeleteSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> HostVStorageObjectRetrieveSnapshotInfo(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.HostVStorageObjectRetrieveSnapshotInfo(this.VimReference, id, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectRevert_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.HostVStorageObjectRevert_Task(this.VimReference, id, datastore.VimReference, snapshotId);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class HttpNfcLease : ManagedObject
{
    protected HttpNfcLease(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseCapabilities> GetPropertyCapabilities()
    {
        var obj = await this.GetProperty<HttpNfcLeaseCapabilities>("capabilities");
        return obj!;
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault?> GetPropertyError()
    {
        var obj = await this.GetProperty<LocalizedMethodFault>("error");
        return obj;
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseInfo?> GetPropertyInfo()
    {
        var obj = await this.GetProperty<HttpNfcLeaseInfo>("info");
        return obj;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyInitializeProgress()
    {
        var obj = await this.GetProperty<int>("initializeProgress");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyMode()
    {
        var obj = await this.GetProperty<string>("mode");
        return obj!;
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseState> GetPropertyState()
    {
        var obj = await this.GetProperty<HttpNfcLeaseState>("state");
        return obj!;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyTransferProgress()
    {
        var obj = await this.GetProperty<int>("transferProgress");
        return obj!;
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseAbort(LocalizedMethodFault? fault)
    {
        await this.Session.VimClient.HttpNfcLeaseAbort(this.VimReference, fault);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseComplete()
    {
        await this.Session.VimClient.HttpNfcLeaseComplete(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseManifestEntry[]?> HttpNfcLeaseGetManifest()
    {
        return await this.Session.VimClient.HttpNfcLeaseGetManifest(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseProbeResult[]?> HttpNfcLeaseProbeUrls(HttpNfcLeaseSourceFile[]? files, int? timeout)
    {
        return await this.Session.VimClient.HttpNfcLeaseProbeUrls(this.VimReference, files, timeout ?? default, timeout.HasValue);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseProgress(int percent)
    {
        await this.Session.VimClient.HttpNfcLeaseProgress(this.VimReference, percent);
    }

    public async System.Threading.Tasks.Task<Task?> HttpNfcLeasePullFromUrls_Task(HttpNfcLeaseSourceFile[]? files)
    {
        var res = await this.Session.VimClient.HttpNfcLeasePullFromUrls_Task(this.VimReference, files);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseSetManifestChecksumType(KeyValue[]? deviceUrlsToChecksumTypes)
    {
        await this.Session.VimClient.HttpNfcLeaseSetManifestChecksumType(this.VimReference, deviceUrlsToChecksumTypes);
    }
}

public partial class InventoryView : ManagedObjectView
{
    protected InventoryView(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> CloseInventoryViewFolder(ManagedEntity[] entity)
    {
        var res = await this.Session.VimClient.CloseInventoryViewFolder(this.VimReference, entity.Select(m => m.VimReference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> OpenInventoryViewFolder(ManagedEntity[] entity)
    {
        var res = await this.Session.VimClient.OpenInventoryViewFolder(this.VimReference, entity.Select(m => m.VimReference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }
}

public partial class IoFilterManager : ManagedObject
{
    protected IoFilterManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> InstallIoFilter_Task(string vibUrl, ComputeResource compRes)
    {
        var res = await this.Session.VimClient.InstallIoFilter_Task(this.VimReference, vibUrl, compRes.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualDiskId[]?> QueryDisksUsingFilter(string filterId, ComputeResource compRes)
    {
        return await this.Session.VimClient.QueryDisksUsingFilter(this.VimReference, filterId, compRes.VimReference);
    }

    public async System.Threading.Tasks.Task<ClusterIoFilterInfo[]?> QueryIoFilterInfo(ComputeResource compRes)
    {
        return await this.Session.VimClient.QueryIoFilterInfo(this.VimReference, compRes.VimReference);
    }

    public async System.Threading.Tasks.Task<IoFilterQueryIssueResult?> QueryIoFilterIssues(string filterId, ComputeResource compRes)
    {
        return await this.Session.VimClient.QueryIoFilterIssues(this.VimReference, filterId, compRes.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ResolveInstallationErrorsOnCluster_Task(string filterId, ClusterComputeResource cluster)
    {
        var res = await this.Session.VimClient.ResolveInstallationErrorsOnCluster_Task(this.VimReference, filterId, cluster.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ResolveInstallationErrorsOnHost_Task(string filterId, HostSystem host)
    {
        var res = await this.Session.VimClient.ResolveInstallationErrorsOnHost_Task(this.VimReference, filterId, host.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UninstallIoFilter_Task(string filterId, ComputeResource compRes)
    {
        var res = await this.Session.VimClient.UninstallIoFilter_Task(this.VimReference, filterId, compRes.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpgradeIoFilter_Task(string filterId, ComputeResource compRes, string vibUrl)
    {
        var res = await this.Session.VimClient.UpgradeIoFilter_Task(this.VimReference, filterId, compRes.VimReference, vibUrl);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class IpPoolManager : ManagedObject
{
    protected IpPoolManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string?> AllocateIpv4Address(Datacenter dc, int poolId, string allocationId)
    {
        return await this.Session.VimClient.AllocateIpv4Address(this.VimReference, dc.VimReference, poolId, allocationId);
    }

    public async System.Threading.Tasks.Task<string?> AllocateIpv6Address(Datacenter dc, int poolId, string allocationId)
    {
        return await this.Session.VimClient.AllocateIpv6Address(this.VimReference, dc.VimReference, poolId, allocationId);
    }

    public async System.Threading.Tasks.Task<int> CreateIpPool(Datacenter dc, IpPool pool)
    {
        return await this.Session.VimClient.CreateIpPool(this.VimReference, dc.VimReference, pool);
    }

    public async System.Threading.Tasks.Task DestroyIpPool(Datacenter dc, int id, bool force)
    {
        await this.Session.VimClient.DestroyIpPool(this.VimReference, dc.VimReference, id, force);
    }

    public async System.Threading.Tasks.Task<IpPoolManagerIpAllocation[]?> QueryIPAllocations(Datacenter dc, int poolId, string extensionKey)
    {
        return await this.Session.VimClient.QueryIPAllocations(this.VimReference, dc.VimReference, poolId, extensionKey);
    }

    public async System.Threading.Tasks.Task<IpPool[]?> QueryIpPools(Datacenter dc)
    {
        return await this.Session.VimClient.QueryIpPools(this.VimReference, dc.VimReference);
    }

    public async System.Threading.Tasks.Task ReleaseIpAllocation(Datacenter dc, int poolId, string allocationId)
    {
        await this.Session.VimClient.ReleaseIpAllocation(this.VimReference, dc.VimReference, poolId, allocationId);
    }

    public async System.Threading.Tasks.Task UpdateIpPool(Datacenter dc, IpPool pool)
    {
        await this.Session.VimClient.UpdateIpPool(this.VimReference, dc.VimReference, pool);
    }
}

public partial class IscsiManager : ManagedObject
{
    protected IscsiManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task BindVnic(string iScsiHbaName, string vnicDevice)
    {
        await this.Session.VimClient.BindVnic(this.VimReference, iScsiHbaName, vnicDevice);
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryBoundVnics(string iScsiHbaName)
    {
        return await this.Session.VimClient.QueryBoundVnics(this.VimReference, iScsiHbaName);
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryCandidateNics(string iScsiHbaName)
    {
        return await this.Session.VimClient.QueryCandidateNics(this.VimReference, iScsiHbaName);
    }

    public async System.Threading.Tasks.Task<IscsiMigrationDependency?> QueryMigrationDependencies(string[] pnicDevice)
    {
        return await this.Session.VimClient.QueryMigrationDependencies(this.VimReference, pnicDevice);
    }

    public async System.Threading.Tasks.Task<IscsiStatus?> QueryPnicStatus(string pnicDevice)
    {
        return await this.Session.VimClient.QueryPnicStatus(this.VimReference, pnicDevice);
    }

    public async System.Threading.Tasks.Task<IscsiStatus?> QueryVnicStatus(string vnicDevice)
    {
        return await this.Session.VimClient.QueryVnicStatus(this.VimReference, vnicDevice);
    }

    public async System.Threading.Tasks.Task UnbindVnic(string iScsiHbaName, string vnicDevice, bool force)
    {
        await this.Session.VimClient.UnbindVnic(this.VimReference, iScsiHbaName, vnicDevice, force);
    }
}

public partial class LicenseAssignmentManager : ManagedObject
{
    protected LicenseAssignmentManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<LicenseAssignmentManagerLicenseAssignment[]?> QueryAssignedLicenses(string? entityId)
    {
        return await this.Session.VimClient.QueryAssignedLicenses(this.VimReference, entityId);
    }

    public async System.Threading.Tasks.Task RemoveAssignedLicense(string entityId)
    {
        await this.Session.VimClient.RemoveAssignedLicense(this.VimReference, entityId);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateAssignedLicense(string entity, string licenseKey, string? entityDisplayName)
    {
        return await this.Session.VimClient.UpdateAssignedLicense(this.VimReference, entity, licenseKey, entityDisplayName);
    }
}

public partial class LicenseManager : ManagedObject
{
    protected LicenseManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<LicenseDiagnostics?> GetPropertyDiagnostics()
    {
        var obj = await this.GetProperty<LicenseDiagnostics>("diagnostics");
        return obj;
    }

    public async System.Threading.Tasks.Task<LicenseManagerEvaluationInfo> GetPropertyEvaluation()
    {
        var obj = await this.GetProperty<LicenseManagerEvaluationInfo>("evaluation");
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseFeatureInfo[]?> GetPropertyFeatureInfo()
    {
        var obj = await this.GetProperty<LicenseFeatureInfo[]>("featureInfo");
        return obj;
    }

    public async System.Threading.Tasks.Task<LicenseAssignmentManager?> GetPropertyLicenseAssignmentManager()
    {
        var licenseAssignmentManager = await this.GetProperty<ManagedObjectReference>("licenseAssignmentManager");
        return ManagedObject.Create<LicenseAssignmentManager>(licenseAssignmentManager, this.Session);
    }

    public async System.Threading.Tasks.Task<string> GetPropertyLicensedEdition()
    {
        var obj = await this.GetProperty<string>("licensedEdition");
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo[]> GetPropertyLicenses()
    {
        var obj = await this.GetProperty<LicenseManagerLicenseInfo[]>("licenses");
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseSource> GetPropertySource()
    {
        var obj = await this.GetProperty<LicenseSource>("source");
        return obj!;
    }

    public async System.Threading.Tasks.Task<bool> GetPropertySourceAvailable()
    {
        var obj = await this.GetProperty<bool>("sourceAvailable");
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> AddLicense(string licenseKey, KeyValue[]? labels)
    {
        return await this.Session.VimClient.AddLicense(this.VimReference, licenseKey, labels);
    }

    public async System.Threading.Tasks.Task<bool> CheckLicenseFeature(HostSystem? host, string featureKey)
    {
        return await this.Session.VimClient.CheckLicenseFeature(this.VimReference, host?.VimReference, featureKey);
    }

    public async System.Threading.Tasks.Task ConfigureLicenseSource(HostSystem? host, LicenseSource licenseSource)
    {
        await this.Session.VimClient.ConfigureLicenseSource(this.VimReference, host?.VimReference, licenseSource);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> DecodeLicense(string licenseKey)
    {
        return await this.Session.VimClient.DecodeLicense(this.VimReference, licenseKey);
    }

    public async System.Threading.Tasks.Task<bool> DisableFeature(HostSystem? host, string featureKey)
    {
        return await this.Session.VimClient.DisableFeature(this.VimReference, host?.VimReference, featureKey);
    }

    public async System.Threading.Tasks.Task<bool> EnableFeature(HostSystem? host, string featureKey)
    {
        return await this.Session.VimClient.EnableFeature(this.VimReference, host?.VimReference, featureKey);
    }

    public async System.Threading.Tasks.Task<LicenseAvailabilityInfo[]?> QueryLicenseSourceAvailability(HostSystem? host)
    {
        return await this.Session.VimClient.QueryLicenseSourceAvailability(this.VimReference, host?.VimReference);
    }

    public async System.Threading.Tasks.Task<LicenseUsageInfo?> QueryLicenseUsage(HostSystem? host)
    {
        return await this.Session.VimClient.QueryLicenseUsage(this.VimReference, host?.VimReference);
    }

    public async System.Threading.Tasks.Task<LicenseFeatureInfo[]?> QuerySupportedFeatures(HostSystem? host)
    {
        return await this.Session.VimClient.QuerySupportedFeatures(this.VimReference, host?.VimReference);
    }

    public async System.Threading.Tasks.Task RemoveLicense(string licenseKey)
    {
        await this.Session.VimClient.RemoveLicense(this.VimReference, licenseKey);
    }

    public async System.Threading.Tasks.Task RemoveLicenseLabel(string licenseKey, string labelKey)
    {
        await this.Session.VimClient.RemoveLicenseLabel(this.VimReference, licenseKey, labelKey);
    }

    public async System.Threading.Tasks.Task SetLicenseEdition(HostSystem? host, string? featureKey)
    {
        await this.Session.VimClient.SetLicenseEdition(this.VimReference, host?.VimReference, featureKey);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateLicense(string licenseKey, KeyValue[]? labels)
    {
        return await this.Session.VimClient.UpdateLicense(this.VimReference, licenseKey, labels);
    }

    public async System.Threading.Tasks.Task UpdateLicenseLabel(string licenseKey, string labelKey, string labelValue)
    {
        await this.Session.VimClient.UpdateLicenseLabel(this.VimReference, licenseKey, labelKey, labelValue);
    }
}

public partial class ListView : ManagedObjectView
{
    protected ListView(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ManagedObject[]?> ModifyListView(ManagedObject[]? add, ManagedObject[]? remove)
    {
        var res = await this.Session.VimClient.ModifyListView(this.VimReference, add?.Select(m => m.VimReference).ToArray(), remove?.Select(m => m.VimReference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedObject[]?> ResetListView(ManagedObject[]? obj)
    {
        var res = await this.Session.VimClient.ResetListView(this.VimReference, obj?.Select(m => m.VimReference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task ResetListViewFromView(View view)
    {
        await this.Session.VimClient.ResetListViewFromView(this.VimReference, view.VimReference);
    }
}

public partial class LocalizationManager : ManagedObject
{
    protected LocalizationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<LocalizationManagerMessageCatalog[]?> GetPropertyCatalog()
    {
        var obj = await this.GetProperty<LocalizationManagerMessageCatalog[]>("catalog");
        return obj;
    }
}

public partial class ManagedEntity : ExtensibleManagedObject
{
    protected ManagedEntity(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyAlarmActionsEnabled()
    {
        var obj = await this.GetProperty<bool>("alarmActionsEnabled");
        return obj;
    }

    public async System.Threading.Tasks.Task<Event[]?> GetPropertyConfigIssue()
    {
        var obj = await this.GetProperty<Event[]>("configIssue");
        return obj;
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyConfigStatus()
    {
        var obj = await this.GetProperty<ManagedEntityStatus>("configStatus");
        return obj!;
    }

    public async System.Threading.Tasks.Task<CustomFieldValue[]?> GetPropertyCustomValue()
    {
        var obj = await this.GetProperty<CustomFieldValue[]>("customValue");
        return obj;
    }

    public async System.Threading.Tasks.Task<AlarmState[]?> GetPropertyDeclaredAlarmState()
    {
        var obj = await this.GetProperty<AlarmState[]>("declaredAlarmState");
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyDisabledMethod()
    {
        var obj = await this.GetProperty<string[]>("disabledMethod");
        return obj;
    }

    public async System.Threading.Tasks.Task<int[]?> GetPropertyEffectiveRole()
    {
        var obj = await this.GetProperty<int[]>("effectiveRole");
        return obj;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        var obj = await this.GetProperty<string>("name");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyOverallStatus()
    {
        var obj = await this.GetProperty<ManagedEntityStatus>("overallStatus");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> GetPropertyParent()
    {
        var parent = await this.GetProperty<ManagedObjectReference>("parent");
        return ManagedObject.Create<ManagedEntity>(parent, this.Session);
    }

    public async System.Threading.Tasks.Task<Permission[]?> GetPropertyPermission()
    {
        var obj = await this.GetProperty<Permission[]>("permission");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task[]?> GetPropertyRecentTask()
    {
        var recentTask = await this.GetProperty<ManagedObjectReference[]>("recentTask");
        return recentTask?
            .Select(r => ManagedObject.Create<Task>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Tag[]?> GetPropertyTag()
    {
        var obj = await this.GetProperty<Tag[]>("tag");
        return obj;
    }

    public async System.Threading.Tasks.Task<AlarmState[]?> GetPropertyTriggeredAlarmState()
    {
        var obj = await this.GetProperty<AlarmState[]>("triggeredAlarmState");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> Destroy_Task()
    {
        var res = await this.Session.VimClient.Destroy_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task Reload()
    {
        await this.Session.VimClient.Reload(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> Rename_Task(string newName)
    {
        var res = await this.Session.VimClient.Rename_Task(this.VimReference, newName);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class ManagedObjectView : View
{
    protected ManagedObjectView(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ManagedObject[]?> GetPropertyView()
    {
        var view = await this.GetProperty<ManagedObjectReference[]>("view");
        return view?
            .Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)!)
            .ToArray();
    }
}

public partial class MessageBusProxy : ManagedObject
{
    protected MessageBusProxy(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class Network : ManagedEntity
{
    protected Network(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> GetPropertyHost()
    {
        var host = await this.GetProperty<ManagedObjectReference[]>("host");
        return host?
            .Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!)
            .ToArray();
    }

    public new async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        var obj = await this.GetProperty<string>("name");
        return obj!;
    }

    public async System.Threading.Tasks.Task<NetworkSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<NetworkSummary>("summary");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm?
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task DestroyNetwork()
    {
        await this.Session.VimClient.DestroyNetwork(this.VimReference);
    }
}

public partial class OpaqueNetwork : Network
{
    protected OpaqueNetwork(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<OpaqueNetworkCapability?> GetPropertyCapability()
    {
        var obj = await this.GetProperty<OpaqueNetworkCapability>("capability");
        return obj;
    }

    public async System.Threading.Tasks.Task<OptionValue[]?> GetPropertyExtraConfig()
    {
        var obj = await this.GetProperty<OptionValue[]>("extraConfig");
        return obj;
    }
}

public partial class OptionManager : ManagedObject
{
    protected OptionManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<OptionValue[]?> GetPropertySetting()
    {
        var obj = await this.GetProperty<OptionValue[]>("setting");
        return obj;
    }

    public async System.Threading.Tasks.Task<OptionDef[]?> GetPropertySupportedOption()
    {
        var obj = await this.GetProperty<OptionDef[]>("supportedOption");
        return obj;
    }

    public async System.Threading.Tasks.Task<OptionValue[]?> QueryOptions(string? name)
    {
        return await this.Session.VimClient.QueryOptions(this.VimReference, name);
    }

    public async System.Threading.Tasks.Task UpdateOptions(OptionValue[] changedValue)
    {
        await this.Session.VimClient.UpdateOptions(this.VimReference, changedValue);
    }
}

public partial class OverheadMemoryManager : ManagedObject
{
    protected OverheadMemoryManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<long> LookupVmOverheadMemory(VirtualMachine vm, HostSystem host)
    {
        return await this.Session.VimClient.LookupVmOverheadMemory(this.VimReference, vm.VimReference, host.VimReference);
    }
}

public partial class OvfManager : ManagedObject
{
    protected OvfManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<OvfOptionInfo[]?> GetPropertyOvfExportOption()
    {
        var obj = await this.GetProperty<OvfOptionInfo[]>("ovfExportOption");
        return obj;
    }

    public async System.Threading.Tasks.Task<OvfOptionInfo[]?> GetPropertyOvfImportOption()
    {
        var obj = await this.GetProperty<OvfOptionInfo[]>("ovfImportOption");
        return obj;
    }

    public async System.Threading.Tasks.Task<OvfCreateDescriptorResult?> CreateDescriptor(ManagedEntity obj, OvfCreateDescriptorParams cdp)
    {
        return await this.Session.VimClient.CreateDescriptor(this.VimReference, obj.VimReference, cdp);
    }

    public async System.Threading.Tasks.Task<OvfCreateImportSpecResult?> CreateImportSpec(string ovfDescriptor, ResourcePool resourcePool, Datastore datastore, OvfCreateImportSpecParams cisp)
    {
        return await this.Session.VimClient.CreateImportSpec(this.VimReference, ovfDescriptor, resourcePool.VimReference, datastore.VimReference, cisp);
    }

    public async System.Threading.Tasks.Task<OvfParseDescriptorResult?> ParseDescriptor(string ovfDescriptor, OvfParseDescriptorParams pdp)
    {
        return await this.Session.VimClient.ParseDescriptor(this.VimReference, ovfDescriptor, pdp);
    }

    public async System.Threading.Tasks.Task<OvfValidateHostResult?> ValidateHost(string ovfDescriptor, HostSystem host, OvfValidateHostParams vhp)
    {
        return await this.Session.VimClient.ValidateHost(this.VimReference, ovfDescriptor, host.VimReference, vhp);
    }
}

public partial class PerformanceManager : ManagedObject
{
    protected PerformanceManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PerformanceDescription> GetPropertyDescription()
    {
        var obj = await this.GetProperty<PerformanceDescription>("description");
        return obj!;
    }

    public async System.Threading.Tasks.Task<PerfInterval[]?> GetPropertyHistoricalInterval()
    {
        var obj = await this.GetProperty<PerfInterval[]>("historicalInterval");
        return obj;
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> GetPropertyPerfCounter()
    {
        var obj = await this.GetProperty<PerfCounterInfo[]>("perfCounter");
        return obj;
    }

    public async System.Threading.Tasks.Task CreatePerfInterval(PerfInterval intervalId)
    {
        await this.Session.VimClient.CreatePerfInterval(this.VimReference, intervalId);
    }

    public async System.Threading.Tasks.Task<PerfMetricId[]?> QueryAvailablePerfMetric(ManagedObject entity, DateTime? beginTime, DateTime? endTime, int? intervalId)
    {
        return await this.Session.VimClient.QueryAvailablePerfMetric(this.VimReference, entity.VimReference, beginTime ?? default, beginTime.HasValue, endTime ?? default, endTime.HasValue, intervalId ?? default, intervalId.HasValue);
    }

    public async System.Threading.Tasks.Task<PerfEntityMetricBase[]?> QueryPerf(PerfQuerySpec[] querySpec)
    {
        return await this.Session.VimClient.QueryPerf(this.VimReference, querySpec);
    }

    public async System.Threading.Tasks.Task<PerfCompositeMetric?> QueryPerfComposite(PerfQuerySpec querySpec)
    {
        return await this.Session.VimClient.QueryPerfComposite(this.VimReference, querySpec);
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounter(int[] counterId)
    {
        return await this.Session.VimClient.QueryPerfCounter(this.VimReference, counterId);
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounterByLevel(int level)
    {
        return await this.Session.VimClient.QueryPerfCounterByLevel(this.VimReference, level);
    }

    public async System.Threading.Tasks.Task<PerfProviderSummary?> QueryPerfProviderSummary(ManagedObject entity)
    {
        return await this.Session.VimClient.QueryPerfProviderSummary(this.VimReference, entity.VimReference);
    }

    public async System.Threading.Tasks.Task RemovePerfInterval(int samplePeriod)
    {
        await this.Session.VimClient.RemovePerfInterval(this.VimReference, samplePeriod);
    }

    public async System.Threading.Tasks.Task ResetCounterLevelMapping(int[] counters)
    {
        await this.Session.VimClient.ResetCounterLevelMapping(this.VimReference, counters);
    }

    public async System.Threading.Tasks.Task UpdateCounterLevelMapping(PerformanceManagerCounterLevelMapping[] counterLevelMap)
    {
        await this.Session.VimClient.UpdateCounterLevelMapping(this.VimReference, counterLevelMap);
    }

    public async System.Threading.Tasks.Task UpdatePerfInterval(PerfInterval interval)
    {
        await this.Session.VimClient.UpdatePerfInterval(this.VimReference, interval);
    }
}

public partial class Profile : ManagedObject
{
    protected Profile(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string> GetPropertyComplianceStatus()
    {
        var obj = await this.GetProperty<string>("complianceStatus");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ProfileConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<ProfileConfigInfo>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyCreatedTime()
    {
        var obj = await this.GetProperty<DateTime>("createdTime");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ProfileDescription?> GetPropertyDescription()
    {
        var obj = await this.GetProperty<ProfileDescription>("description");
        return obj;
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> GetPropertyEntity()
    {
        var entity = await this.GetProperty<ManagedObjectReference[]>("entity");
        return entity?
            .Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyModifiedTime()
    {
        var obj = await this.GetProperty<DateTime>("modifiedTime");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        var obj = await this.GetProperty<string>("name");
        return obj!;
    }

    public async System.Threading.Tasks.Task AssociateProfile(ManagedEntity[] entity)
    {
        await this.Session.VimClient.AssociateProfile(this.VimReference, entity.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<Task?> CheckProfileCompliance_Task(ManagedEntity[]? entity)
    {
        var res = await this.Session.VimClient.CheckProfileCompliance_Task(this.VimReference, entity?.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyProfile()
    {
        await this.Session.VimClient.DestroyProfile(this.VimReference);
    }

    public async System.Threading.Tasks.Task DissociateProfile(ManagedEntity[]? entity)
    {
        await this.Session.VimClient.DissociateProfile(this.VimReference, entity?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<string?> ExportProfile()
    {
        return await this.Session.VimClient.ExportProfile(this.VimReference);
    }

    public async System.Threading.Tasks.Task<ProfileDescription?> RetrieveDescription()
    {
        return await this.Session.VimClient.RetrieveDescription(this.VimReference);
    }
}

public partial class ProfileComplianceManager : ManagedObject
{
    protected ProfileComplianceManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> CheckCompliance_Task(Profile[]? profile, ManagedEntity[]? entity)
    {
        var res = await this.Session.VimClient.CheckCompliance_Task(this.VimReference, profile?.Select(m => m.VimReference).ToArray(), entity?.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ClearComplianceStatus(Profile[]? profile, ManagedEntity[]? entity)
    {
        await this.Session.VimClient.ClearComplianceStatus(this.VimReference, profile?.Select(m => m.VimReference).ToArray(), entity?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<ComplianceResult[]?> QueryComplianceStatus(Profile[]? profile, ManagedEntity[]? entity)
    {
        return await this.Session.VimClient.QueryComplianceStatus(this.VimReference, profile?.Select(m => m.VimReference).ToArray(), entity?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<ProfileExpressionMetadata[]?> QueryExpressionMetadata(string[]? expressionName, Profile? profile)
    {
        return await this.Session.VimClient.QueryExpressionMetadata(this.VimReference, expressionName, profile?.VimReference);
    }
}

public partial class ProfileManager : ManagedObject
{
    protected ProfileManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Profile[]?> GetPropertyProfile()
    {
        var profile = await this.GetProperty<ManagedObjectReference[]>("profile");
        return profile?
            .Select(r => ManagedObject.Create<Profile>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Profile?> CreateProfile(ProfileCreateSpec createSpec)
    {
        var res = await this.Session.VimClient.CreateProfile(this.VimReference, createSpec);
        return ManagedObject.Create<Profile>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Profile[]?> FindAssociatedProfile(ManagedEntity entity)
    {
        var res = await this.Session.VimClient.FindAssociatedProfile(this.VimReference, entity.VimReference);
        return res?.Select(r => ManagedObject.Create<Profile>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ProfilePolicyMetadata[]?> QueryPolicyMetadata(string[]? policyName, Profile? profile)
    {
        return await this.Session.VimClient.QueryPolicyMetadata(this.VimReference, policyName, profile?.VimReference);
    }
}

public partial class PropertyCollector : ManagedObject
{
    protected PropertyCollector(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PropertyFilter[]?> GetPropertyFilter()
    {
        var filter = await this.GetProperty<ManagedObjectReference[]>("filter");
        return filter?
            .Select(r => ManagedObject.Create<PropertyFilter>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task CancelRetrievePropertiesEx(string token)
    {
        await this.Session.VimClient.CancelRetrievePropertiesEx(this.VimReference, token);
    }

    public async System.Threading.Tasks.Task CancelWaitForUpdates()
    {
        await this.Session.VimClient.CancelWaitForUpdates(this.VimReference);
    }

    public async System.Threading.Tasks.Task<UpdateSet?> CheckForUpdates(string? version)
    {
        return await this.Session.VimClient.CheckForUpdates(this.VimReference, version);
    }

    public async System.Threading.Tasks.Task<RetrieveResult?> ContinueRetrievePropertiesEx(string token)
    {
        return await this.Session.VimClient.ContinueRetrievePropertiesEx(this.VimReference, token);
    }

    public async System.Threading.Tasks.Task<PropertyFilter?> CreateFilter(PropertyFilterSpec spec, bool partialUpdates)
    {
        var res = await this.Session.VimClient.CreateFilter(this.VimReference, spec, partialUpdates);
        return ManagedObject.Create<PropertyFilter>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<PropertyCollector?> CreatePropertyCollector()
    {
        var res = await this.Session.VimClient.CreatePropertyCollector(this.VimReference);
        return ManagedObject.Create<PropertyCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyPropertyCollector()
    {
        await this.Session.VimClient.DestroyPropertyCollector(this.VimReference);
    }

    public async System.Threading.Tasks.Task<ObjectContent[]?> RetrieveProperties(PropertyFilterSpec[] specSet)
    {
        return await this.Session.VimClient.RetrieveProperties(this.VimReference, specSet);
    }

    public async System.Threading.Tasks.Task<RetrieveResult?> RetrievePropertiesEx(PropertyFilterSpec[] specSet, RetrieveOptions options)
    {
        return await this.Session.VimClient.RetrievePropertiesEx(this.VimReference, specSet, options);
    }

    public async System.Threading.Tasks.Task<UpdateSet?> WaitForUpdates(string? version)
    {
        return await this.Session.VimClient.WaitForUpdates(this.VimReference, version);
    }

    public async System.Threading.Tasks.Task<UpdateSet?> WaitForUpdatesEx(string? version, WaitOptions? options)
    {
        return await this.Session.VimClient.WaitForUpdatesEx(this.VimReference, version, options);
    }
}

public partial class PropertyFilter : ManagedObject
{
    protected PropertyFilter(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyPartialUpdates()
    {
        var obj = await this.GetProperty<bool>("partialUpdates");
        return obj!;
    }

    public async System.Threading.Tasks.Task<PropertyFilterSpec> GetPropertySpec()
    {
        var obj = await this.GetProperty<PropertyFilterSpec>("spec");
        return obj!;
    }

    public async System.Threading.Tasks.Task DestroyPropertyFilter()
    {
        await this.Session.VimClient.DestroyPropertyFilter(this.VimReference);
    }
}

public partial class ResourcePlanningManager : ManagedObject
{
    protected ResourcePlanningManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<DatabaseSizeEstimate?> EstimateDatabaseSize(DatabaseSizeParam dbSizeParam)
    {
        return await this.Session.VimClient.EstimateDatabaseSize(this.VimReference, dbSizeParam);
    }
}

public partial class ResourcePool : ManagedEntity
{
    protected ResourcePool(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ResourceConfigSpec[]?> GetPropertyChildConfiguration()
    {
        var obj = await this.GetProperty<ResourceConfigSpec[]>("childConfiguration");
        return obj;
    }

    public async System.Threading.Tasks.Task<ResourceConfigSpec> GetPropertyConfig()
    {
        var obj = await this.GetProperty<ResourceConfigSpec>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyNamespace()
    {
        var obj = await this.GetProperty<string>("namespace");
        return obj;
    }

    public async System.Threading.Tasks.Task<ComputeResource> GetPropertyOwner()
    {
        var owner = await this.GetProperty<ManagedObjectReference>("owner");
        return ManagedObject.Create<ComputeResource>(owner, this.Session)!;
    }

    public async System.Threading.Tasks.Task<ResourcePool[]?> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference[]>("resourcePool");
        return resourcePool?
            .Select(r => ManagedObject.Create<ResourcePool>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ResourcePoolRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<ResourcePoolRuntimeInfo>("runtime");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ResourcePoolSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<ResourcePoolSummary>("summary");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm?
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Task?> CreateChildVM_Task(VirtualMachineConfigSpec config, HostSystem? host)
    {
        var res = await this.Session.VimClient.CreateChildVM_Task(this.VimReference, config, host?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ResourcePool?> CreateResourcePool(string name, ResourceConfigSpec spec)
    {
        var res = await this.Session.VimClient.CreateResourcePool(this.VimReference, name, spec);
        return ManagedObject.Create<ResourcePool>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualApp?> CreateVApp(string name, ResourceConfigSpec resSpec, VAppConfigSpec configSpec, Folder? vmFolder)
    {
        var res = await this.Session.VimClient.CreateVApp(this.VimReference, name, resSpec, configSpec, vmFolder?.VimReference);
        return ManagedObject.Create<VirtualApp>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyChildren()
    {
        await this.Session.VimClient.DestroyChildren(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ImportVApp(ImportSpec spec, Folder? folder, HostSystem? host)
    {
        var res = await this.Session.VimClient.ImportVApp(this.VimReference, spec, folder?.VimReference, host?.VimReference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MoveIntoResourcePool(ManagedEntity[] list)
    {
        await this.Session.VimClient.MoveIntoResourcePool(this.VimReference, list.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<ResourceConfigOption?> QueryResourceConfigOption()
    {
        return await this.Session.VimClient.QueryResourceConfigOption(this.VimReference);
    }

    public async System.Threading.Tasks.Task RefreshRuntime()
    {
        await this.Session.VimClient.RefreshRuntime(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> RegisterChildVM_Task(string path, string? name, HostSystem? host)
    {
        var res = await this.Session.VimClient.RegisterChildVM_Task(this.VimReference, path, name, host?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateChildResourceConfiguration(ResourceConfigSpec[] spec)
    {
        await this.Session.VimClient.UpdateChildResourceConfiguration(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task UpdateConfig(string? name, ResourceConfigSpec? config)
    {
        await this.Session.VimClient.UpdateConfig(this.VimReference, name, config);
    }
}

public partial class ScheduledTask : ExtensibleManagedObject
{
    protected ScheduledTask(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ScheduledTaskInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<ScheduledTaskInfo>("info");
        return obj!;
    }

    public async System.Threading.Tasks.Task ReconfigureScheduledTask(ScheduledTaskSpec spec)
    {
        await this.Session.VimClient.ReconfigureScheduledTask(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task RemoveScheduledTask()
    {
        await this.Session.VimClient.RemoveScheduledTask(this.VimReference);
    }

    public async System.Threading.Tasks.Task RunScheduledTask()
    {
        await this.Session.VimClient.RunScheduledTask(this.VimReference);
    }
}

public partial class ScheduledTaskManager : ManagedObject
{
    protected ScheduledTaskManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ScheduledTaskDescription> GetPropertyDescription()
    {
        var obj = await this.GetProperty<ScheduledTaskDescription>("description");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]?> GetPropertyScheduledTask()
    {
        var scheduledTask = await this.GetProperty<ManagedObjectReference[]>("scheduledTask");
        return scheduledTask?
            .Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ScheduledTask?> CreateObjectScheduledTask(ManagedObject obj, ScheduledTaskSpec spec)
    {
        var res = await this.Session.VimClient.CreateObjectScheduledTask(this.VimReference, obj.VimReference, spec);
        return ManagedObject.Create<ScheduledTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ScheduledTask?> CreateScheduledTask(ManagedEntity entity, ScheduledTaskSpec spec)
    {
        var res = await this.Session.VimClient.CreateScheduledTask(this.VimReference, entity.VimReference, spec);
        return ManagedObject.Create<ScheduledTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]?> RetrieveEntityScheduledTask(ManagedEntity? entity)
    {
        var res = await this.Session.VimClient.RetrieveEntityScheduledTask(this.VimReference, entity?.VimReference);
        return res?.Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]?> RetrieveObjectScheduledTask(ManagedObject? obj)
    {
        var res = await this.Session.VimClient.RetrieveObjectScheduledTask(this.VimReference, obj?.VimReference);
        return res?.Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session)!).ToArray();
    }
}

public partial class SearchIndex : ManagedObject
{
    protected SearchIndex(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> FindAllByDnsName(Datacenter? datacenter, string dnsName, bool vmSearch)
    {
        var res = await this.Session.VimClient.FindAllByDnsName(this.VimReference, datacenter?.VimReference, dnsName, vmSearch);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> FindAllByIp(Datacenter? datacenter, string ip, bool vmSearch)
    {
        var res = await this.Session.VimClient.FindAllByIp(this.VimReference, datacenter?.VimReference, ip, vmSearch);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> FindAllByUuid(Datacenter? datacenter, string uuid, bool vmSearch, bool? instanceUuid)
    {
        var res = await this.Session.VimClient.FindAllByUuid(this.VimReference, datacenter?.VimReference, uuid, vmSearch, instanceUuid ?? default, instanceUuid.HasValue);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachine?> FindByDatastorePath(Datacenter datacenter, string path)
    {
        var res = await this.Session.VimClient.FindByDatastorePath(this.VimReference, datacenter.VimReference, path);
        return ManagedObject.Create<VirtualMachine>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByDnsName(Datacenter? datacenter, string dnsName, bool vmSearch)
    {
        var res = await this.Session.VimClient.FindByDnsName(this.VimReference, datacenter?.VimReference, dnsName, vmSearch);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByInventoryPath(string inventoryPath)
    {
        var res = await this.Session.VimClient.FindByInventoryPath(this.VimReference, inventoryPath);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByIp(Datacenter? datacenter, string ip, bool vmSearch)
    {
        var res = await this.Session.VimClient.FindByIp(this.VimReference, datacenter?.VimReference, ip, vmSearch);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByUuid(Datacenter? datacenter, string uuid, bool vmSearch, bool? instanceUuid)
    {
        var res = await this.Session.VimClient.FindByUuid(this.VimReference, datacenter?.VimReference, uuid, vmSearch, instanceUuid ?? default, instanceUuid.HasValue);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindChild(ManagedEntity entity, string name)
    {
        var res = await this.Session.VimClient.FindChild(this.VimReference, entity.VimReference, name);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }
}

public partial class ServiceInstance : ManagedObject
{
    protected ServiceInstance(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Capability> GetPropertyCapability()
    {
        var obj = await this.GetProperty<Capability>("capability");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ServiceContent> GetPropertyContent()
    {
        var obj = await this.GetProperty<ServiceContent>("content");
        return obj!;
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyServerClock()
    {
        var obj = await this.GetProperty<DateTime>("serverClock");
        return obj!;
    }

    public async System.Threading.Tasks.Task<DateTime> CurrentTime()
    {
        return await this.Session.VimClient.CurrentTime(this.VimReference);
    }

    public async System.Threading.Tasks.Task<HostVMotionCompatibility[]?> QueryVMotionCompatibility(VirtualMachine vm, HostSystem[] host, string[]? compatibility)
    {
        return await this.Session.VimClient.QueryVMotionCompatibility(this.VimReference, vm.VimReference, host.Select(m => m.VimReference).ToArray(), compatibility);
    }

    public async System.Threading.Tasks.Task<ProductComponentInfo[]?> RetrieveProductComponents()
    {
        return await this.Session.VimClient.RetrieveProductComponents(this.VimReference);
    }

    public async System.Threading.Tasks.Task<ServiceContent?> RetrieveServiceContent()
    {
        return await this.Session.VimClient.RetrieveServiceContent(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Event[]?> ValidateMigration(VirtualMachine[] vm, VirtualMachinePowerState? state, string[]? testType, ResourcePool? pool, HostSystem? host)
    {
        return await this.Session.VimClient.ValidateMigration(this.VimReference, vm.Select(m => m.VimReference).ToArray(), state ?? default, state.HasValue, testType, pool?.VimReference, host?.VimReference);
    }
}

public partial class ServiceManager : ManagedObject
{
    protected ServiceManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo[]?> GetPropertyService()
    {
        var obj = await this.GetProperty<ServiceManagerServiceInfo[]>("service");
        return obj;
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo[]?> QueryServiceList(string? serviceName, string[]? location)
    {
        return await this.Session.VimClient.QueryServiceList(this.VimReference, serviceName, location);
    }
}

public partial class SessionManager : ManagedObject
{
    protected SessionManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<UserSession?> GetPropertyCurrentSession()
    {
        var obj = await this.GetProperty<UserSession>("currentSession");
        return obj;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyDefaultLocale()
    {
        var obj = await this.GetProperty<string>("defaultLocale");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyMessage()
    {
        var obj = await this.GetProperty<string>("message");
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyMessageLocaleList()
    {
        var obj = await this.GetProperty<string[]>("messageLocaleList");
        return obj;
    }

    public async System.Threading.Tasks.Task<UserSession[]?> GetPropertySessionList()
    {
        var obj = await this.GetProperty<UserSession[]>("sessionList");
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertySupportedLocaleList()
    {
        var obj = await this.GetProperty<string[]>("supportedLocaleList");
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> AcquireCloneTicket()
    {
        return await this.Session.VimClient.AcquireCloneTicket(this.VimReference);
    }

    public async System.Threading.Tasks.Task<SessionManagerGenericServiceTicket?> AcquireGenericServiceTicket(SessionManagerServiceRequestSpec spec)
    {
        return await this.Session.VimClient.AcquireGenericServiceTicket(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task<SessionManagerLocalTicket?> AcquireLocalTicket(string userName)
    {
        return await this.Session.VimClient.AcquireLocalTicket(this.VimReference, userName);
    }

    public async System.Threading.Tasks.Task<UserSession?> CloneSession(string cloneTicket)
    {
        return await this.Session.VimClient.CloneSession(this.VimReference, cloneTicket);
    }

    public async System.Threading.Tasks.Task<UserSession?> ImpersonateUser(string userName, string? locale)
    {
        return await this.Session.VimClient.ImpersonateUser(this.VimReference, userName, locale);
    }

    public async System.Threading.Tasks.Task<UserSession?> Login(string userName, string password, string? locale)
    {
        return await this.Session.VimClient.Login(this.VimReference, userName, password, locale);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginBySSPI(string base64Token, string? locale)
    {
        return await this.Session.VimClient.LoginBySSPI(this.VimReference, base64Token, locale);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginByToken(string? locale)
    {
        return await this.Session.VimClient.LoginByToken(this.VimReference, locale);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginExtensionByCertificate(string extensionKey, string? locale)
    {
        return await this.Session.VimClient.LoginExtensionByCertificate(this.VimReference, extensionKey, locale);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginExtensionBySubjectName(string extensionKey, string? locale)
    {
        return await this.Session.VimClient.LoginExtensionBySubjectName(this.VimReference, extensionKey, locale);
    }

    public async System.Threading.Tasks.Task Logout()
    {
        await this.Session.VimClient.Logout(this.VimReference);
    }

    public async System.Threading.Tasks.Task<bool> SessionIsActive(string sessionID, string userName)
    {
        return await this.Session.VimClient.SessionIsActive(this.VimReference, sessionID, userName);
    }

    public async System.Threading.Tasks.Task SetLocale(string locale)
    {
        await this.Session.VimClient.SetLocale(this.VimReference, locale);
    }

    public async System.Threading.Tasks.Task TerminateSession(string[] sessionId)
    {
        await this.Session.VimClient.TerminateSession(this.VimReference, sessionId);
    }

    public async System.Threading.Tasks.Task UpdateServiceMessage(string message)
    {
        await this.Session.VimClient.UpdateServiceMessage(this.VimReference, message);
    }
}

public partial class SimpleCommand : ManagedObject
{
    protected SimpleCommand(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string> GetPropertyEncodingType()
    {
        var obj = await this.GetProperty<string>("encodingType");
        return obj!;
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo> GetPropertyEntity()
    {
        var obj = await this.GetProperty<ServiceManagerServiceInfo>("entity");
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> ExecuteSimpleCommand(string[]? arguments)
    {
        return await this.Session.VimClient.ExecuteSimpleCommand(this.VimReference, arguments);
    }
}

public partial class SiteInfoManager : ManagedObject
{
    protected SiteInfoManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<SiteInfo?> GetSiteInfo()
    {
        return await this.Session.VimClient.GetSiteInfo(this.VimReference);
    }
}

public partial class StoragePod : Folder
{
    protected StoragePod(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PodStorageDrsEntry?> GetPropertyPodStorageDrsEntry()
    {
        var obj = await this.GetProperty<PodStorageDrsEntry>("podStorageDrsEntry");
        return obj;
    }

    public async System.Threading.Tasks.Task<StoragePodSummary?> GetPropertySummary()
    {
        var obj = await this.GetProperty<StoragePodSummary>("summary");
        return obj;
    }
}

public partial class StorageQueryManager : ManagedObject
{
    protected StorageQueryManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryHostsWithAttachedLun(string lunUuid)
    {
        var res = await this.Session.VimClient.QueryHostsWithAttachedLun(this.VimReference, lunUuid);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }
}

public partial class StorageResourceManager : ManagedObject
{
    protected StorageResourceManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> ApplyStorageDrsRecommendation_Task(string[] key)
    {
        var res = await this.Session.VimClient.ApplyStorageDrsRecommendation_Task(this.VimReference, key);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ApplyStorageDrsRecommendationToPod_Task(StoragePod pod, string key)
    {
        var res = await this.Session.VimClient.ApplyStorageDrsRecommendationToPod_Task(this.VimReference, pod.VimReference, key);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CancelStorageDrsRecommendation(string[] key)
    {
        await this.Session.VimClient.CancelStorageDrsRecommendation(this.VimReference, key);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureDatastoreIORM_Task(Datastore datastore, StorageIORMConfigSpec spec)
    {
        var res = await this.Session.VimClient.ConfigureDatastoreIORM_Task(this.VimReference, datastore.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureStorageDrsForPod_Task(StoragePod pod, StorageDrsConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ConfigureStorageDrsForPod_Task(this.VimReference, pod.VimReference, spec, modify);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<StoragePerformanceSummary[]?> QueryDatastorePerformanceSummary(Datastore datastore)
    {
        return await this.Session.VimClient.QueryDatastorePerformanceSummary(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<StorageIORMConfigOption?> QueryIORMConfigOption(HostSystem host)
    {
        return await this.Session.VimClient.QueryIORMConfigOption(this.VimReference, host.VimReference);
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult?> RecommendDatastores(StoragePlacementSpec storageSpec)
    {
        return await this.Session.VimClient.RecommendDatastores(this.VimReference, storageSpec);
    }

    public async System.Threading.Tasks.Task RefreshStorageDrsRecommendation(StoragePod pod)
    {
        await this.Session.VimClient.RefreshStorageDrsRecommendation(this.VimReference, pod.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> RefreshStorageDrsRecommendationsForPod_Task(StoragePod pod)
    {
        var res = await this.Session.VimClient.RefreshStorageDrsRecommendationsForPod_Task(this.VimReference, pod.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault?> ValidateStoragePodConfig(StoragePod pod, StorageDrsConfigSpec spec)
    {
        return await this.Session.VimClient.ValidateStoragePodConfig(this.VimReference, pod.VimReference, spec);
    }
}

public partial class Task : ExtensibleManagedObject
{
    protected Task(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<TaskInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<TaskInfo>("info");
        return obj!;
    }

    public async System.Threading.Tasks.Task CancelTask()
    {
        await this.Session.VimClient.CancelTask(this.VimReference);
    }

    public async System.Threading.Tasks.Task SetTaskDescription(LocalizableMessage description)
    {
        await this.Session.VimClient.SetTaskDescription(this.VimReference, description);
    }

    public async System.Threading.Tasks.Task SetTaskState(TaskInfoState state, object? result, LocalizedMethodFault? fault)
    {
        await this.Session.VimClient.SetTaskState(this.VimReference, state, result, fault);
    }

    public async System.Threading.Tasks.Task UpdateProgress(int percentDone)
    {
        await this.Session.VimClient.UpdateProgress(this.VimReference, percentDone);
    }
}

public partial class TaskHistoryCollector : HistoryCollector
{
    protected TaskHistoryCollector(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> GetPropertyLatestPage()
    {
        var obj = await this.GetProperty<TaskInfo[]>("latestPage");
        return obj;
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadNextTasks(int maxCount)
    {
        return await this.Session.VimClient.ReadNextTasks(this.VimReference, maxCount);
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadPreviousTasks(int maxCount)
    {
        return await this.Session.VimClient.ReadPreviousTasks(this.VimReference, maxCount);
    }
}

public partial class TaskManager : ManagedObject
{
    protected TaskManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<TaskDescription> GetPropertyDescription()
    {
        var obj = await this.GetProperty<TaskDescription>("description");
        return obj!;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyMaxCollector()
    {
        var obj = await this.GetProperty<int>("maxCollector");
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task[]?> GetPropertyRecentTask()
    {
        var recentTask = await this.GetProperty<ManagedObjectReference[]>("recentTask");
        return recentTask?
            .Select(r => ManagedObject.Create<Task>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<TaskHistoryCollector?> CreateCollectorForTasks(TaskFilterSpec filter)
    {
        var res = await this.Session.VimClient.CreateCollectorForTasks(this.VimReference, filter);
        return ManagedObject.Create<TaskHistoryCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<TaskInfo?> CreateTask(ManagedObject obj, string taskTypeId, string? initiatedBy, bool cancelable, string? parentTaskKey, string? activationId)
    {
        return await this.Session.VimClient.CreateTask(this.VimReference, obj.VimReference, taskTypeId, initiatedBy, cancelable, parentTaskKey, activationId);
    }
}

public partial class TenantTenantManager : ManagedObject
{
    protected TenantTenantManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task MarkServiceProviderEntities(ManagedEntity[]? entity)
    {
        await this.Session.VimClient.MarkServiceProviderEntities(this.VimReference, entity?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> RetrieveServiceProviderEntities()
    {
        var res = await this.Session.VimClient.RetrieveServiceProviderEntities(this.VimReference);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task UnmarkServiceProviderEntities(ManagedEntity[]? entity)
    {
        await this.Session.VimClient.UnmarkServiceProviderEntities(this.VimReference, entity?.Select(m => m.VimReference).ToArray());
    }
}

public partial class UserDirectory : ManagedObject
{
    protected UserDirectory(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyDomainList()
    {
        var obj = await this.GetProperty<string[]>("domainList");
        return obj;
    }

    public async System.Threading.Tasks.Task<UserSearchResult[]?> RetrieveUserGroups(string? domain, string searchStr, string? belongsToGroup, string? belongsToUser, bool exactMatch, bool findUsers, bool findGroups)
    {
        return await this.Session.VimClient.RetrieveUserGroups(this.VimReference, domain, searchStr, belongsToGroup, belongsToUser, exactMatch, findUsers, findGroups);
    }
}

public partial class VcenterVStorageObjectManager : VStorageObjectManagerBase
{
    protected VcenterVStorageObjectManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task AttachTagToVStorageObject(ID id, string category, string tag)
    {
        await this.Session.VimClient.AttachTagToVStorageObject(this.VimReference, id, category, tag);
    }

    public async System.Threading.Tasks.Task ClearVStorageObjectControlFlags(ID id, Datastore datastore, string[]? controlFlags)
    {
        await this.Session.VimClient.ClearVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task?> CloneVStorageObject_Task(ID id, Datastore datastore, VslmCloneSpec spec)
    {
        var res = await this.Session.VimClient.CloneVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDisk_Task(VslmCreateSpec spec)
    {
        var res = await this.Session.VimClient.CreateDisk_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDiskFromSnapshot_Task(ID id, Datastore datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path)
    {
        var res = await this.Session.VimClient.CreateDiskFromSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId, name, profile, crypto, path);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteSnapshot_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.DeleteSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteVStorageObject_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.DeleteVStorageObject_Task(this.VimReference, id, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteVStorageObjectEx_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.DeleteVStorageObjectEx_Task(this.VimReference, id, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DetachTagFromVStorageObject(ID id, string category, string tag)
    {
        await this.Session.VimClient.DetachTagFromVStorageObject(this.VimReference, id, category, tag);
    }

    public async System.Threading.Tasks.Task<Task?> ExtendDisk_Task(ID id, Datastore datastore, long newCapacityInMB)
    {
        var res = await this.Session.VimClient.ExtendDisk_Task(this.VimReference, id, datastore.VimReference, newCapacityInMB);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InflateDisk_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.InflateDisk_Task(this.VimReference, id, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTagEntry[]?> ListTagsAttachedToVStorageObject(ID id)
    {
        return await this.Session.VimClient.ListTagsAttachedToVStorageObject(this.VimReference, id);
    }

    public async System.Threading.Tasks.Task<ID[]?> ListVStorageObject(Datastore datastore)
    {
        return await this.Session.VimClient.ListVStorageObject(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<ID[]?> ListVStorageObjectsAttachedToTag(string category, string tag)
    {
        return await this.Session.VimClient.ListVStorageObjectsAttachedToTag(this.VimReference, category, tag);
    }

    public async System.Threading.Tasks.Task<Task?> ReconcileDatastoreInventory_Task(Datastore datastore)
    {
        var res = await this.Session.VimClient.ReconcileDatastoreInventory_Task(this.VimReference, datastore.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> RegisterDisk(string path, string? name)
    {
        return await this.Session.VimClient.RegisterDisk(this.VimReference, path, name);
    }

    public async System.Threading.Tasks.Task<Task?> RelocateVStorageObject_Task(ID id, Datastore datastore, VslmRelocateSpec spec)
    {
        var res = await this.Session.VimClient.RelocateVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RenameVStorageObject(ID id, Datastore datastore, string name)
    {
        await this.Session.VimClient.RenameVStorageObject(this.VimReference, id, datastore.VimReference, name);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotDetails?> RetrieveSnapshotDetails(ID id, Datastore datastore, ID snapshotId)
    {
        return await this.Session.VimClient.RetrieveSnapshotDetails(this.VimReference, id, datastore.VimReference, snapshotId);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> RetrieveSnapshotInfo(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.RetrieveSnapshotInfo(this.VimReference, id, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> RetrieveVStorageInfrastructureObjectPolicy(Datastore datastore)
    {
        return await this.Session.VimClient.RetrieveVStorageInfrastructureObjectPolicy(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> RetrieveVStorageObject(ID id, Datastore datastore, string[]? diskInfoFlags)
    {
        return await this.Session.VimClient.RetrieveVStorageObject(this.VimReference, id, datastore.VimReference, diskInfoFlags);
    }

    public async System.Threading.Tasks.Task<VStorageObjectAssociations[]?> RetrieveVStorageObjectAssociations(RetrieveVStorageObjSpec[]? ids)
    {
        return await this.Session.VimClient.RetrieveVStorageObjectAssociations(this.VimReference, ids);
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> RetrieveVStorageObjectState(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.RetrieveVStorageObjectState(this.VimReference, id, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> RevertVStorageObject_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.RevertVStorageObject_Task(this.VimReference, id, datastore.VimReference, snapshotId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ScheduleReconcileDatastoreInventory(Datastore datastore)
    {
        await this.Session.VimClient.ScheduleReconcileDatastoreInventory(this.VimReference, datastore.VimReference);
    }

    public async System.Threading.Tasks.Task SetVStorageObjectControlFlags(ID id, Datastore datastore, string[]? controlFlags)
    {
        await this.Session.VimClient.SetVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVStorageInfrastructureObjectPolicy_Task(vslmInfrastructureObjectPolicySpec spec)
    {
        var res = await this.Session.VimClient.UpdateVStorageInfrastructureObjectPolicy_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVStorageObjectCrypto_Task(ID id, Datastore datastore, VirtualMachineProfileSpec[]? profile, DiskCryptoSpec? disksCrypto)
    {
        var res = await this.Session.VimClient.UpdateVStorageObjectCrypto_Task(this.VimReference, id, datastore.VimReference, profile, disksCrypto);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVStorageObjectPolicy_Task(ID id, Datastore datastore, VirtualMachineProfileSpec[]? profile)
    {
        var res = await this.Session.VimClient.UpdateVStorageObjectPolicy_Task(this.VimReference, id, datastore.VimReference, profile);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VCenterUpdateVStorageObjectMetadataEx_Task(ID id, Datastore datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var res = await this.Session.VimClient.VCenterUpdateVStorageObjectMetadataEx_Task(this.VimReference, id, datastore.VimReference, metadata, deleteKeys);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VStorageObjectCreateSnapshot_Task(ID id, Datastore datastore, string description)
    {
        var res = await this.Session.VimClient.VStorageObjectCreateSnapshot_Task(this.VimReference, id, datastore.VimReference, description);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> VstorageObjectVCenterQueryChangedDiskAreas(ID id, Datastore datastore, ID snapshotId, long startOffset, string changeId)
    {
        return await this.Session.VimClient.VstorageObjectVCenterQueryChangedDiskAreas(this.VimReference, id, datastore.VimReference, snapshotId, startOffset, changeId);
    }
}

public partial class View : ManagedObject
{
    protected View(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task DestroyView()
    {
        await this.Session.VimClient.DestroyView(this.VimReference);
    }
}

public partial class ViewManager : ManagedObject
{
    protected ViewManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<View[]?> GetPropertyViewList()
    {
        var viewList = await this.GetProperty<ManagedObjectReference[]>("viewList");
        return viewList?
            .Select(r => ManagedObject.Create<View>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ContainerView?> CreateContainerView(ManagedEntity container, string[]? type, bool recursive)
    {
        var res = await this.Session.VimClient.CreateContainerView(this.VimReference, container.VimReference, type, recursive);
        return ManagedObject.Create<ContainerView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<InventoryView?> CreateInventoryView()
    {
        var res = await this.Session.VimClient.CreateInventoryView(this.VimReference);
        return ManagedObject.Create<InventoryView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ListView?> CreateListView(ManagedObject[]? obj)
    {
        var res = await this.Session.VimClient.CreateListView(this.VimReference, obj?.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<ListView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ListView?> CreateListViewFromView(View view)
    {
        var res = await this.Session.VimClient.CreateListViewFromView(this.VimReference, view.VimReference);
        return ManagedObject.Create<ListView>(res, this.Session);
    }
}

public partial class VirtualApp : ResourcePool
{
    protected VirtualApp(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<VirtualAppLinkInfo[]?> GetPropertyChildLink()
    {
        var obj = await this.GetProperty<VirtualAppLinkInfo[]>("childLink");
        return obj;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore?
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network?
            .Select(r => ManagedObject.Create<Network>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Folder?> GetPropertyParentFolder()
    {
        var parentFolder = await this.GetProperty<ManagedObjectReference>("parentFolder");
        return ManagedObject.Create<Folder>(parentFolder, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> GetPropertyParentVApp()
    {
        var parentVApp = await this.GetProperty<ManagedObjectReference>("parentVApp");
        return ManagedObject.Create<ManagedEntity>(parentVApp, this.Session);
    }

    public async System.Threading.Tasks.Task<VAppConfigInfo?> GetPropertyVAppConfig()
    {
        var obj = await this.GetProperty<VAppConfigInfo>("vAppConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> CloneVApp_Task(string name, ResourcePool target, VAppCloneSpec spec)
    {
        var res = await this.Session.VimClient.CloneVApp_Task(this.VimReference, name, target.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ExportVApp()
    {
        var res = await this.Session.VimClient.ExportVApp(this.VimReference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOffVApp_Task(bool force)
    {
        var res = await this.Session.VimClient.PowerOffVApp_Task(this.VimReference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOnVApp_Task()
    {
        var res = await this.Session.VimClient.PowerOnVApp_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SuspendVApp_Task()
    {
        var res = await this.Session.VimClient.SuspendVApp_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnregisterVApp_Task()
    {
        var res = await this.Session.VimClient.UnregisterVApp_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateLinkedChildren(VirtualAppLinkInfo[]? addChangeSet, ManagedEntity[]? removeSet)
    {
        await this.Session.VimClient.UpdateLinkedChildren(this.VimReference, addChangeSet, removeSet?.Select(m => m.VimReference).ToArray());
    }

    public async System.Threading.Tasks.Task UpdateVAppConfig(VAppConfigSpec spec)
    {
        await this.Session.VimClient.UpdateVAppConfig(this.VimReference, spec);
    }
}

public partial class VirtualDiskManager : ManagedObject
{
    protected VirtualDiskManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> CopyVirtualDisk_Task(string sourceName, Datacenter? sourceDatacenter, string destName, Datacenter? destDatacenter, VirtualDiskSpec? destSpec, bool? force)
    {
        var res = await this.Session.VimClient.CopyVirtualDisk_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destName, destDatacenter?.VimReference, destSpec, force ?? default, force.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateVirtualDisk_Task(string name, Datacenter? datacenter, VirtualDiskSpec spec)
    {
        var res = await this.Session.VimClient.CreateVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DefragmentVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.DefragmentVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.DeleteVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> EagerZeroVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.EagerZeroVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ExtendVirtualDisk_Task(string name, Datacenter? datacenter, long newCapacityKb, bool? eagerZero)
    {
        var res = await this.Session.VimClient.ExtendVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference, newCapacityKb, eagerZero ?? default, eagerZero.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ImportUnmanagedSnapshot(string vdisk, Datacenter? datacenter, string vvolId)
    {
        await this.Session.VimClient.ImportUnmanagedSnapshot(this.VimReference, vdisk, datacenter?.VimReference, vvolId);
    }

    public async System.Threading.Tasks.Task<Task?> InflateVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.InflateVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveVirtualDisk_Task(string sourceName, Datacenter? sourceDatacenter, string destName, Datacenter? destDatacenter, bool? force, VirtualMachineProfileSpec[]? profile)
    {
        var res = await this.Session.VimClient.MoveVirtualDisk_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destName, destDatacenter?.VimReference, force ?? default, force.HasValue, profile);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int> QueryVirtualDiskFragmentation(string name, Datacenter? datacenter)
    {
        return await this.Session.VimClient.QueryVirtualDiskFragmentation(this.VimReference, name, datacenter?.VimReference);
    }

    public async System.Threading.Tasks.Task<HostDiskDimensionsChs?> QueryVirtualDiskGeometry(string name, Datacenter? datacenter)
    {
        return await this.Session.VimClient.QueryVirtualDiskGeometry(this.VimReference, name, datacenter?.VimReference);
    }

    public async System.Threading.Tasks.Task<string?> QueryVirtualDiskUuid(string name, Datacenter? datacenter)
    {
        return await this.Session.VimClient.QueryVirtualDiskUuid(this.VimReference, name, datacenter?.VimReference);
    }

    public async System.Threading.Tasks.Task ReleaseManagedSnapshot(string vdisk, Datacenter? datacenter)
    {
        await this.Session.VimClient.ReleaseManagedSnapshot(this.VimReference, vdisk, datacenter?.VimReference);
    }

    public async System.Threading.Tasks.Task SetVirtualDiskUuid(string name, Datacenter? datacenter, string uuid)
    {
        await this.Session.VimClient.SetVirtualDiskUuid(this.VimReference, name, datacenter?.VimReference, uuid);
    }

    public async System.Threading.Tasks.Task<Task?> ShrinkVirtualDisk_Task(string name, Datacenter? datacenter, bool? copy)
    {
        var res = await this.Session.VimClient.ShrinkVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference, copy ?? default, copy.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ZeroFillVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.ZeroFillVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class VirtualizationManager : ManagedObject
{
    protected VirtualizationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class VirtualMachine : ManagedEntity
{
    protected VirtualMachine(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<VirtualMachineCapability> GetPropertyCapability()
    {
        var obj = await this.GetProperty<VirtualMachineCapability>("capability");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigInfo?> GetPropertyConfig()
    {
        var obj = await this.GetProperty<VirtualMachineConfigInfo>("config");
        return obj;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore?
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<EnvironmentBrowser> GetPropertyEnvironmentBrowser()
    {
        var environmentBrowser = await this.GetProperty<ManagedObjectReference>("environmentBrowser");
        return ManagedObject.Create<EnvironmentBrowser>(environmentBrowser, this.Session)!;
    }

    public async System.Threading.Tasks.Task<GuestInfo?> GetPropertyGuest()
    {
        var obj = await this.GetProperty<GuestInfo>("guest");
        return obj;
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyGuestHeartbeatStatus()
    {
        var obj = await this.GetProperty<ManagedEntityStatus>("guestHeartbeatStatus");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineFileLayout?> GetPropertyLayout()
    {
        var obj = await this.GetProperty<VirtualMachineFileLayout>("layout");
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineFileLayoutEx?> GetPropertyLayoutEx()
    {
        var obj = await this.GetProperty<VirtualMachineFileLayoutEx>("layoutEx");
        return obj;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network?
            .Select(r => ManagedObject.Create<Network>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> GetPropertyParentVApp()
    {
        var parentVApp = await this.GetProperty<ManagedObjectReference>("parentVApp");
        return ManagedObject.Create<ManagedEntity>(parentVApp, this.Session);
    }

    public async System.Threading.Tasks.Task<ResourceConfigSpec?> GetPropertyResourceConfig()
    {
        var obj = await this.GetProperty<ResourceConfigSpec>("resourceConfig");
        return obj;
    }

    public async System.Threading.Tasks.Task<ResourcePool?> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference>("resourcePool");
        return ManagedObject.Create<ResourcePool>(resourcePool, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualMachineSnapshot[]?> GetPropertyRootSnapshot()
    {
        var rootSnapshot = await this.GetProperty<ManagedObjectReference[]>("rootSnapshot");
        return rootSnapshot?
            .Select(r => ManagedObject.Create<VirtualMachineSnapshot>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachineRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<VirtualMachineRuntimeInfo>("runtime");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineSnapshotInfo?> GetPropertySnapshot()
    {
        var obj = await this.GetProperty<VirtualMachineSnapshotInfo>("snapshot");
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineStorageInfo?> GetPropertyStorage()
    {
        var obj = await this.GetProperty<VirtualMachineStorageInfo>("storage");
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<VirtualMachineSummary>("summary");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineMksTicket?> AcquireMksTicket()
    {
        return await this.Session.VimClient.AcquireMksTicket(this.VimReference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineTicket?> AcquireTicket(string ticketType)
    {
        return await this.Session.VimClient.AcquireTicket(this.VimReference, ticketType);
    }

    public async System.Threading.Tasks.Task AnswerVM(string questionId, string answerChoice)
    {
        await this.Session.VimClient.AnswerVM(this.VimReference, questionId, answerChoice);
    }

    public async System.Threading.Tasks.Task<Task?> ApplyEvcModeVM_Task(HostFeatureMask[]? mask, bool? completeMasks)
    {
        var res = await this.Session.VimClient.ApplyEvcModeVM_Task(this.VimReference, mask, completeMasks ?? default, completeMasks.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> AttachDisk_Task(ID diskId, Datastore datastore, int? controllerKey, int? unitNumber)
    {
        var res = await this.Session.VimClient.AttachDisk_Task(this.VimReference, diskId, datastore.VimReference, controllerKey ?? default, controllerKey.HasValue, unitNumber ?? default, unitNumber.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CheckCustomizationSpec(CustomizationSpec spec)
    {
        await this.Session.VimClient.CheckCustomizationSpec(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task<Task?> CloneVM_Task(Folder folder, string name, VirtualMachineCloneSpec spec)
    {
        var res = await this.Session.VimClient.CloneVM_Task(this.VimReference, folder.VimReference, name, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ConsolidateVMDisks_Task()
    {
        var res = await this.Session.VimClient.ConsolidateVMDisks_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateScreenshot_Task()
    {
        var res = await this.Session.VimClient.CreateScreenshot_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSecondaryVM_Task(HostSystem? host)
    {
        var res = await this.Session.VimClient.CreateSecondaryVM_Task(this.VimReference, host?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSecondaryVMEx_Task(HostSystem? host, FaultToleranceConfigSpec? spec)
    {
        var res = await this.Session.VimClient.CreateSecondaryVMEx_Task(this.VimReference, host?.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSnapshot_Task(string name, string? description, bool memory, bool quiesce)
    {
        var res = await this.Session.VimClient.CreateSnapshot_Task(this.VimReference, name, description, memory, quiesce);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSnapshotEx_Task(string name, string? description, bool memory, VirtualMachineGuestQuiesceSpec? quiesceSpec)
    {
        var res = await this.Session.VimClient.CreateSnapshotEx_Task(this.VimReference, name, description, memory, quiesceSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CryptoUnlock_Task()
    {
        var res = await this.Session.VimClient.CryptoUnlock_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CustomizeVM_Task(CustomizationSpec spec)
    {
        var res = await this.Session.VimClient.CustomizeVM_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DefragmentAllDisks()
    {
        await this.Session.VimClient.DefragmentAllDisks(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> DetachDisk_Task(ID diskId)
    {
        var res = await this.Session.VimClient.DetachDisk_Task(this.VimReference, diskId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DisableSecondaryVM_Task(VirtualMachine vm)
    {
        var res = await this.Session.VimClient.DisableSecondaryVM_Task(this.VimReference, vm.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<bool> DropConnections(VirtualMachineConnection[]? listOfConnections)
    {
        return await this.Session.VimClient.DropConnections(this.VimReference, listOfConnections);
    }

    public async System.Threading.Tasks.Task<Task?> EnableSecondaryVM_Task(VirtualMachine vm, HostSystem? host)
    {
        var res = await this.Session.VimClient.EnableSecondaryVM_Task(this.VimReference, vm.VimReference, host?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> EstimateStorageForConsolidateSnapshots_Task()
    {
        var res = await this.Session.VimClient.EstimateStorageForConsolidateSnapshots_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ExportVm()
    {
        var res = await this.Session.VimClient.ExportVm(this.VimReference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string?> ExtractOvfEnvironment()
    {
        return await this.Session.VimClient.ExtractOvfEnvironment(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> InstantClone_Task(VirtualMachineInstantCloneSpec spec)
    {
        var res = await this.Session.VimClient.InstantClone_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MakePrimaryVM_Task(VirtualMachine vm)
    {
        var res = await this.Session.VimClient.MakePrimaryVM_Task(this.VimReference, vm.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MarkAsTemplate()
    {
        await this.Session.VimClient.MarkAsTemplate(this.VimReference);
    }

    public async System.Threading.Tasks.Task MarkAsVirtualMachine(ResourcePool pool, HostSystem? host)
    {
        await this.Session.VimClient.MarkAsVirtualMachine(this.VimReference, pool.VimReference, host?.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> MigrateVM_Task(ResourcePool? pool, HostSystem? host, VirtualMachineMovePriority priority, VirtualMachinePowerState? state)
    {
        var res = await this.Session.VimClient.MigrateVM_Task(this.VimReference, pool?.VimReference, host?.VimReference, priority, state ?? default, state.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MountToolsInstaller()
    {
        await this.Session.VimClient.MountToolsInstaller(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOffVM_Task()
    {
        var res = await this.Session.VimClient.PowerOffVM_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOnVM_Task(HostSystem? host)
    {
        var res = await this.Session.VimClient.PowerOnVM_Task(this.VimReference, host?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PromoteDisks_Task(bool unlink, VirtualDisk[]? disks)
    {
        var res = await this.Session.VimClient.PromoteDisks_Task(this.VimReference, unlink, disks);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int> PutUsbScanCodes(UsbScanCodeSpec spec)
    {
        return await this.Session.VimClient.PutUsbScanCodes(this.VimReference, spec);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> QueryChangedDiskAreas(VirtualMachineSnapshot? snapshot, int deviceKey, long startOffset, string changeId)
    {
        return await this.Session.VimClient.QueryChangedDiskAreas(this.VimReference, snapshot?.VimReference, deviceKey, startOffset, changeId);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConnection[]?> QueryConnections()
    {
        return await this.Session.VimClient.QueryConnections(this.VimReference);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibility()
    {
        return await this.Session.VimClient.QueryFaultToleranceCompatibility(this.VimReference);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibilityEx(bool? forLegacyFt)
    {
        return await this.Session.VimClient.QueryFaultToleranceCompatibilityEx(this.VimReference, forLegacyFt ?? default, forLegacyFt.HasValue);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryUnownedFiles()
    {
        return await this.Session.VimClient.QueryUnownedFiles(this.VimReference);
    }

    public async System.Threading.Tasks.Task RebootGuest()
    {
        await this.Session.VimClient.RebootGuest(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigVM_Task(VirtualMachineConfigSpec spec)
    {
        var res = await this.Session.VimClient.ReconfigVM_Task(this.VimReference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshStorageInfo()
    {
        await this.Session.VimClient.RefreshStorageInfo(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ReloadVirtualMachineFromPath_Task(string configurationPath)
    {
        var res = await this.Session.VimClient.ReloadVirtualMachineFromPath_Task(this.VimReference, configurationPath);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RelocateVM_Task(VirtualMachineRelocateSpec spec, VirtualMachineMovePriority? priority)
    {
        var res = await this.Session.VimClient.RelocateVM_Task(this.VimReference, spec, priority ?? default, priority.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveAllSnapshots_Task(bool? consolidate)
    {
        var res = await this.Session.VimClient.RemoveAllSnapshots_Task(this.VimReference, consolidate ?? default, consolidate.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ResetGuestInformation()
    {
        await this.Session.VimClient.ResetGuestInformation(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> ResetVM_Task()
    {
        var res = await this.Session.VimClient.ResetVM_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RevertToCurrentSnapshot_Task(HostSystem? host, bool? suppressPowerOn)
    {
        var res = await this.Session.VimClient.RevertToCurrentSnapshot_Task(this.VimReference, host?.VimReference, suppressPowerOn ?? default, suppressPowerOn.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task SendNMI()
    {
        await this.Session.VimClient.SendNMI(this.VimReference);
    }

    public async System.Threading.Tasks.Task SetDisplayTopology(VirtualMachineDisplayTopology[] displays)
    {
        await this.Session.VimClient.SetDisplayTopology(this.VimReference, displays);
    }

    public async System.Threading.Tasks.Task SetScreenResolution(int width, int height)
    {
        await this.Session.VimClient.SetScreenResolution(this.VimReference, width, height);
    }

    public async System.Threading.Tasks.Task ShutdownGuest()
    {
        await this.Session.VimClient.ShutdownGuest(this.VimReference);
    }

    public async System.Threading.Tasks.Task StandbyGuest()
    {
        await this.Session.VimClient.StandbyGuest(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> StartRecording_Task(string name, string? description)
    {
        var res = await this.Session.VimClient.StartRecording_Task(this.VimReference, name, description);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StartReplaying_Task(VirtualMachineSnapshot replaySnapshot)
    {
        var res = await this.Session.VimClient.StartReplaying_Task(this.VimReference, replaySnapshot.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StopRecording_Task()
    {
        var res = await this.Session.VimClient.StopRecording_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StopReplaying_Task()
    {
        var res = await this.Session.VimClient.StopReplaying_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SuspendVM_Task()
    {
        var res = await this.Session.VimClient.SuspendVM_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> TerminateFaultTolerantVM_Task(VirtualMachine? vm)
    {
        var res = await this.Session.VimClient.TerminateFaultTolerantVM_Task(this.VimReference, vm?.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task TerminateVM()
    {
        await this.Session.VimClient.TerminateVM(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> TurnOffFaultToleranceForVM_Task()
    {
        var res = await this.Session.VimClient.TurnOffFaultToleranceForVM_Task(this.VimReference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UnmountToolsInstaller()
    {
        await this.Session.VimClient.UnmountToolsInstaller(this.VimReference);
    }

    public async System.Threading.Tasks.Task UnregisterVM()
    {
        await this.Session.VimClient.UnregisterVM(this.VimReference);
    }

    public async System.Threading.Tasks.Task<Task?> UpgradeTools_Task(string? installerOptions)
    {
        var res = await this.Session.VimClient.UpgradeTools_Task(this.VimReference, installerOptions);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpgradeVM_Task(string? version)
    {
        var res = await this.Session.VimClient.UpgradeVM_Task(this.VimReference, version);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class VirtualMachineCompatibilityChecker : ManagedObject
{
    protected VirtualMachineCompatibilityChecker(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> CheckCompatibility_Task(VirtualMachine vm, HostSystem? host, ResourcePool? pool, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckCompatibility_Task(this.VimReference, vm.VimReference, host?.VimReference, pool?.VimReference, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckPowerOn_Task(VirtualMachine vm, HostSystem? host, ResourcePool? pool, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckPowerOn_Task(this.VimReference, vm.VimReference, host?.VimReference, pool?.VimReference, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckVmConfig_Task(VirtualMachineConfigSpec spec, VirtualMachine? vm, HostSystem? host, ResourcePool? pool, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckVmConfig_Task(this.VimReference, spec, vm?.VimReference, host?.VimReference, pool?.VimReference, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class VirtualMachineGuestCustomizationManager : ManagedObject
{
    protected VirtualMachineGuestCustomizationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> AbortCustomization_Task(VirtualMachine vm, GuestAuthentication auth)
    {
        var res = await this.Session.VimClient.AbortCustomization_Task(this.VimReference, vm.VimReference, auth);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CustomizeGuest_Task(VirtualMachine vm, GuestAuthentication auth, CustomizationSpec spec, OptionValue[]? configParams)
    {
        var res = await this.Session.VimClient.CustomizeGuest_Task(this.VimReference, vm.VimReference, auth, spec, configParams);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StartGuestNetwork_Task(VirtualMachine vm, GuestAuthentication auth)
    {
        var res = await this.Session.VimClient.StartGuestNetwork_Task(this.VimReference, vm.VimReference, auth);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class VirtualMachineProvisioningChecker : ManagedObject
{
    protected VirtualMachineProvisioningChecker(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> CheckClone_Task(VirtualMachine vm, Folder folder, string name, VirtualMachineCloneSpec spec, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckClone_Task(this.VimReference, vm.VimReference, folder.VimReference, name, spec, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckInstantClone_Task(VirtualMachine vm, VirtualMachineInstantCloneSpec spec, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckInstantClone_Task(this.VimReference, vm.VimReference, spec, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckMigrate_Task(VirtualMachine vm, HostSystem? host, ResourcePool? pool, VirtualMachinePowerState? state, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckMigrate_Task(this.VimReference, vm.VimReference, host?.VimReference, pool?.VimReference, state ?? default, state.HasValue, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckRelocate_Task(VirtualMachine vm, VirtualMachineRelocateSpec spec, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckRelocate_Task(this.VimReference, vm.VimReference, spec, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> QueryVMotionCompatibilityEx_Task(VirtualMachine[] vm, HostSystem[] host)
    {
        var res = await this.Session.VimClient.QueryVMotionCompatibilityEx_Task(this.VimReference, vm.Select(m => m.VimReference).ToArray(), host.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class VirtualMachineSnapshot : ExtensibleManagedObject
{
    protected VirtualMachineSnapshot(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<VirtualMachineSnapshot[]?> GetPropertyChildSnapshot()
    {
        var childSnapshot = await this.GetProperty<ManagedObjectReference[]>("childSnapshot");
        return childSnapshot?
            .Select(r => ManagedObject.Create<VirtualMachineSnapshot>(r, this.Session)!)
            .ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<VirtualMachineConfigInfo>("config");
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference>("vm");
        return ManagedObject.Create<VirtualMachine>(vm, this.Session)!;
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ExportSnapshot()
    {
        var res = await this.Session.VimClient.ExportSnapshot(this.VimReference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveSnapshot_Task(bool removeChildren, bool? consolidate)
    {
        var res = await this.Session.VimClient.RemoveSnapshot_Task(this.VimReference, removeChildren, consolidate ?? default, consolidate.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RenameSnapshot(string? name, string? description)
    {
        await this.Session.VimClient.RenameSnapshot(this.VimReference, name, description);
    }

    public async System.Threading.Tasks.Task<Task?> RevertToSnapshot_Task(HostSystem? host, bool? suppressPowerOn)
    {
        var res = await this.Session.VimClient.RevertToSnapshot_Task(this.VimReference, host?.VimReference, suppressPowerOn ?? default, suppressPowerOn.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class VmwareDistributedVirtualSwitch : DistributedVirtualSwitch
{
    protected VmwareDistributedVirtualSwitch(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> UpdateDVSLacpGroupConfig_Task(VMwareDvsLacpGroupSpec[] lacpGroupSpec)
    {
        var res = await this.Session.VimClient.UpdateDVSLacpGroupConfig_Task(this.VimReference, lacpGroupSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

public partial class VsanUpgradeSystem : ManagedObject
{
    protected VsanUpgradeSystem(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<Task?> PerformVsanUpgrade_Task(ClusterComputeResource cluster, bool? performObjectUpgrade, bool? downgradeFormat, bool? allowReducedRedundancy, HostSystem[]? excludeHosts)
    {
        var res = await this.Session.VimClient.PerformVsanUpgrade_Task(this.VimReference, cluster.VimReference, performObjectUpgrade ?? default, performObjectUpgrade.HasValue, downgradeFormat ?? default, downgradeFormat.HasValue, allowReducedRedundancy ?? default, allowReducedRedundancy.HasValue, excludeHosts?.Select(m => m.VimReference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemPreflightCheckResult?> PerformVsanUpgradePreflightCheck(ClusterComputeResource cluster, bool? downgradeFormat)
    {
        return await this.Session.VimClient.PerformVsanUpgradePreflightCheck(this.VimReference, cluster.VimReference, downgradeFormat ?? default, downgradeFormat.HasValue);
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemUpgradeStatus?> QueryVsanUpgradeStatus(ClusterComputeResource cluster)
    {
        return await this.Session.VimClient.QueryVsanUpgradeStatus(this.VimReference, cluster.VimReference);
    }
}

public partial class VStorageObjectManagerBase : ManagedObject
{
    protected VStorageObjectManagerBase(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

#pragma warning restore SA1402 // File may only contain a single type

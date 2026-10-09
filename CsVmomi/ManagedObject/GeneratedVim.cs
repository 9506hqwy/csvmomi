namespace CsVmomi;

#pragma warning disable IDE0058 // Expression value is never used

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
        var obj = await this.GetProperty<AlarmInfo>("info").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task ReconfigureAlarm(AlarmSpec spec)
    {
        await this.Session.VimClient.ReconfigureAlarm(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveAlarm()
    {
        await this.Session.VimClient.RemoveAlarm(this.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<AlarmExpression[]>("defaultExpression").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<AlarmDescription> GetPropertyDescription()
    {
        var obj = await this.GetProperty<AlarmDescription>("description").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task AcknowledgeAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.VimClient.AcknowledgeAlarm(this.VimReference, alarm.VimReference, entity.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> AreAlarmActionsEnabled(ManagedEntity entity)
    {
        return await this.Session.VimClient.AreAlarmActionsEnabled(this.VimReference, entity.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ClearTriggeredAlarms(AlarmFilterSpec filter)
    {
        await this.Session.VimClient.ClearTriggeredAlarms(this.VimReference, filter).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Alarm?> CreateAlarm(ManagedEntity entity, AlarmSpec spec)
    {
        var res = await this.Session.VimClient.CreateAlarm(this.VimReference, entity.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Alarm>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.VimClient.DisableAlarm(this.VimReference, alarm.VimReference, entity.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnableAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.VimClient.EnableAlarm(this.VimReference, alarm.VimReference, entity.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnableAlarmActions(ManagedEntity entity, bool enabled)
    {
        await this.Session.VimClient.EnableAlarmActions(this.VimReference, entity.VimReference, enabled).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Alarm[]?> GetAlarm(ManagedEntity? entity)
    {
        var res = await this.Session.VimClient.GetAlarm(this.VimReference, entity?.VimReference).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<Alarm>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<AlarmState[]?> GetAlarmState(ManagedEntity entity)
    {
        return await this.Session.VimClient.GetAlarmState(this.VimReference, entity.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<AuthorizationDescription>("description").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<AuthorizationPrivilege[]?> GetPropertyPrivilegeList()
    {
        var obj = await this.GetProperty<AuthorizationPrivilege[]>("privilegeList").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<AuthorizationRole[]?> GetPropertyRoleList()
    {
        var obj = await this.GetProperty<AuthorizationRole[]>("roleList").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<int> AddAuthorizationRole(string name, string[]? privIds)
    {
        return await this.Session.VimClient.AddAuthorizationRole(this.VimReference, name, privIds).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserPrivilegeResult[]?> FetchUserPrivilegeOnEntities(ManagedEntity[] entities, string userName)
    {
        return await this.Session.VimClient.FetchUserPrivilegeOnEntities(this.VimReference, [.. entities.Select(m => m.VimReference)], userName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]?> HasPrivilegeOnEntities(ManagedEntity[] entity, string sessionId, string[]? privId)
    {
        return await this.Session.VimClient.HasPrivilegeOnEntities(this.VimReference, [.. entity.Select(m => m.VimReference)], sessionId, privId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool[]?> HasPrivilegeOnEntity(ManagedEntity entity, string sessionId, string[]? privId)
    {
        return await this.Session.VimClient.HasPrivilegeOnEntity(this.VimReference, entity.VimReference, sessionId, privId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]?> HasUserPrivilegeOnEntities(ManagedObject[] entities, string userName, string[]? privId)
    {
        return await this.Session.VimClient.HasUserPrivilegeOnEntities(this.VimReference, [.. entities.Select(m => m.VimReference)], userName, privId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MergePermissions(int srcRoleId, int dstRoleId)
    {
        await this.Session.VimClient.MergePermissions(this.VimReference, srcRoleId, dstRoleId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveAuthorizationRole(int roleId, bool failIfUsed)
    {
        await this.Session.VimClient.RemoveAuthorizationRole(this.VimReference, roleId, failIfUsed).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveEntityPermission(ManagedEntity entity, string user, bool isGroup)
    {
        await this.Session.VimClient.RemoveEntityPermission(this.VimReference, entity.VimReference, user, isGroup).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ResetEntityPermissions(ManagedEntity entity, Permission[]? permission)
    {
        await this.Session.VimClient.ResetEntityPermissions(this.VimReference, entity.VimReference, permission).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveAllPermissions()
    {
        return await this.Session.VimClient.RetrieveAllPermissions(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveEntityPermissions(ManagedEntity entity, bool inherited)
    {
        return await this.Session.VimClient.RetrieveEntityPermissions(this.VimReference, entity.VimReference, inherited).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveRolePermissions(int roleId)
    {
        return await this.Session.VimClient.RetrieveRolePermissions(this.VimReference, roleId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetEntityPermissions(ManagedEntity entity, Permission[]? permission)
    {
        await this.Session.VimClient.SetEntityPermissions(this.VimReference, entity.VimReference, permission).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateAuthorizationRole(int roleId, string newName, string[]? privIds)
    {
        await this.Session.VimClient.UpdateAuthorizationRole(this.VimReference, roleId, newName, privIds).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.CertMgrRefreshCACertificatesAndCRLs_Task(this.VimReference, [.. host.Select(m => m.VimReference)]).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CertMgrRefreshCertificates_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.CertMgrRefreshCertificates_Task(this.VimReference, [.. host.Select(m => m.VimReference)]).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CertMgrRevokeCertificates_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.CertMgrRevokeCertificates_Task(this.VimReference, [.. host.Select(m => m.VimReference)]).ConfigureAwait(false);
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
        var obj = await this.GetProperty<ClusterActionHistory[]>("actionHistory").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterConfigInfo> GetPropertyConfiguration()
    {
        var obj = await this.GetProperty<ClusterConfigInfo>("configuration").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ClusterDrsFaults[]?> GetPropertyDrsFault()
    {
        var obj = await this.GetProperty<ClusterDrsFaults[]>("drsFault").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterDrsRecommendation[]?> GetPropertyDrsRecommendation()
    {
        var obj = await this.GetProperty<ClusterDrsRecommendation[]>("drsRecommendation").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceHCIConfigInfo?> GetPropertyHciConfig()
    {
        var obj = await this.GetProperty<ClusterComputeResourceHCIConfigInfo>("hciConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterDrsMigration[]?> GetPropertyMigrationHistory()
    {
        var obj = await this.GetProperty<ClusterDrsMigration[]>("migrationHistory").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterRecommendation[]?> GetPropertyRecommendation()
    {
        var obj = await this.GetProperty<ClusterRecommendation[]>("recommendation").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceSummary> GetPropertySummaryEx()
    {
        var obj = await this.GetProperty<ClusterComputeResourceSummary>("summaryEx").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task AbandonHciWorkflow()
    {
        await this.Session.VimClient.AbandonHciWorkflow(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> AddHost_Task(HostConnectSpec spec, bool asConnected, ResourcePool? resourcePool, string? license)
    {
        var res = await this.Session.VimClient.AddHost_Task(this.VimReference, spec, asConnected, resourcePool?.VimReference, license).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ApplyRecommendation(string key)
    {
        await this.Session.VimClient.ApplyRecommendation(this.VimReference, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CancelRecommendation(string key)
    {
        await this.Session.VimClient.CancelRecommendation(this.VimReference, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ClusterEnterMaintenanceResult?> ClusterEnterMaintenanceMode(HostSystem[] host, OptionValue[]? option, ClusterComputeResourceMaintenanceInfo? info)
    {
        return await this.Session.VimClient.ClusterEnterMaintenanceMode(this.VimReference, [.. host.Select(m => m.VimReference)], option, info).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureHCI_Task(ClusterComputeResourceHCIConfigSpec clusterSpec, ClusterComputeResourceHostConfigurationInput[]? hostInputs)
    {
        var res = await this.Session.VimClient.ConfigureHCI_Task(this.VimReference, clusterSpec, hostInputs).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterEVCManager?> EvcManager()
    {
        var res = await this.Session.VimClient.EvcManager(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<ClusterEVCManager>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ExtendHCI_Task(ClusterComputeResourceHostConfigurationInput[]? hostInputs, SDDCBase? vSanConfigSpec)
    {
        var res = await this.Session.VimClient.ExtendHCI_Task(this.VimReference, hostInputs, vSanConfigSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterRuleInfo[]?> FindRulesForVm(VirtualMachine vm)
    {
        return await this.Session.VimClient.FindRulesForVm(this.VimReference, vm.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ClusterResourceUsageSummary?> GetResourceUsage()
    {
        return await this.Session.VimClient.GetResourceUsage(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetSystemVMsRestrictedDatastores()
    {
        var res = await this.Session.VimClient.GetSystemVMsRestrictedDatastores(this.VimReference).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Task?> MoveHostInto_Task(HostSystem host, ResourcePool? resourcePool)
    {
        var res = await this.Session.VimClient.MoveHostInto_Task(this.VimReference, host.VimReference, resourcePool?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveInto_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.MoveInto_Task(this.VimReference, [.. host.Select(m => m.VimReference)]).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<PlacementResult?> PlaceVm(PlacementSpec placementSpec)
    {
        return await this.Session.VimClient.PlaceVm(this.VimReference, placementSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ClusterHostRecommendation[]?> RecommendHostsForVm(VirtualMachine vm, ResourcePool? pool)
    {
        return await this.Session.VimClient.RecommendHostsForVm(this.VimReference, vm.VimReference, pool?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureCluster_Task(ClusterConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ReconfigureCluster_Task(this.VimReference, spec, modify).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshRecommendation()
    {
        await this.Session.VimClient.RefreshRecommendation(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ClusterDasAdvancedRuntimeInfo?> RetrieveDasAdvancedRuntimeInfo()
    {
        return await this.Session.VimClient.RetrieveDasAdvancedRuntimeInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetCryptoMode(string cryptoMode, ClusterComputeResourceCryptoModePolicy? policy)
    {
        await this.Session.VimClient.SetCryptoMode(this.VimReference, cryptoMode, policy).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> StampAllRulesWithUuid_Task()
    {
        var res = await this.Session.VimClient.StampAllRulesWithUuid_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceValidationResultBase[]?> ValidateHCIConfiguration(ClusterComputeResourceHCIConfigSpec? hciConfigSpec, HostSystem[]? hosts)
    {
        return await this.Session.VimClient.ValidateHCIConfiguration(this.VimReference, hciConfigSpec, hosts?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
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
        var obj = await this.GetProperty<ClusterEVCManagerEVCState>("evcState").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource> GetPropertyManagedCluster()
    {
        var managedCluster = await this.GetProperty<ManagedObjectReference>("managedCluster").ConfigureAwait(false);
        return ManagedObject.Create<ClusterComputeResource>(managedCluster, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Task?> CheckAddHostEvc_Task(HostConnectSpec cnxSpec)
    {
        var res = await this.Session.VimClient.CheckAddHostEvc_Task(this.VimReference, cnxSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckConfigureEvcMode_Task(string evcModeKey, string? evcGraphicsModeKey)
    {
        var res = await this.Session.VimClient.CheckConfigureEvcMode_Task(this.VimReference, evcModeKey, evcGraphicsModeKey).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureEvcMode_Task(string evcModeKey, string? evcGraphicsModeKey)
    {
        var res = await this.Session.VimClient.ConfigureEvcMode_Task(this.VimReference, evcModeKey, evcGraphicsModeKey).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DisableEvcMode_Task()
    {
        var res = await this.Session.VimClient.DisableEvcMode_Task(this.VimReference).ConfigureAwait(false);
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
        await this.Session.VimClient.UpdateClusterProfile(this.VimReference, config).ConfigureAwait(false);
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
        var obj = await this.GetProperty<bool>("configManagerEnabled").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ComputeResourceConfigInfo> GetPropertyConfigurationEx()
    {
        var obj = await this.GetProperty<ComputeResourceConfigInfo>("configurationEx").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore").ConfigureAwait(false);
        return datastore?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<EnvironmentBrowser?> GetPropertyEnvironmentBrowser()
    {
        var environmentBrowser = await this.GetProperty<ManagedObjectReference>("environmentBrowser").ConfigureAwait(false);
        return ManagedObject.Create<EnvironmentBrowser>(environmentBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> GetPropertyHost()
    {
        var host = await this.GetProperty<ManagedObjectReference[]>("host").ConfigureAwait(false);
        return host?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyLifecycleManaged()
    {
        var obj = await this.GetProperty<bool>("lifecycleManaged").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network").ConfigureAwait(false);
        return network?.Select(r => ManagedObject.Create<Network>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyNetworkBootMode()
    {
        var obj = await this.GetProperty<string>("networkBootMode").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ResourcePool?> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference>("resourcePool").ConfigureAwait(false);
        return ManagedObject.Create<ResourcePool>(resourcePool, this.Session);
    }

    public async System.Threading.Tasks.Task<ComputeResourceSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<ComputeResourceSummary>("summary").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> DisableNetworkBoot_Task()
    {
        var res = await this.Session.VimClient.DisableNetworkBoot_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> EnableNetworkBoot_Task(string networkBootMode)
    {
        var res = await this.Session.VimClient.EnableNetworkBoot_Task(this.VimReference, networkBootMode).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureComputeResource_Task(ComputeResourceConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ReconfigureComputeResource_Task(this.VimReference, spec, modify).ConfigureAwait(false);
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
        var container = await this.GetProperty<ManagedObjectReference>("container").ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(container, this.Session)!;
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyRecursive()
    {
        var obj = await this.GetProperty<bool>("recursive").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyType()
    {
        var obj = await this.GetProperty<string[]>("type").ConfigureAwait(false);
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
        var obj = await this.GetProperty<bool>("enabled").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task AddKey(CryptoKeyPlain key)
    {
        await this.Session.VimClient.AddKey(this.VimReference, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]?> AddKeys(CryptoKeyPlain[]? keys)
    {
        return await this.Session.VimClient.AddKeys(this.VimReference, keys).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoKeyId[]?> ListKeys(int? limit)
    {
        return await this.Session.VimClient.ListKeys(this.VimReference, limit ?? default, limit.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveKey(CryptoKeyId key, bool force)
    {
        await this.Session.VimClient.RemoveKey(this.VimReference, key, force).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]?> RemoveKeys(CryptoKeyId[]? keys, bool force)
    {
        return await this.Session.VimClient.RemoveKeys(this.VimReference, keys, force).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.ChangeKey_Task(this.VimReference, newKey).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostDisable()
    {
        await this.Session.VimClient.CryptoManagerHostDisable(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostEnable(CryptoKeyPlain initialKey)
    {
        await this.Session.VimClient.CryptoManagerHostEnable(this.VimReference, initialKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostPrepare()
    {
        await this.Session.VimClient.CryptoManagerHostPrepare(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoManagerHostKeyStatus[]?> GetCryptoKeyStatus(CryptoKeyId[]? keys)
    {
        return await this.Session.VimClient.GetCryptoKeyStatus(this.VimReference, keys).ConfigureAwait(false);
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
        var obj = await this.GetProperty<KmipClusterInfo[]>("kmipServers").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GenerateClientCsr(KeyProviderId cluster, CryptoManagerKmipCertSignRequest? request)
    {
        return await this.Session.VimClient.GenerateClientCsr(this.VimReference, cluster, request).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult?> GenerateKey(KeyProviderId? keyProvider, CryptoManagerKmipCustomAttributeSpec? spec, CryptoManagerKmipGenerateKeySpec? keySpec)
    {
        return await this.Session.VimClient.GenerateKey(this.VimReference, keyProvider, spec, keySpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> GenerateSelfSignedClientCert(KeyProviderId cluster, CryptoManagerKmipCertSignRequest? request)
    {
        return await this.Session.VimClient.GenerateSelfSignedClientCert(this.VimReference, cluster, request).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<KeyProviderId?> GetDefaultKmsCluster(ManagedEntity? entity, bool? defaultsToParent)
    {
        return await this.Session.VimClient.GetDefaultKmsCluster(this.VimReference, entity?.VimReference, defaultsToParent ?? default, defaultsToParent.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> IsKmsClusterActive(KeyProviderId? cluster)
    {
        return await this.Session.VimClient.IsKmsClusterActive(this.VimReference, cluster).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmipServers(int? limit)
    {
        return await this.Session.VimClient.ListKmipServers(this.VimReference, limit ?? default, limit.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmsClusters(bool? includeKmsServers, int? managementTypeFilter, int? statusFilter)
    {
        return await this.Session.VimClient.ListKmsClusters(this.VimReference, includeKmsServers ?? default, includeKmsServers.HasValue, managementTypeFilter ?? default, managementTypeFilter.HasValue, statusFilter ?? default, statusFilter.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MarkDefault(KeyProviderId clusterId)
    {
        await this.Session.VimClient.MarkDefault(this.VimReference, clusterId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipCryptoKeyStatus[]?> QueryCryptoKeyStatus(CryptoKeyId[]? keyIds, int checkKeyBitMap)
    {
        return await this.Session.VimClient.QueryCryptoKeyStatus(this.VimReference, keyIds, checkKeyBitMap).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RegisterKmipServer(KmipServerSpec server)
    {
        await this.Session.VimClient.RegisterKmipServer(this.VimReference, server).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RegisterKmsCluster(KeyProviderId clusterId, string? managementType)
    {
        await this.Session.VimClient.RegisterKmsCluster(this.VimReference, clusterId, managementType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveKmipServer(KeyProviderId clusterId, string serverName)
    {
        await this.Session.VimClient.RemoveKmipServer(this.VimReference, clusterId, serverName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> RetrieveClientCert(KeyProviderId cluster)
    {
        return await this.Session.VimClient.RetrieveClientCert(this.VimReference, cluster).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> RetrieveClientCsr(KeyProviderId cluster)
    {
        return await this.Session.VimClient.RetrieveClientCsr(this.VimReference, cluster).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipServerCertInfo?> RetrieveKmipServerCert(KeyProviderId keyProvider, KmipServerInfo server)
    {
        return await this.Session.VimClient.RetrieveKmipServerCert(this.VimReference, keyProvider, server).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RetrieveKmipServersStatus_Task(KmipClusterInfo[]? clusters)
    {
        var res = await this.Session.VimClient.RetrieveKmipServersStatus_Task(this.VimReference, clusters).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string?> RetrieveSelfSignedClientCert(KeyProviderId cluster)
    {
        return await this.Session.VimClient.RetrieveSelfSignedClientCert(this.VimReference, cluster).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetDefaultKmsCluster(ManagedEntity? entity, KeyProviderId? clusterId)
    {
        await this.Session.VimClient.SetDefaultKmsCluster(this.VimReference, entity?.VimReference, clusterId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult?> SetKeyCustomAttributes(CryptoKeyId keyId, CryptoManagerKmipCustomAttributeSpec spec)
    {
        return await this.Session.VimClient.SetKeyCustomAttributes(this.VimReference, keyId, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnregisterKmsCluster(KeyProviderId clusterId)
    {
        await this.Session.VimClient.UnregisterKmsCluster(this.VimReference, clusterId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateKmipServer(KmipServerSpec server)
    {
        await this.Session.VimClient.UpdateKmipServer(this.VimReference, server).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateKmsSignedCsrClientCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.VimClient.UpdateKmsSignedCsrClientCert(this.VimReference, cluster, certificate).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateSelfSignedClientCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.VimClient.UpdateSelfSignedClientCert(this.VimReference, cluster, certificate).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UploadClientCert(KeyProviderId cluster, string certificate, string privateKey)
    {
        await this.Session.VimClient.UploadClientCert(this.VimReference, cluster, certificate, privateKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UploadKmipServerCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.VimClient.UploadKmipServerCert(this.VimReference, cluster, certificate).ConfigureAwait(false);
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
        var obj = await this.GetProperty<CustomFieldDef[]>("field").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<CustomFieldDef?> AddCustomFieldDef(string name, string? moType, PrivilegePolicyDef? fieldDefPolicy, PrivilegePolicyDef? fieldPolicy)
    {
        return await this.Session.VimClient.AddCustomFieldDef(this.VimReference, name, moType, fieldDefPolicy, fieldPolicy).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveCustomFieldDef(int key)
    {
        await this.Session.VimClient.RemoveCustomFieldDef(this.VimReference, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RenameCustomFieldDef(int key, string name)
    {
        await this.Session.VimClient.RenameCustomFieldDef(this.VimReference, key, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetField(ManagedEntity entity, int key, string value)
    {
        await this.Session.VimClient.SetField(this.VimReference, entity.VimReference, key, value).ConfigureAwait(false);
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
        var obj = await this.GetProperty<byte[]>("encryptionKey").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<CustomizationSpecInfo[]?> GetPropertyInfo()
    {
        var obj = await this.GetProperty<CustomizationSpecInfo[]>("info").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task CheckCustomizationResources(string guestOs)
    {
        await this.Session.VimClient.CheckCustomizationResources(this.VimReference, guestOs).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CreateCustomizationSpec(CustomizationSpecItem item)
    {
        await this.Session.VimClient.CreateCustomizationSpec(this.VimReference, item).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> CustomizationSpecItemToXml(CustomizationSpecItem item)
    {
        return await this.Session.VimClient.CustomizationSpecItemToXml(this.VimReference, item).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteCustomizationSpec(string name)
    {
        await this.Session.VimClient.DeleteCustomizationSpec(this.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> DoesCustomizationSpecExist(string name)
    {
        return await this.Session.VimClient.DoesCustomizationSpecExist(this.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DuplicateCustomizationSpec(string name, string newName)
    {
        await this.Session.VimClient.DuplicateCustomizationSpec(this.VimReference, name, newName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem?> GetCustomizationSpec(string name)
    {
        return await this.Session.VimClient.GetCustomizationSpec(this.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> IsGuestOsCustomizable(string guestId)
    {
        return await this.Session.VimClient.IsGuestOsCustomizable(this.VimReference, guestId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task OverwriteCustomizationSpec(CustomizationSpecItem item)
    {
        await this.Session.VimClient.OverwriteCustomizationSpec(this.VimReference, item).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RenameCustomizationSpec(string name, string newName)
    {
        await this.Session.VimClient.RenameCustomizationSpec(this.VimReference, name, newName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem?> XmlToCustomizationSpecItem(string specItemXml)
    {
        return await this.Session.VimClient.XmlToCustomizationSpecItem(this.VimReference, specItemXml).ConfigureAwait(false);
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
        var obj = await this.GetProperty<DatacenterConfigInfo>("configuration").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore").ConfigureAwait(false);
        return datastore?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyDatastoreFolder()
    {
        var datastoreFolder = await this.GetProperty<ManagedObjectReference>("datastoreFolder").ConfigureAwait(false);
        return ManagedObject.Create<Folder>(datastoreFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyHostFolder()
    {
        var hostFolder = await this.GetProperty<ManagedObjectReference>("hostFolder").ConfigureAwait(false);
        return ManagedObject.Create<Folder>(hostFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network").ConfigureAwait(false);
        return network?.Select(r => ManagedObject.Create<Network>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyNetworkFolder()
    {
        var networkFolder = await this.GetProperty<ManagedObjectReference>("networkFolder").ConfigureAwait(false);
        return ManagedObject.Create<Folder>(networkFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyVmFolder()
    {
        var vmFolder = await this.GetProperty<ManagedObjectReference>("vmFolder").ConfigureAwait(false);
        return ManagedObject.Create<Folder>(vmFolder, this.Session)!;
    }

    public async System.Threading.Tasks.Task<DatacenterBasicConnectInfo[]?> BatchQueryConnectInfo(HostConnectSpec[]? hostSpecs)
    {
        return await this.Session.VimClient.BatchQueryConnectInfo(this.VimReference, hostSpecs).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOnMultiVM_Task(VirtualMachine[] vm, OptionValue[]? option)
    {
        var res = await this.Session.VimClient.PowerOnMultiVM_Task(this.VimReference, [.. vm.Select(m => m.VimReference)], option).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfo(string hostname, int port, string username, string password, string? sslThumbprint, string? sslCertificate)
    {
        return await this.Session.VimClient.QueryConnectionInfo(this.VimReference, hostname, port, username, password, sslThumbprint, sslCertificate).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfoViaSpec(HostConnectSpec spec)
    {
        return await this.Session.VimClient.QueryConnectionInfoViaSpec(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryDatacenterConfigOptionDescriptor()
    {
        return await this.Session.VimClient.QueryDatacenterConfigOptionDescriptor(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDatacenter_Task(DatacenterConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ReconfigureDatacenter_Task(this.VimReference, spec, modify).ConfigureAwait(false);
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
        var browser = await this.GetProperty<ManagedObjectReference>("browser").ConfigureAwait(false);
        return ManagedObject.Create<HostDatastoreBrowser>(browser, this.Session)!;
    }

    public async System.Threading.Tasks.Task<DatastoreCapability> GetPropertyCapability()
    {
        var obj = await this.GetProperty<DatastoreCapability>("capability").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<DatastoreHostMount[]?> GetPropertyHost()
    {
        var obj = await this.GetProperty<DatastoreHostMount[]>("host").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<DatastoreInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<DatastoreInfo>("info").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<StorageIORMInfo?> GetPropertyIormConfiguration()
    {
        var obj = await this.GetProperty<StorageIORMInfo>("iormConfiguration").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<DatastoreSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<DatastoreSummary>("summary").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm").ConfigureAwait(false);
        return vm?.Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult?> DatastoreEnterMaintenanceMode()
    {
        return await this.Session.VimClient.DatastoreEnterMaintenanceMode(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> DatastoreExitMaintenanceMode_Task()
    {
        var res = await this.Session.VimClient.DatastoreExitMaintenanceMode_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyDatastore()
    {
        await this.Session.VimClient.DestroyDatastore(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> IsClusteredVmdkEnabled()
    {
        return await this.Session.VimClient.IsClusteredVmdkEnabled(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshDatastore()
    {
        await this.Session.VimClient.RefreshDatastore(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshDatastoreStorageInfo()
    {
        await this.Session.VimClient.RefreshDatastoreStorageInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RenameDatastore(string newName)
    {
        await this.Session.VimClient.RenameDatastore(this.VimReference, newName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVirtualMachineFiles_Task(DatastoreMountPathDatastorePair[] mountPathDatastoreMapping)
    {
        var res = await this.Session.VimClient.UpdateVirtualMachineFiles_Task(this.VimReference, mountPathDatastoreMapping).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVVolVirtualMachineFiles_Task(DatastoreVVolContainerFailoverPair[]? failoverPair)
    {
        var res = await this.Session.VimClient.UpdateVVolVirtualMachineFiles_Task(this.VimReference, failoverPair).ConfigureAwait(false);
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
        return await this.Session.VimClient.ConvertNamespacePathToUuidPath(this.VimReference, datacenter?.VimReference, namespaceUrl).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> CreateDirectory(Datastore datastore, string? displayName, string? policy, long? size)
    {
        return await this.Session.VimClient.CreateDirectory(this.VimReference, datastore.VimReference, displayName, policy, size ?? default, size.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteDirectory(Datacenter? datacenter, string datastorePath)
    {
        await this.Session.VimClient.DeleteDirectory(this.VimReference, datacenter?.VimReference, datastorePath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task IncreaseDirectorySize(Datacenter? datacenter, string stableName, long size)
    {
        await this.Session.VimClient.IncreaseDirectorySize(this.VimReference, datacenter?.VimReference, stableName, size).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DatastoreNamespaceManagerDirectoryInfo?> QueryDirectoryInfo(Datacenter? datacenter, string stableName)
    {
        return await this.Session.VimClient.QueryDirectoryInfo(this.VimReference, datacenter?.VimReference, stableName).ConfigureAwait(false);
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
        return await this.Session.VimClient.BrowseDiagnosticLog(this.VimReference, host?.VimReference, key, start ?? default, start.HasValue, lines ?? default, lines.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EmitSyslogMark(string message)
    {
        await this.Session.VimClient.EmitSyslogMark(this.VimReference, message).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerAuditRecordResult?> FetchAuditRecords(string? token)
    {
        return await this.Session.VimClient.FetchAuditRecords(this.VimReference, token).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> GenerateLogBundles_Task(bool includeDefault, HostSystem[]? host)
    {
        var res = await this.Session.VimClient.GenerateLogBundles_Task(this.VimReference, includeDefault, host?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerLogDescriptor[]?> QueryDescriptions(HostSystem? host)
    {
        return await this.Session.VimClient.QueryDescriptions(this.VimReference, host?.VimReference).ConfigureAwait(false);
    }
}

public partial class DirectPathProfileManager : ManagedObject
{
    protected DirectPathProfileManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<string?> DirectPathProfileManagerCreate(DirectPathProfileManagerCreateSpec spec)
    {
        return await this.Session.VimClient.DirectPathProfileManagerCreate(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DirectPathProfileManagerDelete(string id)
    {
        await this.Session.VimClient.DirectPathProfileManagerDelete(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DirectPathProfileInfo[]?> DirectPathProfileManagerList(DirectPathProfileManagerFilterSpec filterSpec)
    {
        return await this.Session.VimClient.DirectPathProfileManagerList(this.VimReference, filterSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DirectPathProfileManagerCapacityResult[]?> DirectPathProfileManagerQueryCapacity(DirectPathProfileManagerTargetEntity target, DirectPathProfileManagerCapacityQuerySpec[]? querySpec)
    {
        return await this.Session.VimClient.DirectPathProfileManagerQueryCapacity(this.VimReference, target, querySpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DirectPathProfileManagerUpdate(string id, DirectPathProfileManagerUpdateSpec spec)
    {
        await this.Session.VimClient.DirectPathProfileManagerUpdate(this.VimReference, id, spec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<DVPortgroupConfigInfo>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyKey()
    {
        var obj = await this.GetProperty<string>("key").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyPortKeys()
    {
        var obj = await this.GetProperty<string[]>("portKeys").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> DVPortgroupRollback_Task(EntityBackupConfig? entityBackup)
    {
        var res = await this.Session.VimClient.DVPortgroupRollback_Task(this.VimReference, entityBackup).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDVPortgroup_Task(DVPortgroupConfigSpec spec)
    {
        var res = await this.Session.VimClient.ReconfigureDVPortgroup_Task(this.VimReference, spec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<DVSCapability>("capability").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<DVSConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<DVSConfigInfo>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<DVSNetworkResourcePool[]?> GetPropertyNetworkResourcePool()
    {
        var obj = await this.GetProperty<DVSNetworkResourcePool[]>("networkResourcePool").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup[]?> GetPropertyPortgroup()
    {
        var portgroup = await this.GetProperty<ManagedObjectReference[]>("portgroup").ConfigureAwait(false);
        return portgroup?.Select(r => ManagedObject.Create<DistributedVirtualPortgroup>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<DVSRuntimeInfo?> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<DVSRuntimeInfo>("runtime").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<DVSSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<DVSSummary>("summary").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyUuid()
    {
        var obj = await this.GetProperty<string>("uuid").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> AddDVPortgroup_Task(DVPortgroupConfigSpec[] spec)
    {
        var res = await this.Session.VimClient.AddDVPortgroup_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task AddNetworkResourcePool(DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        await this.Session.VimClient.AddNetworkResourcePool(this.VimReference, configSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDVPortgroup_Task(DVPortgroupConfigSpec spec)
    {
        var res = await this.Session.VimClient.CreateDVPortgroup_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DvsReconfigureVmVnicNetworkResourcePool_Task(DvsVmVnicResourcePoolConfigSpec[] configSpec)
    {
        var res = await this.Session.VimClient.DvsReconfigureVmVnicNetworkResourcePool_Task(this.VimReference, configSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DVSRollback_Task(EntityBackupConfig? entityBackup)
    {
        var res = await this.Session.VimClient.DVSRollback_Task(this.VimReference, entityBackup).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task EnableNetworkResourceManagement(bool enable)
    {
        await this.Session.VimClient.EnableNetworkResourceManagement(this.VimReference, enable).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> FetchDVPortKeys(DistributedVirtualSwitchPortCriteria? criteria)
    {
        return await this.Session.VimClient.FetchDVPortKeys(this.VimReference, criteria).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPort[]?> FetchDVPorts(DistributedVirtualSwitchPortCriteria? criteria)
    {
        return await this.Session.VimClient.FetchDVPorts(this.VimReference, criteria).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup?> LookupDvPortGroup(string portgroupKey)
    {
        var res = await this.Session.VimClient.LookupDvPortGroup(this.VimReference, portgroupKey).ConfigureAwait(false);
        return ManagedObject.Create<DistributedVirtualPortgroup>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MergeDvs_Task(DistributedVirtualSwitch dvs)
    {
        var res = await this.Session.VimClient.MergeDvs_Task(this.VimReference, dvs.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveDVPort_Task(string[] portKey, string? destinationPortgroupKey)
    {
        var res = await this.Session.VimClient.MoveDVPort_Task(this.VimReference, portKey, destinationPortgroupKey).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PerformDvsProductSpecOperation_Task(string operation, DistributedVirtualSwitchProductSpec? productSpec)
    {
        var res = await this.Session.VimClient.PerformDvsProductSpecOperation_Task(this.VimReference, operation, productSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int[]?> QueryUsedVlanIdInDvs()
    {
        return await this.Session.VimClient.QueryUsedVlanIdInDvs(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDVPort_Task(DVPortConfigSpec[] port)
    {
        var res = await this.Session.VimClient.ReconfigureDVPort_Task(this.VimReference, port).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureDvs_Task(DVSConfigSpec spec)
    {
        var res = await this.Session.VimClient.ReconfigureDvs_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RectifyDvsHost_Task(HostSystem[]? hosts)
    {
        var res = await this.Session.VimClient.RectifyDvsHost_Task(this.VimReference, hosts?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshDVPortState(string[]? portKeys)
    {
        await this.Session.VimClient.RefreshDVPortState(this.VimReference, portKeys).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveNetworkResourcePool(string[] key)
    {
        await this.Session.VimClient.RemoveNetworkResourcePool(this.VimReference, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateDvsCapability(DVSCapability capability)
    {
        await this.Session.VimClient.UpdateDvsCapability(this.VimReference, capability).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateDVSHealthCheckConfig_Task(DVSHealthCheckConfig[] healthCheckConfig)
    {
        var res = await this.Session.VimClient.UpdateDVSHealthCheckConfig_Task(this.VimReference, healthCheckConfig).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateNetworkResourcePool(DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        await this.Session.VimClient.UpdateNetworkResourcePool(this.VimReference, configSpec).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.DVSManagerExportEntity_Task(this.VimReference, selectionSet).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DVSManagerImportEntity_Task(EntityBackupConfig[] entityBackup, string importType)
    {
        var res = await this.Session.VimClient.DVSManagerImportEntity_Task(this.VimReference, entityBackup, importType).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup?> DVSManagerLookupDvPortGroup(string switchUuid, string portgroupKey)
    {
        var res = await this.Session.VimClient.DVSManagerLookupDvPortGroup(this.VimReference, switchUuid, portgroupKey).ConfigureAwait(false);
        return ManagedObject.Create<DistributedVirtualPortgroup>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchManagerSpanInfo[]?> GetVpcNetworkSpan(string? spanId)
    {
        return await this.Session.VimClient.GetVpcNetworkSpan(this.VimReference, spanId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchProductSpec[]?> QueryAvailableDvsSpec(bool? recommended)
    {
        return await this.Session.VimClient.QueryAvailableDvsSpec(this.VimReference, recommended ?? default, recommended.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryCompatibleHostForExistingDvs(ManagedEntity container, bool recursive, DistributedVirtualSwitch dvs)
    {
        var res = await this.Session.VimClient.QueryCompatibleHostForExistingDvs(this.VimReference, container.VimReference, recursive, dvs.VimReference).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryCompatibleHostForNewDvs(ManagedEntity container, bool recursive, DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        var res = await this.Session.VimClient.QueryCompatibleHostForNewDvs(this.VimReference, container.VimReference, recursive, switchProductSpec).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<DVSManagerPhysicalNicsList[]?> QueryCompatibleVmnicsFromHosts(HostSystem[]? hosts, DistributedVirtualSwitch dvs)
    {
        return await this.Session.VimClient.QueryCompatibleVmnicsFromHosts(this.VimReference, hosts?.Select(m => m.VimReference).ToArray(), dvs.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitch?> QueryDvsByUuid(string uuid)
    {
        var res = await this.Session.VimClient.QueryDvsByUuid(this.VimReference, uuid).ConfigureAwait(false);
        return ManagedObject.Create<DistributedVirtualSwitch>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchManagerCompatibilityResult[]?> QueryDvsCheckCompatibility(DistributedVirtualSwitchManagerHostContainer hostContainer, DistributedVirtualSwitchManagerDvsProductSpec? dvsProductSpec, DistributedVirtualSwitchManagerHostDvsFilterSpec[]? hostFilterSpec)
    {
        return await this.Session.VimClient.QueryDvsCheckCompatibility(this.VimReference, hostContainer, dvsProductSpec, hostFilterSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchHostProductSpec[]?> QueryDvsCompatibleHostSpec(DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        return await this.Session.VimClient.QueryDvsCompatibleHostSpec(this.VimReference, switchProductSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DVSManagerDvsConfigTarget?> QueryDvsConfigTarget(HostSystem? host, DistributedVirtualSwitch? dvs)
    {
        return await this.Session.VimClient.QueryDvsConfigTarget(this.VimReference, host?.VimReference, dvs?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DVSFeatureCapability?> QueryDvsFeatureCapability(DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        return await this.Session.VimClient.QueryDvsFeatureCapability(this.VimReference, switchProductSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchNetworkOffloadSpec[]?> QuerySupportedNetworkOffloadSpec(DistributedVirtualSwitchProductSpec switchProductSpec)
    {
        return await this.Session.VimClient.QuerySupportedNetworkOffloadSpec(this.VimReference, switchProductSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RectifyDvsOnHost_Task(HostSystem[] hosts)
    {
        var res = await this.Session.VimClient.RectifyDvsOnHost_Task(this.VimReference, [.. hosts.Select(m => m.VimReference)]).ConfigureAwait(false);
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
        var datastoreBrowser = await this.GetProperty<ManagedObjectReference>("datastoreBrowser").ConfigureAwait(false);
        return ManagedObject.Create<HostDatastoreBrowser>(datastoreBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOption(string? key, HostSystem? host)
    {
        return await this.Session.VimClient.QueryConfigOption(this.VimReference, key, host?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryConfigOptionDescriptor()
    {
        return await this.Session.VimClient.QueryConfigOptionDescriptor(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOptionEx(EnvironmentBrowserConfigOptionQuerySpec? spec)
    {
        return await this.Session.VimClient.QueryConfigOptionEx(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ConfigTarget?> QueryConfigTarget(HostSystem? host)
    {
        return await this.Session.VimClient.QueryConfigTarget(this.VimReference, host?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostCapability?> QueryTargetCapabilities(HostSystem? host)
    {
        return await this.Session.VimClient.QueryTargetCapabilities(this.VimReference, host?.VimReference).ConfigureAwait(false);
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

    public async System.Threading.Tasks.Task<bool> GetPropertyInitialized()
    {
        var obj = await this.GetProperty<bool>("initialized").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Event[]?> GetPropertyLatestPage()
    {
        var obj = await this.GetProperty<Event[]>("latestPage").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Event[]?> ReadNextEvents(int maxCount)
    {
        return await this.Session.VimClient.ReadNextEvents(this.VimReference, maxCount).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Event[]?> ReadPreviousEvents(int maxCount)
    {
        return await this.Session.VimClient.ReadPreviousEvents(this.VimReference, maxCount).ConfigureAwait(false);
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
        var obj = await this.GetProperty<EventDescription>("description").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Event?> GetPropertyLatestEvent()
    {
        var obj = await this.GetProperty<Event>("latestEvent").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyMaxCollector()
    {
        var obj = await this.GetProperty<int>("maxCollector").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<EventHistoryCollector?> CreateCollectorForEvents(EventFilterSpec filter)
    {
        var res = await this.Session.VimClient.CreateCollectorForEvents(this.VimReference, filter).ConfigureAwait(false);
        return ManagedObject.Create<EventHistoryCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task LogUserEvent(ManagedEntity entity, string msg)
    {
        await this.Session.VimClient.LogUserEvent(this.VimReference, entity.VimReference, msg).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task PostEvent(Event eventToPost, TaskInfo? taskInfo)
    {
        await this.Session.VimClient.PostEvent(this.VimReference, eventToPost, taskInfo).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Event[]?> QueryEvents(EventFilterSpec filter, EventManagerEventViewSpec? eventViewSpec)
    {
        return await this.Session.VimClient.QueryEvents(this.VimReference, filter, eventViewSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<EventArgDesc[]?> RetrieveArgumentDescription(string eventTypeId)
    {
        return await this.Session.VimClient.RetrieveArgumentDescription(this.VimReference, eventTypeId).ConfigureAwait(false);
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
        var obj = await this.GetProperty<CustomFieldDef[]>("availableField").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<CustomFieldValue[]?> GetPropertyValue()
    {
        var obj = await this.GetProperty<CustomFieldValue[]>("value").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task SetCustomValue(string key, string value)
    {
        await this.Session.VimClient.SetCustomValue(this.VimReference, key, value).ConfigureAwait(false);
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
        var obj = await this.GetProperty<Extension[]>("extensionList").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Extension?> FindExtension(string extensionKey)
    {
        return await this.Session.VimClient.FindExtension(this.VimReference, extensionKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> GetPublicKey()
    {
        return await this.Session.VimClient.GetPublicKey(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ExtensionManagerIpAllocationUsage[]?> QueryExtensionIpAllocationUsage(string[]? extensionKeys)
    {
        return await this.Session.VimClient.QueryExtensionIpAllocationUsage(this.VimReference, extensionKeys).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> QueryManagedBy(string extensionKey)
    {
        var res = await this.Session.VimClient.QueryManagedBy(this.VimReference, extensionKey).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task RegisterExtension(Extension extension)
    {
        await this.Session.VimClient.RegisterExtension(this.VimReference, extension).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetExtensionCertificate(string extensionKey, string? certificatePem)
    {
        await this.Session.VimClient.SetExtensionCertificate(this.VimReference, extensionKey, certificatePem).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetPublicKey(string extensionKey, string publicKey)
    {
        await this.Session.VimClient.SetPublicKey(this.VimReference, extensionKey, publicKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetServiceAccount(string extensionKey, string serviceAccount)
    {
        await this.Session.VimClient.SetServiceAccount(this.VimReference, extensionKey, serviceAccount).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnregisterExtension(string extensionKey)
    {
        await this.Session.VimClient.UnregisterExtension(this.VimReference, extensionKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateExtension(Extension extension)
    {
        await this.Session.VimClient.UpdateExtension(this.VimReference, extension).ConfigureAwait(false);
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
        var obj = await this.GetProperty<string[]>("disabledConfigureMethod").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureVcha_Task(VchaClusterConfigSpec configSpec)
    {
        var res = await this.Session.VimClient.ConfigureVcha_Task(this.VimReference, configSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreatePassiveNode_Task(PassiveNodeDeploymentSpec passiveDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var res = await this.Session.VimClient.CreatePassiveNode_Task(this.VimReference, passiveDeploymentSpec, sourceVcSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateWitnessNode_Task(NodeDeploymentSpec witnessDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var res = await this.Session.VimClient.CreateWitnessNode_Task(this.VimReference, witnessDeploymentSpec, sourceVcSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeployVcha_Task(VchaClusterDeploymentSpec deploymentSpec)
    {
        var res = await this.Session.VimClient.DeployVcha_Task(this.VimReference, deploymentSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DestroyVcha_Task()
    {
        var res = await this.Session.VimClient.DestroyVcha_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VchaClusterConfigInfo?> GetVchaConfig()
    {
        return await this.Session.VimClient.GetVchaConfig(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> PrepareVcha_Task(VchaClusterNetworkSpec networkSpec)
    {
        var res = await this.Session.VimClient.PrepareVcha_Task(this.VimReference, networkSpec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<string[]>("disabledClusterMethod").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GetClusterMode()
    {
        return await this.Session.VimClient.GetClusterMode(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VchaClusterHealth?> GetVchaClusterHealth()
    {
        return await this.Session.VimClient.GetVchaClusterHealth(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> InitiateFailover_Task(bool planned)
    {
        var res = await this.Session.VimClient.InitiateFailover_Task(this.VimReference, planned).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SetClusterMode_Task(string mode)
    {
        var res = await this.Session.VimClient.SetClusterMode_Task(this.VimReference, mode).ConfigureAwait(false);
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
        await this.Session.VimClient.ChangeOwner(this.VimReference, name, datacenter?.VimReference, owner).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> CopyDatastoreFile_Task(string sourceName, Datacenter? sourceDatacenter, string destinationName, Datacenter? destinationDatacenter, bool? force)
    {
        var res = await this.Session.VimClient.CopyDatastoreFile_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destinationName, destinationDatacenter?.VimReference, force ?? default, force.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteDatastoreFile_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.DeleteDatastoreFile_Task(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MakeDirectory(string name, Datacenter? datacenter, bool? createParentDirectories)
    {
        await this.Session.VimClient.MakeDirectory(this.VimReference, name, datacenter?.VimReference, createParentDirectories ?? default, createParentDirectories.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> MoveDatastoreFile_Task(string sourceName, Datacenter? sourceDatacenter, string destinationName, Datacenter? destinationDatacenter, bool? force)
    {
        var res = await this.Session.VimClient.MoveDatastoreFile_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destinationName, destinationDatacenter?.VimReference, force ?? default, force.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<FileLockInfoResult?> QueryFileLockInfo(string path, HostSystem? host)
    {
        return await this.Session.VimClient.QueryFileLockInfo(this.VimReference, path, host?.VimReference).ConfigureAwait(false);
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
        var childEntity = await this.GetProperty<ManagedObjectReference[]>("childEntity").ConfigureAwait(false);
        return childEntity?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyChildType()
    {
        var obj = await this.GetProperty<string[]>("childType").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<FolderExternallyManagedFolderInfo?> GetPropertyExternallyManagedFolderInfo()
    {
        var obj = await this.GetProperty<FolderExternallyManagedFolderInfo>("externallyManagedFolderInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyNamespace()
    {
        var obj = await this.GetProperty<string>("namespace").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> AddStandaloneHost_Task(HostConnectSpec spec, ComputeResourceConfigSpec? compResSpec, bool addConnected, string? license)
    {
        var res = await this.Session.VimClient.AddStandaloneHost_Task(this.VimReference, spec, compResSpec, addConnected, license).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> BatchAddHostsToCluster_Task(ClusterComputeResource cluster, FolderNewHostSpec[]? newHosts, HostSystem[]? existingHosts, ComputeResourceConfigSpec? compResSpec, string? desiredState)
    {
        var res = await this.Session.VimClient.BatchAddHostsToCluster_Task(this.VimReference, cluster.VimReference, newHosts, existingHosts?.Select(m => m.VimReference).ToArray(), compResSpec, desiredState).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> BatchAddStandaloneHosts_Task(FolderNewHostSpec[]? newHosts, ComputeResourceConfigSpec? compResSpec, bool addConnected)
    {
        var res = await this.Session.VimClient.BatchAddStandaloneHosts_Task(this.VimReference, newHosts, compResSpec, addConnected).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource?> CreateCluster(string name, ClusterConfigSpec spec)
    {
        var res = await this.Session.VimClient.CreateCluster(this.VimReference, name, spec).ConfigureAwait(false);
        return ManagedObject.Create<ClusterComputeResource>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource?> CreateClusterEx(string name, ClusterConfigSpecEx spec)
    {
        var res = await this.Session.VimClient.CreateClusterEx(this.VimReference, name, spec).ConfigureAwait(false);
        return ManagedObject.Create<ClusterComputeResource>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datacenter?> CreateDatacenter(string name)
    {
        var res = await this.Session.VimClient.CreateDatacenter(this.VimReference, name).ConfigureAwait(false);
        return ManagedObject.Create<Datacenter>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDVS_Task(DVSCreateSpec spec)
    {
        var res = await this.Session.VimClient.CreateDVS_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Folder?> CreateFolder(string name)
    {
        var res = await this.Session.VimClient.CreateFolder(this.VimReference, name).ConfigureAwait(false);
        return ManagedObject.Create<Folder>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<StoragePod?> CreateStoragePod(string name)
    {
        var res = await this.Session.VimClient.CreateStoragePod(this.VimReference, name).ConfigureAwait(false);
        return ManagedObject.Create<StoragePod>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateVM_Task(VirtualMachineConfigSpec config, ResourcePool pool, HostSystem? host)
    {
        var res = await this.Session.VimClient.CreateVM_Task(this.VimReference, config, pool.VimReference, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveIntoFolder_Task(ManagedEntity[] list)
    {
        var res = await this.Session.VimClient.MoveIntoFolder_Task(this.VimReference, [.. list.Select(m => m.VimReference)]).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RegisterVM_Task(string path, string? name, bool asTemplate, ResourcePool? pool, HostSystem? host)
    {
        var res = await this.Session.VimClient.RegisterVM_Task(this.VimReference, path, name, asTemplate, pool?.VimReference, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnregisterAndDestroy_Task()
    {
        var res = await this.Session.VimClient.UnregisterAndDestroy_Task(this.VimReference).ConfigureAwait(false);
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
        await this.Session.VimClient.AddGuestAlias(this.VimReference, vm.VimReference, auth, username, mapCert, base64Cert, aliasInfo).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<GuestAliases[]?> ListGuestAliases(VirtualMachine vm, GuestAuthentication auth, string username)
    {
        return await this.Session.VimClient.ListGuestAliases(this.VimReference, vm.VimReference, auth, username).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<GuestMappedAliases[]?> ListGuestMappedAliases(VirtualMachine vm, GuestAuthentication auth)
    {
        return await this.Session.VimClient.ListGuestMappedAliases(this.VimReference, vm.VimReference, auth).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveGuestAlias(VirtualMachine vm, GuestAuthentication auth, string username, string base64Cert, GuestAuthSubject subject)
    {
        await this.Session.VimClient.RemoveGuestAlias(this.VimReference, vm.VimReference, auth, username, base64Cert, subject).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveGuestAliasByCert(VirtualMachine vm, GuestAuthentication auth, string username, string base64Cert)
    {
        await this.Session.VimClient.RemoveGuestAliasByCert(this.VimReference, vm.VimReference, auth, username, base64Cert).ConfigureAwait(false);
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
        return await this.Session.VimClient.AcquireCredentialsInGuest(this.VimReference, vm.VimReference, requestedAuth, sessionID ?? default, sessionID.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReleaseCredentialsInGuest(VirtualMachine vm, GuestAuthentication auth)
    {
        await this.Session.VimClient.ReleaseCredentialsInGuest(this.VimReference, vm.VimReference, auth).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ValidateCredentialsInGuest(VirtualMachine vm, GuestAuthentication auth)
    {
        await this.Session.VimClient.ValidateCredentialsInGuest(this.VimReference, vm.VimReference, auth).ConfigureAwait(false);
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
        await this.Session.VimClient.ChangeFileAttributesInGuest(this.VimReference, vm.VimReference, auth, guestFilePath, fileAttributes).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> CreateTemporaryDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath)
    {
        return await this.Session.VimClient.CreateTemporaryDirectoryInGuest(this.VimReference, vm.VimReference, auth, prefix, suffix, directoryPath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> CreateTemporaryFileInGuest(VirtualMachine vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath)
    {
        return await this.Session.VimClient.CreateTemporaryFileInGuest(this.VimReference, vm.VimReference, auth, prefix, suffix, directoryPath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string directoryPath, bool recursive)
    {
        await this.Session.VimClient.DeleteDirectoryInGuest(this.VimReference, vm.VimReference, auth, directoryPath, recursive).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteFileInGuest(VirtualMachine vm, GuestAuthentication auth, string filePath)
    {
        await this.Session.VimClient.DeleteFileInGuest(this.VimReference, vm.VimReference, auth, filePath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<FileTransferInformation?> InitiateFileTransferFromGuest(VirtualMachine vm, GuestAuthentication auth, string guestFilePath)
    {
        return await this.Session.VimClient.InitiateFileTransferFromGuest(this.VimReference, vm.VimReference, auth, guestFilePath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> InitiateFileTransferToGuest(VirtualMachine vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes, long fileSize, bool overwrite)
    {
        return await this.Session.VimClient.InitiateFileTransferToGuest(this.VimReference, vm.VimReference, auth, guestFilePath, fileAttributes, fileSize, overwrite).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<GuestListFileInfo?> ListFilesInGuest(VirtualMachine vm, GuestAuthentication auth, string filePath, int? index, int? maxResults, string? matchPattern)
    {
        return await this.Session.VimClient.ListFilesInGuest(this.VimReference, vm.VimReference, auth, filePath, index ?? default, index.HasValue, maxResults ?? default, maxResults.HasValue, matchPattern).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MakeDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string directoryPath, bool createParentDirectories)
    {
        await this.Session.VimClient.MakeDirectoryInGuest(this.VimReference, vm.VimReference, auth, directoryPath, createParentDirectories).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MoveDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string srcDirectoryPath, string dstDirectoryPath)
    {
        await this.Session.VimClient.MoveDirectoryInGuest(this.VimReference, vm.VimReference, auth, srcDirectoryPath, dstDirectoryPath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MoveFileInGuest(VirtualMachine vm, GuestAuthentication auth, string srcFilePath, string dstFilePath, bool overwrite)
    {
        await this.Session.VimClient.MoveFileInGuest(this.VimReference, vm.VimReference, auth, srcFilePath, dstFilePath, overwrite).ConfigureAwait(false);
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
        var aliasManager = await this.GetProperty<ManagedObjectReference>("aliasManager").ConfigureAwait(false);
        return ManagedObject.Create<GuestAliasManager>(aliasManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestAuthManager?> GetPropertyAuthManager()
    {
        var authManager = await this.GetProperty<ManagedObjectReference>("authManager").ConfigureAwait(false);
        return ManagedObject.Create<GuestAuthManager>(authManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestFileManager?> GetPropertyFileManager()
    {
        var fileManager = await this.GetProperty<ManagedObjectReference>("fileManager").ConfigureAwait(false);
        return ManagedObject.Create<GuestFileManager>(fileManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestWindowsRegistryManager?> GetPropertyGuestWindowsRegistryManager()
    {
        var guestWindowsRegistryManager = await this.GetProperty<ManagedObjectReference>("guestWindowsRegistryManager").ConfigureAwait(false);
        return ManagedObject.Create<GuestWindowsRegistryManager>(guestWindowsRegistryManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestProcessManager?> GetPropertyProcessManager()
    {
        var processManager = await this.GetProperty<ManagedObjectReference>("processManager").ConfigureAwait(false);
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
        return await this.Session.VimClient.ListProcessesInGuest(this.VimReference, vm.VimReference, auth, pids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> ReadEnvironmentVariableInGuest(VirtualMachine vm, GuestAuthentication auth, string[]? names)
    {
        return await this.Session.VimClient.ReadEnvironmentVariableInGuest(this.VimReference, vm.VimReference, auth, names).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<long> StartProgramInGuest(VirtualMachine vm, GuestAuthentication auth, GuestProgramSpec spec)
    {
        return await this.Session.VimClient.StartProgramInGuest(this.VimReference, vm.VimReference, auth, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task TerminateProcessInGuest(VirtualMachine vm, GuestAuthentication auth, long pid)
    {
        await this.Session.VimClient.TerminateProcessInGuest(this.VimReference, vm.VimReference, auth, pid).ConfigureAwait(false);
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
        await this.Session.VimClient.CreateRegistryKeyInGuest(this.VimReference, vm.VimReference, auth, keyName, isVolatile, classType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteRegistryKeyInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive)
    {
        await this.Session.VimClient.DeleteRegistryKeyInGuest(this.VimReference, vm.VimReference, auth, keyName, recursive).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteRegistryValueInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegValueNameSpec valueName)
    {
        await this.Session.VimClient.DeleteRegistryValueInGuest(this.VimReference, vm.VimReference, auth, valueName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<GuestRegKeyRecordSpec[]?> ListRegistryKeysInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive, string? matchPattern)
    {
        return await this.Session.VimClient.ListRegistryKeysInGuest(this.VimReference, vm.VimReference, auth, keyName, recursive, matchPattern).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<GuestRegValueSpec[]?> ListRegistryValuesInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool expandStrings, string? matchPattern)
    {
        return await this.Session.VimClient.ListRegistryValuesInGuest(this.VimReference, vm.VimReference, auth, keyName, expandStrings, matchPattern).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetRegistryValueInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegValueSpec value)
    {
        await this.Session.VimClient.SetRegistryValueInGuest(this.VimReference, vm.VimReference, auth, value).ConfigureAwait(false);
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
        return await this.Session.VimClient.AddFilter(this.VimReference, providerId, filterName, infoIds).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task AddFilterEntities(string filterId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.AddFilterEntities(this.VimReference, filterId, entities?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task AddMonitoredEntities(string providerId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.AddMonitoredEntities(this.VimReference, providerId, entities?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> HasMonitoredEntity(string providerId, ManagedEntity entity)
    {
        return await this.Session.VimClient.HasMonitoredEntity(this.VimReference, providerId, entity.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> HasProvider(string id)
    {
        return await this.Session.VimClient.HasProvider(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task PostHealthUpdates(string providerId, HealthUpdate[]? updates)
    {
        await this.Session.VimClient.PostHealthUpdates(this.VimReference, providerId, updates).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> QueryFilterEntities(string filterId)
    {
        var res = await this.Session.VimClient.QueryFilterEntities(this.VimReference, filterId).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string[]?> QueryFilterInfoIds(string filterId)
    {
        return await this.Session.VimClient.QueryFilterInfoIds(this.VimReference, filterId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryFilterList(string providerId)
    {
        return await this.Session.VimClient.QueryFilterList(this.VimReference, providerId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryFilterName(string filterId)
    {
        return await this.Session.VimClient.QueryFilterName(this.VimReference, filterId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HealthUpdateInfo[]?> QueryHealthUpdateInfos(string providerId)
    {
        return await this.Session.VimClient.QueryHealthUpdateInfos(this.VimReference, providerId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HealthUpdate[]?> QueryHealthUpdates(string providerId)
    {
        return await this.Session.VimClient.QueryHealthUpdates(this.VimReference, providerId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> QueryMonitoredEntities(string providerId)
    {
        var res = await this.Session.VimClient.QueryMonitoredEntities(this.VimReference, providerId).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string[]?> QueryProviderList()
    {
        return await this.Session.VimClient.QueryProviderList(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryProviderName(string id)
    {
        return await this.Session.VimClient.QueryProviderName(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> QueryUnmonitoredHosts(string providerId, ClusterComputeResource cluster)
    {
        var res = await this.Session.VimClient.QueryUnmonitoredHosts(this.VimReference, providerId, cluster.VimReference).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<string?> RegisterHealthUpdateProvider(string name, HealthUpdateInfo[]? healthUpdateInfo)
    {
        return await this.Session.VimClient.RegisterHealthUpdateProvider(this.VimReference, name, healthUpdateInfo).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveFilter(string filterId)
    {
        await this.Session.VimClient.RemoveFilter(this.VimReference, filterId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveFilterEntities(string filterId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.RemoveFilterEntities(this.VimReference, filterId, entities?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveMonitoredEntities(string providerId, ManagedEntity[]? entities)
    {
        await this.Session.VimClient.RemoveMonitoredEntities(this.VimReference, providerId, entities?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnregisterHealthUpdateProvider(string providerId)
    {
        await this.Session.VimClient.UnregisterHealthUpdateProvider(this.VimReference, providerId).ConfigureAwait(false);
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
        var obj = await this.GetProperty<object>("filter").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task DestroyCollector()
    {
        await this.Session.VimClient.DestroyCollector(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ResetCollector()
    {
        await this.Session.VimClient.ResetCollector(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RewindCollector()
    {
        await this.Session.VimClient.RewindCollector(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetCollectorPageSize(int maxCount)
    {
        await this.Session.VimClient.SetCollectorPageSize(this.VimReference, maxCount).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostLockdownMode>("lockdownMode").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task ChangeAccessMode(string principal, bool isGroup, HostAccessMode accessMode)
    {
        await this.Session.VimClient.ChangeAccessMode(this.VimReference, principal, isGroup, accessMode).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ChangeLockdownMode(HostLockdownMode mode)
    {
        await this.Session.VimClient.ChangeLockdownMode(this.VimReference, mode).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryLockdownExceptions()
    {
        return await this.Session.VimClient.QueryLockdownExceptions(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> QuerySystemUsers()
    {
        return await this.Session.VimClient.QuerySystemUsers(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostAccessControlEntry[]?> RetrieveHostAccessControlEntries()
    {
        return await this.Session.VimClient.RetrieveHostAccessControlEntries(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateLockdownExceptions(string[]? users)
    {
        await this.Session.VimClient.UpdateLockdownExceptions(this.VimReference, users).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateSystemUsers(string[]? users)
    {
        await this.Session.VimClient.UpdateSystemUsers(this.VimReference, users).ConfigureAwait(false);
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
        await this.Session.VimClient.DisableSmartCardAuthentication(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnableSmartCardAuthentication()
    {
        await this.Session.VimClient.EnableSmartCardAuthentication(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ImportCertificateForCAM_Task(string certPath, string camServer)
    {
        var res = await this.Session.VimClient.ImportCertificateForCAM_Task(this.VimReference, certPath, camServer).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task InstallSmartCardTrustAnchor(string cert)
    {
        await this.Session.VimClient.InstallSmartCardTrustAnchor(this.VimReference, cert).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> JoinDomain_Task(string domainName, string userName, string password)
    {
        var res = await this.Session.VimClient.JoinDomain_Task(this.VimReference, domainName, userName, password).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> JoinDomainWithCAM_Task(string domainName, string camServer)
    {
        var res = await this.Session.VimClient.JoinDomainWithCAM_Task(this.VimReference, domainName, camServer).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> LeaveCurrentDomain_Task(bool force)
    {
        var res = await this.Session.VimClient.LeaveCurrentDomain_Task(this.VimReference, force).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string[]?> ListSmartCardTrustAnchors()
    {
        return await this.Session.VimClient.ListSmartCardTrustAnchors(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchor(string issuer, string serial)
    {
        await this.Session.VimClient.RemoveSmartCardTrustAnchor(this.VimReference, issuer, serial).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchorByFingerprint(string fingerprint, string digest)
    {
        await this.Session.VimClient.RemoveSmartCardTrustAnchorByFingerprint(this.VimReference, fingerprint, digest).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchorCertificate(string certificate)
    {
        await this.Session.VimClient.RemoveSmartCardTrustAnchorCertificate(this.VimReference, certificate).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReplaceSmartCardTrustAnchors(string[]? certs)
    {
        await this.Session.VimClient.ReplaceSmartCardTrustAnchors(this.VimReference, certs).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostAssignableHardwareBinding[]>("binding").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostAssignableHardwareConfig> GetPropertyConfig()
    {
        var obj = await this.GetProperty<HostAssignableHardwareConfig>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<byte[]?> DownloadDescriptionTree()
    {
        return await this.Session.VimClient.DownloadDescriptionTree(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineDynamicPassthroughInfo[]?> RetrieveDynamicPassthroughInfo()
    {
        return await this.Session.VimClient.RetrieveDynamicPassthroughInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVendorDeviceGroupInfo[]?> RetrieveVendorDeviceGroupInfo()
    {
        return await this.Session.VimClient.RetrieveVendorDeviceGroupInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateAssignableHardwareConfig(HostAssignableHardwareConfig config)
    {
        await this.Session.VimClient.UpdateAssignableHardwareConfig(this.VimReference, config).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostAuthenticationManagerInfo>("info").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostAuthenticationStore[]> GetPropertySupportedStore()
    {
        var supportedStore = await this.GetProperty<ManagedObjectReference[]>("supportedStore").ConfigureAwait(false);
        return [.. supportedStore!.Select(r => ManagedObject.Create<HostAuthenticationStore>(r, this.Session)!)];
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
        var obj = await this.GetProperty<HostAuthenticationStoreInfo>("info").ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostAutoStartManagerConfig>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task AutoStartPowerOff()
    {
        await this.Session.VimClient.AutoStartPowerOff(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task AutoStartPowerOn()
    {
        await this.Session.VimClient.AutoStartPowerOn(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReconfigureAutostart(HostAutoStartManagerConfig spec)
    {
        await this.Session.VimClient.ReconfigureAutostart(this.VimReference, spec).ConfigureAwait(false);
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
        return await this.Session.VimClient.QueryBootDevices(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateBootDevice(string key)
    {
        await this.Session.VimClient.UpdateBootDevice(this.VimReference, key).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostCacheConfigurationInfo[]>("cacheConfigurationInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureHostCache_Task(HostCacheConfigurationSpec spec)
    {
        var res = await this.Session.VimClient.ConfigureHostCache_Task(this.VimReference, spec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostCertificateManagerCertificateInfo>("certificateInfo").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequest(bool useIpAddressAsCommonName, HostCertificateManagerCertificateSpec? spec)
    {
        return await this.Session.VimClient.GenerateCertificateSigningRequest(this.VimReference, useIpAddressAsCommonName, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequestByDn(string distinguishedName, HostCertificateManagerCertificateSpec? spec)
    {
        return await this.Session.VimClient.GenerateCertificateSigningRequestByDn(this.VimReference, distinguishedName, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task InstallServerCertificate(string cert)
    {
        await this.Session.VimClient.InstallServerCertificate(this.VimReference, cert).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> ListCACertificateRevocationLists()
    {
        return await this.Session.VimClient.ListCACertificateRevocationLists(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> ListCACertificates()
    {
        return await this.Session.VimClient.ListCACertificates(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task NotifyAffectedServices(string[]? services)
    {
        await this.Session.VimClient.NotifyAffectedServices(this.VimReference, services).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ProvisionServerPrivateKey(string key)
    {
        await this.Session.VimClient.ProvisionServerPrivateKey(this.VimReference, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReplaceCACertificatesAndCRLs(string[] caCert, string[]? caCrl)
    {
        await this.Session.VimClient.ReplaceCACertificatesAndCRLs(this.VimReference, caCert, caCrl).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostCertificateManagerCertificateInfo[]?> RetrieveCertificateInfoList()
    {
        return await this.Session.VimClient.RetrieveCertificateInfoList(this.VimReference).ConfigureAwait(false);
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

    public async System.Threading.Tasks.Task<HostCpuSchedulerInfo?> GetPropertyCpuSchedulerInfo()
    {
        var obj = await this.GetProperty<HostCpuSchedulerInfo>("cpuSchedulerInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostHyperThreadScheduleInfo?> GetPropertyHyperthreadInfo()
    {
        var obj = await this.GetProperty<HostHyperThreadScheduleInfo>("hyperthreadInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task DisableHyperThreading()
    {
        await this.Session.VimClient.DisableHyperThreading(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnableHyperThreading()
    {
        await this.Session.VimClient.EnableHyperThreading(this.VimReference).ConfigureAwait(false);
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
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore").ConfigureAwait(false);
        return datastore?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<FileQuery[]?> GetPropertySupportedType()
    {
        var obj = await this.GetProperty<FileQuery[]>("supportedType").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task DeleteFile(string datastorePath)
    {
        await this.Session.VimClient.DeleteFile(this.VimReference, datastorePath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> SearchDatastore_Task(string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec)
    {
        var res = await this.Session.VimClient.SearchDatastore_Task(this.VimReference, datastorePath, searchSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SearchDatastoreSubFolders_Task(string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec)
    {
        var res = await this.Session.VimClient.SearchDatastoreSubFolders_Task(this.VimReference, datastorePath, searchSpec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostDatastoreSystemCapabilities>("capabilities").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore").ConfigureAwait(false);
        return datastore?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task ConfigureDatastorePrincipal(string userName, string? password)
    {
        await this.Session.VimClient.ConfigureDatastorePrincipal(this.VimReference, userName, password).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateLocalDatastore(string name, string path)
    {
        var res = await this.Session.VimClient.CreateLocalDatastore(this.VimReference, name, path).ConfigureAwait(false);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateNasDatastore(HostNasVolumeSpec spec)
    {
        var res = await this.Session.VimClient.CreateNasDatastore(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateVmfsDatastore(VmfsDatastoreCreateSpec spec)
    {
        var res = await this.Session.VimClient.CreateVmfsDatastore(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> CreateVvolDatastore(HostDatastoreSystemVvolDatastoreSpec spec)
    {
        var res = await this.Session.VimClient.CreateVvolDatastore(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableClusteredVmdkSupport(Datastore datastore)
    {
        await this.Session.VimClient.DisableClusteredVmdkSupport(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnableClusteredVmdkSupport(Datastore datastore)
    {
        await this.Session.VimClient.EnableClusteredVmdkSupport(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Datastore?> ExpandVmfsDatastore(Datastore datastore, VmfsDatastoreExpandSpec spec)
    {
        var res = await this.Session.VimClient.ExpandVmfsDatastore(this.VimReference, datastore.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore?> ExtendVmfsDatastore(Datastore datastore, VmfsDatastoreExtendSpec spec)
    {
        var res = await this.Session.VimClient.ExtendVmfsDatastore(this.VimReference, datastore.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableDisksForVmfs(Datastore? datastore)
    {
        return await this.Session.VimClient.QueryAvailableDisksForVmfs(this.VimReference, datastore?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<long> QueryMaxQueueDepth(Datastore datastore)
    {
        return await this.Session.VimClient.QueryMaxQueueDepth(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolumes()
    {
        return await this.Session.VimClient.QueryUnresolvedVmfsVolumes(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreCreateOptions(string devicePath, int? vmfsMajorVersion)
    {
        return await this.Session.VimClient.QueryVmfsDatastoreCreateOptions(this.VimReference, devicePath, vmfsMajorVersion ?? default, vmfsMajorVersion.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExpandOptions(Datastore datastore)
    {
        return await this.Session.VimClient.QueryVmfsDatastoreExpandOptions(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExtendOptions(Datastore datastore, string devicePath, bool? suppressExpandCandidates)
    {
        return await this.Session.VimClient.QueryVmfsDatastoreExtendOptions(this.VimReference, datastore.VimReference, devicePath, suppressExpandCandidates ?? default, suppressExpandCandidates.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveDatastore(Datastore datastore)
    {
        await this.Session.VimClient.RemoveDatastore(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveDatastoreEx_Task(Datastore[] datastore)
    {
        var res = await this.Session.VimClient.RemoveDatastoreEx_Task(this.VimReference, [.. datastore.Select(m => m.VimReference)]).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ResignatureUnresolvedVmfsVolume_Task(HostUnresolvedVmfsResignatureSpec resolutionSpec)
    {
        var res = await this.Session.VimClient.ResignatureUnresolvedVmfsVolume_Task(this.VimReference, resolutionSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ResolveNfsServerHostName(string hostName, string? volumeName, bool? force, bool? isNFS41)
    {
        await this.Session.VimClient.ResolveNfsServerHostName(this.VimReference, hostName, volumeName, force ?? default, force.HasValue, isNFS41 ?? default, isNFS41.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetMaxQueueDepth(Datastore datastore, long maxQdepth)
    {
        await this.Session.VimClient.SetMaxQueueDepth(this.VimReference, datastore.VimReference, maxQdepth).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateLocalSwapDatastore(Datastore? datastore)
    {
        await this.Session.VimClient.UpdateLocalSwapDatastore(this.VimReference, datastore?.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostDateTimeInfo>("dateTimeInfo").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemTimeZone[]?> QueryAvailableTimeZones()
    {
        return await this.Session.VimClient.QueryAvailableTimeZones(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DateTime> QueryDateTime()
    {
        return await this.Session.VimClient.QueryDateTime(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshDateTimeSystem()
    {
        await this.Session.VimClient.RefreshDateTimeSystem(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemServiceTestResult?> TestTimeService()
    {
        return await this.Session.VimClient.TestTimeService(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateDateTime(DateTime dateTime)
    {
        await this.Session.VimClient.UpdateDateTime(this.VimReference, dateTime).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateDateTimeConfig(HostDateTimeConfig config)
    {
        await this.Session.VimClient.UpdateDateTimeConfig(this.VimReference, config).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostDiagnosticPartition>("activePartition").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task CreateDiagnosticPartition(HostDiagnosticPartitionCreateSpec spec)
    {
        await this.Session.VimClient.CreateDiagnosticPartition(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartition[]?> QueryAvailablePartition()
    {
        return await this.Session.VimClient.QueryAvailablePartition(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateDescription?> QueryPartitionCreateDesc(string diskUuid, string diagnosticType)
    {
        return await this.Session.VimClient.QueryPartitionCreateDesc(this.VimReference, diskUuid, diagnosticType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateOption[]?> QueryPartitionCreateOptions(string storageType, string diagnosticType)
    {
        return await this.Session.VimClient.QueryPartitionCreateOptions(this.VimReference, storageType, diagnosticType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SelectActivePartition(HostScsiDiskPartition? partition)
    {
        await this.Session.VimClient.SelectActivePartition(this.VimReference, partition).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostEsxAgentHostManagerConfigInfo>("configInfo").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task EsxAgentHostManagerUpdateConfig(HostEsxAgentHostManagerConfigInfo configInfo)
    {
        await this.Session.VimClient.EsxAgentHostManagerUpdateConfig(this.VimReference, configInfo).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostFirewallInfo>("firewallInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task DisableRuleset(string id)
    {
        await this.Session.VimClient.DisableRuleset(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnableRuleset(string id)
    {
        await this.Session.VimClient.EnableRuleset(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshFirewall()
    {
        await this.Session.VimClient.RefreshFirewall(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateDefaultPolicy(HostFirewallDefaultPolicy defaultPolicy)
    {
        await this.Session.VimClient.UpdateDefaultPolicy(this.VimReference, defaultPolicy).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateRuleset(string id, HostFirewallRulesetRulesetSpec spec)
    {
        await this.Session.VimClient.UpdateRuleset(this.VimReference, id, spec).ConfigureAwait(false);
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
        return await this.Session.VimClient.BackupFirmwareConfiguration(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryFirmwareConfigUploadURL()
    {
        return await this.Session.VimClient.QueryFirmwareConfigUploadURL(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ResetFirmwareToFactoryDefaults()
    {
        await this.Session.VimClient.ResetFirmwareToFactoryDefaults(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RestoreFirmwareConfiguration(bool force)
    {
        await this.Session.VimClient.RestoreFirmwareConfiguration(this.VimReference, force).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostGraphicsConfig>("graphicsConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostGraphicsInfo[]?> GetPropertyGraphicsInfo()
    {
        var obj = await this.GetProperty<HostGraphicsInfo[]>("graphicsInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostSharedGpuCapabilities[]?> GetPropertySharedGpuCapabilities()
    {
        var obj = await this.GetProperty<HostSharedGpuCapabilities[]>("sharedGpuCapabilities").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertySharedPassthruGpuTypes()
    {
        var obj = await this.GetProperty<string[]>("sharedPassthruGpuTypes").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<bool> IsSharedGraphicsActive()
    {
        return await this.Session.VimClient.IsSharedGraphicsActive(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshGraphicsManager()
    {
        await this.Session.VimClient.RefreshGraphicsManager(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuDeviceInfo[]?> RetrieveVgpuDeviceInfo()
    {
        return await this.Session.VimClient.RetrieveVgpuDeviceInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuProfileInfo[]?> RetrieveVgpuProfileInfo()
    {
        return await this.Session.VimClient.RetrieveVgpuProfileInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateGraphicsConfig(HostGraphicsConfig config)
    {
        await this.Session.VimClient.UpdateGraphicsConfig(this.VimReference, config).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HealthSystemRuntime>("runtime").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task ClearSystemEventLog()
    {
        await this.Session.VimClient.ClearSystemEventLog(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<SystemEventInfo[]?> FetchSystemEventLog()
    {
        return await this.Session.VimClient.FetchSystemEventLog(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshHealthStatusSystem()
    {
        await this.Session.VimClient.RefreshHealthStatusSystem(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ResetSystemHealthInfo()
    {
        await this.Session.VimClient.ResetSystemHealthInfo(this.VimReference).ConfigureAwait(false);
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
        return await this.Session.VimClient.FetchSoftwarePackages(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> HostImageConfigGetAcceptance()
    {
        return await this.Session.VimClient.HostImageConfigGetAcceptance(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostImageProfileSummary?> HostImageConfigGetProfile()
    {
        return await this.Session.VimClient.HostImageConfigGetProfile(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DateTime> InstallDate()
    {
        return await this.Session.VimClient.InstallDate(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateHostImageAcceptanceLevel(string newAcceptanceLevel)
    {
        await this.Session.VimClient.UpdateHostImageAcceptanceLevel(this.VimReference, newAcceptanceLevel).ConfigureAwait(false);
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
        return await this.Session.VimClient.QueryConfiguredModuleOptionString(this.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<KernelModuleInfo[]?> QueryModules()
    {
        return await this.Session.VimClient.QueryModules(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateModuleOptionString(string name, string options)
    {
        await this.Session.VimClient.UpdateModuleOptionString(this.VimReference, name, options).ConfigureAwait(false);
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
        await this.Session.VimClient.AssignUserToGroup(this.VimReference, user, group).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ChangePassword(string user, string oldPassword, string newPassword)
    {
        await this.Session.VimClient.ChangePassword(this.VimReference, user, oldPassword, newPassword).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CreateGroup(HostAccountSpec group)
    {
        await this.Session.VimClient.CreateGroup(this.VimReference, group).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CreateUser(HostAccountSpec user)
    {
        await this.Session.VimClient.CreateUser(this.VimReference, user).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveGroup(string groupName)
    {
        await this.Session.VimClient.RemoveGroup(this.VimReference, groupName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveUser(string userName)
    {
        await this.Session.VimClient.RemoveUser(this.VimReference, userName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnassignUserFromGroup(string user, string group)
    {
        await this.Session.VimClient.UnassignUserFromGroup(this.VimReference, user, group).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateUser(HostAccountSpec user)
    {
        await this.Session.VimClient.UpdateUser(this.VimReference, user).ConfigureAwait(false);
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
        var obj = await this.GetProperty<ServiceConsoleReservationInfo>("consoleReservationInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineMemoryReservationInfo?> GetPropertyVirtualMachineReservationInfo()
    {
        var obj = await this.GetProperty<VirtualMachineMemoryReservationInfo>("virtualMachineReservationInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task ReconfigureServiceConsoleReservation(long cfgBytes)
    {
        await this.Session.VimClient.ReconfigureServiceConsoleReservation(this.VimReference, cfgBytes).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReconfigureVirtualMachineReservation(VirtualMachineMemoryReservationSpec spec)
    {
        await this.Session.VimClient.ReconfigureVirtualMachineReservation(this.VimReference, spec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostNetCapabilities>("capabilities").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostIpRouteConfig?> GetPropertyConsoleIpRouteConfig()
    {
        var obj = await this.GetProperty<HostIpRouteConfig>("consoleIpRouteConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostDnsConfig?> GetPropertyDnsConfig()
    {
        var obj = await this.GetProperty<HostDnsConfig>("dnsConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostIpRouteConfig?> GetPropertyIpRouteConfig()
    {
        var obj = await this.GetProperty<HostIpRouteConfig>("ipRouteConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostNetworkConfig?> GetPropertyNetworkConfig()
    {
        var obj = await this.GetProperty<HostNetworkConfig>("networkConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostNetworkInfo?> GetPropertyNetworkInfo()
    {
        var obj = await this.GetProperty<HostNetworkInfo>("networkInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostNetOffloadCapabilities?> GetPropertyOffloadCapabilities()
    {
        var obj = await this.GetProperty<HostNetOffloadCapabilities>("offloadCapabilities").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task AddPortGroup(HostPortGroupSpec portgrp)
    {
        await this.Session.VimClient.AddPortGroup(this.VimReference, portgrp).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> AddServiceConsoleVirtualNic(string portgroup, HostVirtualNicSpec nic)
    {
        return await this.Session.VimClient.AddServiceConsoleVirtualNic(this.VimReference, portgroup, nic).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> AddVirtualNic(string portgroup, HostVirtualNicSpec nic)
    {
        return await this.Session.VimClient.AddVirtualNic(this.VimReference, portgroup, nic).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task AddVirtualSwitch(string vswitchName, HostVirtualSwitchSpec? spec)
    {
        await this.Session.VimClient.AddVirtualSwitch(this.VimReference, vswitchName, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PhysicalNicHintInfo[]?> QueryNetworkHint(string[]? device)
    {
        return await this.Session.VimClient.QueryNetworkHint(this.VimReference, device).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshNetworkSystem()
    {
        await this.Session.VimClient.RefreshNetworkSystem(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemovePortGroup(string pgName)
    {
        await this.Session.VimClient.RemovePortGroup(this.VimReference, pgName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveServiceConsoleVirtualNic(string device)
    {
        await this.Session.VimClient.RemoveServiceConsoleVirtualNic(this.VimReference, device).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveVirtualNic(string device)
    {
        await this.Session.VimClient.RemoveVirtualNic(this.VimReference, device).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveVirtualSwitch(string vswitchName)
    {
        await this.Session.VimClient.RemoveVirtualSwitch(this.VimReference, vswitchName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RestartServiceConsoleVirtualNic(string device)
    {
        await this.Session.VimClient.RestartServiceConsoleVirtualNic(this.VimReference, device).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task StartDpuFailover(string dvsName, string? targetDpuAlias)
    {
        await this.Session.VimClient.StartDpuFailover(this.VimReference, dvsName, targetDpuAlias).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateConsoleIpRouteConfig(HostIpRouteConfig config)
    {
        await this.Session.VimClient.UpdateConsoleIpRouteConfig(this.VimReference, config).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateDnsConfig(HostDnsConfig config)
    {
        await this.Session.VimClient.UpdateDnsConfig(this.VimReference, config).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteConfig(HostIpRouteConfig config)
    {
        await this.Session.VimClient.UpdateIpRouteConfig(this.VimReference, config).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteTableConfig(HostIpRouteTableConfig config)
    {
        await this.Session.VimClient.UpdateIpRouteTableConfig(this.VimReference, config).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostNetworkConfigResult?> UpdateNetworkConfig(HostNetworkConfig config, string changeMode)
    {
        return await this.Session.VimClient.UpdateNetworkConfig(this.VimReference, config, changeMode).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdatePhysicalNicLinkSpeed(string device, PhysicalNicLinkInfo? linkSpeed)
    {
        await this.Session.VimClient.UpdatePhysicalNicLinkSpeed(this.VimReference, device, linkSpeed).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdatePortGroup(string pgName, HostPortGroupSpec portgrp)
    {
        await this.Session.VimClient.UpdatePortGroup(this.VimReference, pgName, portgrp).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateServiceConsoleVirtualNic(string device, HostVirtualNicSpec nic)
    {
        await this.Session.VimClient.UpdateServiceConsoleVirtualNic(this.VimReference, device, nic).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateVirtualNic(string device, HostVirtualNicSpec nic)
    {
        await this.Session.VimClient.UpdateVirtualNic(this.VimReference, device, nic).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateVirtualSwitch(string vswitchName, HostVirtualSwitchSpec spec)
    {
        await this.Session.VimClient.UpdateVirtualSwitch(this.VimReference, vswitchName, spec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<NvdimmSystemInfo>("nvdimmSystemInfo").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> CreateNvdimmNamespace_Task(NvdimmNamespaceCreateSpec createSpec)
    {
        var res = await this.Session.VimClient.CreateNvdimmNamespace_Task(this.VimReference, createSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateNvdimmPMemNamespace_Task(NvdimmPMemNamespaceCreateSpec createSpec)
    {
        var res = await this.Session.VimClient.CreateNvdimmPMemNamespace_Task(this.VimReference, createSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteNvdimmBlockNamespaces_Task()
    {
        var res = await this.Session.VimClient.DeleteNvdimmBlockNamespaces_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteNvdimmNamespace_Task(NvdimmNamespaceDeleteSpec deleteSpec)
    {
        var res = await this.Session.VimClient.DeleteNvdimmNamespace_Task(this.VimReference, deleteSpec).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.CheckHostPatch_Task(this.VimReference, metaUrls, bundleUrls, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InstallHostPatch_Task(HostPatchManagerLocator repository, string updateID, bool? force)
    {
        var res = await this.Session.VimClient.InstallHostPatch_Task(this.VimReference, repository, updateID, force ?? default, force.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InstallHostPatchV2_Task(string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.InstallHostPatchV2_Task(this.VimReference, metaUrls, bundleUrls, vibUrls, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> QueryHostPatch_Task(HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.QueryHostPatch_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ScanHostPatch_Task(HostPatchManagerLocator repository, string[]? updateID)
    {
        var res = await this.Session.VimClient.ScanHostPatch_Task(this.VimReference, repository, updateID).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ScanHostPatchV2_Task(string[]? metaUrls, string[]? bundleUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.ScanHostPatchV2_Task(this.VimReference, metaUrls, bundleUrls, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StageHostPatch_Task(string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.StageHostPatch_Task(this.VimReference, metaUrls, bundleUrls, vibUrls, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UninstallHostPatch_Task(string[]? bulletinIds, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var res = await this.Session.VimClient.UninstallHostPatch_Task(this.VimReference, bulletinIds, spec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostPciPassthruInfo[]>("pciPassthruInfo").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostSriovDevicePoolInfo[]?> GetPropertySriovDevicePoolInfo()
    {
        var obj = await this.GetProperty<HostSriovDevicePoolInfo[]>("sriovDevicePoolInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task Refresh()
    {
        await this.Session.VimClient.Refresh(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdatePassthruConfig(HostPciPassthruConfig[] config)
    {
        await this.Session.VimClient.UpdatePassthruConfig(this.VimReference, config).ConfigureAwait(false);
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
        var obj = await this.GetProperty<PowerSystemCapability>("capability").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<PowerSystemInfo> GetPropertyInfo()
    {
        var obj = await this.GetProperty<PowerSystemInfo>("info").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task ConfigurePowerPolicy(int key)
    {
        await this.Session.VimClient.ConfigurePowerPolicy(this.VimReference, key).ConfigureAwait(false);
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

    public async System.Threading.Tasks.Task<DateTime> GetPropertyComplianceCheckTime()
    {
        var obj = await this.GetProperty<DateTime>("complianceCheckTime").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostSystem?> GetPropertyReferenceHost()
    {
        var referenceHost = await this.GetProperty<ManagedObjectReference>("referenceHost").ConfigureAwait(false);
        return ManagedObject.Create<HostSystem>(referenceHost, this.Session);
    }

    public async System.Threading.Tasks.Task<HostProfileValidationFailureInfo?> GetPropertyValidationFailureInfo()
    {
        var obj = await this.GetProperty<HostProfileValidationFailureInfo>("validationFailureInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyValidationState()
    {
        var obj = await this.GetProperty<string>("validationState").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyValidationStateUpdateTime()
    {
        var obj = await this.GetProperty<DateTime>("validationStateUpdateTime").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ProfileExecuteResult?> ExecuteHostProfile(HostSystem host, ProfileDeferredPolicyOptionParameter[]? deferredParam)
    {
        return await this.Session.VimClient.ExecuteHostProfile(this.VimReference, host.VimReference, deferredParam).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task HostProfileResetValidationState()
    {
        await this.Session.VimClient.HostProfileResetValidationState(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateHostProfile(HostProfileConfigSpec config)
    {
        await this.Session.VimClient.UpdateHostProfile(this.VimReference, config).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateReferenceHost(HostSystem? host)
    {
        await this.Session.VimClient.UpdateReferenceHost(this.VimReference, host?.VimReference).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.ApplyEntitiesConfig_Task(this.VimReference, applyConfigSpecs).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ApplyHostConfig_Task(HostSystem host, HostConfigSpec configSpec, ProfileDeferredPolicyOptionParameter[]? userInput)
    {
        var res = await this.Session.VimClient.ApplyHostConfig_Task(this.VimReference, host.VimReference, configSpec, userInput).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckAnswerFileStatus_Task(HostSystem[] host)
    {
        var res = await this.Session.VimClient.CheckAnswerFileStatus_Task(this.VimReference, [.. host.Select(m => m.VimReference)]).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CompositeHostProfile_Task(Profile source, Profile[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toBeReplacedWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied)
    {
        var res = await this.Session.VimClient.CompositeHostProfile_Task(this.VimReference, source.VimReference, targets?.Select(m => m.VimReference).ToArray(), toBeMerged, toBeReplacedWith, toBeDeleted, enableStatusToBeCopied).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ApplyProfile?> CreateDefaultProfile(string profileType, string? profileTypeName, Profile? profile)
    {
        return await this.Session.VimClient.CreateDefaultProfile(this.VimReference, profileType, profileTypeName, profile?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ExportAnswerFile_Task(HostSystem host)
    {
        var res = await this.Session.VimClient.ExportAnswerFile_Task(this.VimReference, host.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostProfileManagerConfigTaskList?> GenerateConfigTaskList(HostConfigSpec configSpec, HostSystem host)
    {
        return await this.Session.VimClient.GenerateConfigTaskList(this.VimReference, configSpec, host.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> GenerateHostConfigTaskSpec_Task(StructuredCustomizations[]? hostsInfo)
    {
        var res = await this.Session.VimClient.GenerateHostConfigTaskSpec_Task(this.VimReference, hostsInfo).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> GenerateHostProfileTaskList_Task(HostConfigSpec configSpec, HostSystem host)
    {
        var res = await this.Session.VimClient.GenerateHostProfileTaskList_Task(this.VimReference, configSpec, host.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult[]?> QueryAnswerFileStatus(HostSystem[] host)
    {
        return await this.Session.VimClient.QueryAnswerFileStatus(this.VimReference, [.. host.Select(m => m.VimReference)]).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ProfileMetadata[]?> QueryHostProfileMetadata(string[]? profileName, Profile? profile)
    {
        return await this.Session.VimClient.QueryHostProfileMetadata(this.VimReference, profileName, profile?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ProfileProfileStructure?> QueryProfileStructure(Profile? profile)
    {
        return await this.Session.VimClient.QueryProfileStructure(this.VimReference, profile?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFile(HostSystem host)
    {
        return await this.Session.VimClient.RetrieveAnswerFile(this.VimReference, host.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFileForProfile(HostSystem host, HostApplyProfile applyProfile)
    {
        return await this.Session.VimClient.RetrieveAnswerFileForProfile(this.VimReference, host.VimReference, applyProfile).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizations(HostSystem[]? hosts)
    {
        return await this.Session.VimClient.RetrieveHostCustomizations(this.VimReference, hosts?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizationsForProfile(HostSystem[]? hosts, HostApplyProfile applyProfile)
    {
        return await this.Session.VimClient.RetrieveHostCustomizationsForProfile(this.VimReference, hosts?.Select(m => m.VimReference).ToArray(), applyProfile).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateAnswerFile_Task(HostSystem host, AnswerFileCreateSpec configSpec)
    {
        var res = await this.Session.VimClient.UpdateAnswerFile_Task(this.VimReference, host.VimReference, configSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ValidateHostProfileComposition_Task(Profile source, Profile[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toReplaceWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied, bool? errorOnly)
    {
        var res = await this.Session.VimClient.ValidateHostProfileComposition_Task(this.VimReference, source.VimReference, targets?.Select(m => m.VimReference).ToArray(), toBeMerged, toReplaceWith, toBeDeleted, enableStatusToBeCopied, errorOnly ?? default, errorOnly.HasValue).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostServiceInfo>("serviceInfo").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task RefreshServices()
    {
        await this.Session.VimClient.RefreshServices(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RestartService(string id)
    {
        await this.Session.VimClient.RestartService(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task StartService(string id)
    {
        await this.Session.VimClient.StartService(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task StopService(string id)
    {
        await this.Session.VimClient.StopService(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UninstallService(string id)
    {
        await this.Session.VimClient.UninstallService(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateServicePolicy(string id, string policy)
    {
        await this.Session.VimClient.UpdateServicePolicy(this.VimReference, id, policy).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostSnmpConfigSpec>("configuration").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostSnmpSystemAgentLimits> GetPropertyLimits()
    {
        var obj = await this.GetProperty<HostSnmpSystemAgentLimits>("limits").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task ReconfigureSnmpAgent(HostSnmpConfigSpec spec)
    {
        await this.Session.VimClient.ReconfigureSnmpAgent(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SendTestNotification()
    {
        await this.Session.VimClient.SendTestNotification(this.VimReference).ConfigureAwait(false);
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
        await this.Session.VimClient.DeleteHostSpecification(this.VimReference, host.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteHostSubSpecification(HostSystem host, string subSpecName)
    {
        await this.Session.VimClient.DeleteHostSubSpecification(this.VimReference, host.VimReference, subSpecName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostSystem[]?> HostSpecGetUpdatedHosts(string? startChangeID, string? endChangeID)
    {
        var res = await this.Session.VimClient.HostSpecGetUpdatedHosts(this.VimReference, startChangeID, endChangeID).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<HostSpecification?> RetrieveHostSpecification(HostSystem host, bool fromHost)
    {
        return await this.Session.VimClient.RetrieveHostSpecification(this.VimReference, host.VimReference, fromHost).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateHostSpecification(HostSystem host, HostSpecification hostSpec)
    {
        await this.Session.VimClient.UpdateHostSpecification(this.VimReference, host.VimReference, hostSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateHostSubSpecification(HostSystem host, HostSubSpecification hostSubSpec)
    {
        await this.Session.VimClient.UpdateHostSubSpecification(this.VimReference, host.VimReference, hostSubSpec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostFileSystemVolumeInfo>("fileSystemVolumeInfo").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostMultipathStateInfo?> GetPropertyMultipathStateInfo()
    {
        var obj = await this.GetProperty<HostMultipathStateInfo>("multipathStateInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostStorageDeviceInfo?> GetPropertyStorageDeviceInfo()
    {
        var obj = await this.GetProperty<HostStorageDeviceInfo>("storageDeviceInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertySystemFile()
    {
        var obj = await this.GetProperty<string[]>("systemFile").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task AddInternetScsiSendTargets(string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets)
    {
        await this.Session.VimClient.AddInternetScsiSendTargets(this.VimReference, iScsiHbaDevice, targets).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task AddInternetScsiStaticTargets(string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        await this.Session.VimClient.AddInternetScsiStaticTargets(this.VimReference, iScsiHbaDevice, targets).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task AttachScsiLun(string lunUuid)
    {
        await this.Session.VimClient.AttachScsiLun(this.VimReference, lunUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> AttachScsiLunEx_Task(string[] lunUuid)
    {
        var res = await this.Session.VimClient.AttachScsiLunEx_Task(this.VimReference, lunUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task AttachVmfsExtent(string vmfsPath, HostScsiDiskPartition extent)
    {
        await this.Session.VimClient.AttachVmfsExtent(this.VimReference, vmfsPath, extent).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ChangeNFSUserPassword(string password)
    {
        await this.Session.VimClient.ChangeNFSUserPassword(this.VimReference, password).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ClearNFSUser()
    {
        await this.Session.VimClient.ClearNFSUser(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfo(string devicePath, HostDiskPartitionLayout layout, string? partitionFormat)
    {
        return await this.Session.VimClient.ComputeDiskPartitionInfo(this.VimReference, devicePath, layout, partitionFormat).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfoForResize(HostScsiDiskPartition partition, HostDiskPartitionBlockRange blockRange, string? partitionFormat)
    {
        return await this.Session.VimClient.ComputeDiskPartitionInfoForResize(this.VimReference, partition, blockRange, partitionFormat).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ConnectNvmeController(HostNvmeConnectSpec connectSpec)
    {
        await this.Session.VimClient.ConnectNvmeController(this.VimReference, connectSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ConnectNvmeControllerEx_Task(HostNvmeConnectSpec[]? connectSpec)
    {
        var res = await this.Session.VimClient.ConnectNvmeControllerEx_Task(this.VimReference, connectSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CreateNvmeOverRdmaAdapter(string rdmaDeviceName)
    {
        await this.Session.VimClient.CreateNvmeOverRdmaAdapter(this.VimReference, rdmaDeviceName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CreateSoftwareAdapter(HostHbaCreateSpec spec)
    {
        await this.Session.VimClient.CreateSoftwareAdapter(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteScsiLunState(string lunCanonicalName)
    {
        await this.Session.VimClient.DeleteScsiLunState(this.VimReference, lunCanonicalName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteVffsVolumeState(string vffsUuid)
    {
        await this.Session.VimClient.DeleteVffsVolumeState(this.VimReference, vffsUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DeleteVmfsVolumeState(string vmfsUuid)
    {
        await this.Session.VimClient.DeleteVmfsVolumeState(this.VimReference, vmfsUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DestroyVffs(string vffsPath)
    {
        await this.Session.VimClient.DestroyVffs(this.VimReference, vffsPath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DetachScsiLun(string lunUuid)
    {
        await this.Session.VimClient.DetachScsiLun(this.VimReference, lunUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> DetachScsiLunEx_Task(string[] lunUuid)
    {
        var res = await this.Session.VimClient.DetachScsiLunEx_Task(this.VimReference, lunUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableMultipathPath(string pathName)
    {
        await this.Session.VimClient.DisableMultipathPath(this.VimReference, pathName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DisconnectNvmeController(HostNvmeDisconnectSpec disconnectSpec)
    {
        await this.Session.VimClient.DisconnectNvmeController(this.VimReference, disconnectSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> DisconnectNvmeControllerEx_Task(HostNvmeDisconnectSpec[]? disconnectSpec)
    {
        var res = await this.Session.VimClient.DisconnectNvmeControllerEx_Task(this.VimReference, disconnectSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DiscoverFcoeHbas(FcoeConfigFcoeSpecification fcoeSpec)
    {
        await this.Session.VimClient.DiscoverFcoeHbas(this.VimReference, fcoeSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostNvmeDiscoveryLog?> DiscoverNvmeControllers(HostNvmeDiscoverSpec discoverSpec)
    {
        return await this.Session.VimClient.DiscoverNvmeControllers(this.VimReference, discoverSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnableMultipathPath(string pathName)
    {
        await this.Session.VimClient.EnableMultipathPath(this.VimReference, pathName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ExpandVmfsExtent(string vmfsPath, HostScsiDiskPartition extent)
    {
        await this.Session.VimClient.ExpandVmfsExtent(this.VimReference, vmfsPath, extent).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ExtendVffs(string vffsPath, string devicePath, HostDiskPartitionSpec? spec)
    {
        await this.Session.VimClient.ExtendVffs(this.VimReference, vffsPath, devicePath, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostVffsVolume?> FormatVffs(HostVffsSpec createSpec)
    {
        return await this.Session.VimClient.FormatVffs(this.VimReference, createSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostVmfsVolume?> FormatVmfs(HostVmfsSpec createSpec)
    {
        return await this.Session.VimClient.FormatVmfs(this.VimReference, createSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsLocal_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsLocal_Task(this.VimReference, scsiDiskUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsNonLocal_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsNonLocal_Task(this.VimReference, scsiDiskUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsNonSsd_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsNonSsd_Task(this.VimReference, scsiDiskUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MarkAsSsd_Task(string scsiDiskUuid)
    {
        var res = await this.Session.VimClient.MarkAsSsd_Task(this.VimReference, scsiDiskUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MarkForRemoval(string hbaName, bool remove)
    {
        await this.Session.VimClient.MarkForRemoval(this.VimReference, hbaName, remove).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MarkPerenniallyReserved(string lunUuid, bool state)
    {
        await this.Session.VimClient.MarkPerenniallyReserved(this.VimReference, lunUuid, state).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> MarkPerenniallyReservedEx_Task(string[]? lunUuid, bool state)
    {
        var res = await this.Session.VimClient.MarkPerenniallyReservedEx_Task(this.VimReference, lunUuid, state).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MountVffsVolume(string vffsUuid)
    {
        await this.Session.VimClient.MountVffsVolume(this.VimReference, vffsUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MountVmfsVolume(string vmfsUuid)
    {
        await this.Session.VimClient.MountVmfsVolume(this.VimReference, vmfsUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> MountVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.VimClient.MountVmfsVolumeEx_Task(this.VimReference, vmfsUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableSsds(string? vffsPath)
    {
        return await this.Session.VimClient.QueryAvailableSsds(this.VimReference, vffsPath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostNasVolumeUserInfo?> QueryNFSUser()
    {
        return await this.Session.VimClient.QueryNFSUser(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostPathSelectionPolicyOption[]?> QueryPathSelectionPolicyOptions()
    {
        return await this.Session.VimClient.QueryPathSelectionPolicyOptions(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostStorageArrayTypePolicyOption[]?> QueryStorageArrayTypePolicyOptions()
    {
        return await this.Session.VimClient.QueryStorageArrayTypePolicyOptions(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolume()
    {
        return await this.Session.VimClient.QueryUnresolvedVmfsVolume(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VmfsConfigOption[]?> QueryVmfsConfigOption()
    {
        return await this.Session.VimClient.QueryVmfsConfigOption(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshStorageSystem()
    {
        await this.Session.VimClient.RefreshStorageSystem(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiSendTargets(string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets, bool? force)
    {
        await this.Session.VimClient.RemoveInternetScsiSendTargets(this.VimReference, iScsiHbaDevice, targets, force ?? default, force.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiStaticTargets(string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        await this.Session.VimClient.RemoveInternetScsiStaticTargets(this.VimReference, iScsiHbaDevice, targets).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveNvmeOverRdmaAdapter(string hbaDeviceName)
    {
        await this.Session.VimClient.RemoveNvmeOverRdmaAdapter(this.VimReference, hbaDeviceName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveSoftwareAdapter(string hbaDeviceName)
    {
        await this.Session.VimClient.RemoveSoftwareAdapter(this.VimReference, hbaDeviceName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RescanAllHba()
    {
        await this.Session.VimClient.RescanAllHba(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RescanHba(string hbaDevice)
    {
        await this.Session.VimClient.RescanHba(this.VimReference, hbaDevice).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RescanVffs()
    {
        await this.Session.VimClient.RescanVffs(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RescanVmfs()
    {
        await this.Session.VimClient.RescanVmfs(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsResolutionResult[]?> ResolveMultipleUnresolvedVmfsVolumes(HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        return await this.Session.VimClient.ResolveMultipleUnresolvedVmfsVolumes(this.VimReference, resolutionSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ResolveMultipleUnresolvedVmfsVolumesEx_Task(HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        var res = await this.Session.VimClient.ResolveMultipleUnresolvedVmfsVolumesEx_Task(this.VimReference, resolutionSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo[]?> RetrieveDiskPartitionInfo(string[] devicePath)
    {
        return await this.Session.VimClient.RetrieveDiskPartitionInfo(this.VimReference, devicePath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetMultipathLunPolicy(string lunId, HostMultipathInfoLogicalUnitPolicy policy)
    {
        await this.Session.VimClient.SetMultipathLunPolicy(this.VimReference, lunId, policy).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetNFSUser(string user, string password)
    {
        await this.Session.VimClient.SetNFSUser(this.VimReference, user, password).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> TurnDiskLocatorLedOff_Task(string[] scsiDiskUuids)
    {
        var res = await this.Session.VimClient.TurnDiskLocatorLedOff_Task(this.VimReference, scsiDiskUuids).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> TurnDiskLocatorLedOn_Task(string[] scsiDiskUuids)
    {
        var res = await this.Session.VimClient.TurnDiskLocatorLedOn_Task(this.VimReference, scsiDiskUuids).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnmapVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.VimClient.UnmapVmfsVolumeEx_Task(this.VimReference, vmfsUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UnmountForceMountedVmfsVolume(string vmfsUuid)
    {
        await this.Session.VimClient.UnmountForceMountedVmfsVolume(this.VimReference, vmfsUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnmountVffsVolume(string vffsUuid)
    {
        await this.Session.VimClient.UnmountVffsVolume(this.VimReference, vffsUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnmountVmfsVolume(string vmfsUuid)
    {
        await this.Session.VimClient.UnmountVmfsVolume(this.VimReference, vmfsUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> UnmountVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.VimClient.UnmountVmfsVolumeEx_Task(this.VimReference, vmfsUuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateDiskPartitions(string devicePath, HostDiskPartitionSpec spec)
    {
        await this.Session.VimClient.UpdateDiskPartitions(this.VimReference, devicePath, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateHppMultipathLunPolicy(string lunId, HostMultipathInfoHppLogicalUnitPolicy policy)
    {
        await this.Session.VimClient.UpdateHppMultipathLunPolicy(this.VimReference, lunId, policy).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAdvancedOptions(string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaParamValue[] options)
    {
        await this.Session.VimClient.UpdateInternetScsiAdvancedOptions(this.VimReference, iScsiHbaDevice, targetSet, options).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAlias(string iScsiHbaDevice, string iScsiAlias)
    {
        await this.Session.VimClient.UpdateInternetScsiAlias(this.VimReference, iScsiHbaDevice, iScsiAlias).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAuthenticationProperties(string iScsiHbaDevice, HostInternetScsiHbaAuthenticationProperties authenticationProperties, HostInternetScsiHbaTargetSet? targetSet)
    {
        await this.Session.VimClient.UpdateInternetScsiAuthenticationProperties(this.VimReference, iScsiHbaDevice, authenticationProperties, targetSet).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDigestProperties(string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaDigestProperties digestProperties)
    {
        await this.Session.VimClient.UpdateInternetScsiDigestProperties(this.VimReference, iScsiHbaDevice, targetSet, digestProperties).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDiscoveryProperties(string iScsiHbaDevice, HostInternetScsiHbaDiscoveryProperties discoveryProperties)
    {
        await this.Session.VimClient.UpdateInternetScsiDiscoveryProperties(this.VimReference, iScsiHbaDevice, discoveryProperties).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiIPProperties(string iScsiHbaDevice, HostInternetScsiHbaIPProperties ipProperties)
    {
        await this.Session.VimClient.UpdateInternetScsiIPProperties(this.VimReference, iScsiHbaDevice, ipProperties).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiName(string iScsiHbaDevice, string iScsiName)
    {
        await this.Session.VimClient.UpdateInternetScsiName(this.VimReference, iScsiHbaDevice, iScsiName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateScsiLunDisplayName(string lunUuid, string displayName)
    {
        await this.Session.VimClient.UpdateScsiLunDisplayName(this.VimReference, lunUuid, displayName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateSoftwareInternetScsiEnabled(bool enabled)
    {
        await this.Session.VimClient.UpdateSoftwareInternetScsiEnabled(this.VimReference, enabled).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapBandwidth(string vmfsUuid, VmfsUnmapBandwidthSpec unmapBandwidthSpec)
    {
        await this.Session.VimClient.UpdateVmfsUnmapBandwidth(this.VimReference, vmfsUuid, unmapBandwidthSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapPriority(string vmfsUuid, string unmapPriority)
    {
        await this.Session.VimClient.UpdateVmfsUnmapPriority(this.VimReference, vmfsUuid, unmapPriority).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpgradeVmfs(string vmfsPath)
    {
        await this.Session.VimClient.UpgradeVmfs(this.VimReference, vmfsPath).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpgradeVmLayout()
    {
        await this.Session.VimClient.UpgradeVmLayout(this.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<AnswerFileStatusResult>("answerFileValidationResult").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult?> GetPropertyAnswerFileValidationState()
    {
        var obj = await this.GetProperty<AnswerFileStatusResult>("answerFileValidationState").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostCapability?> GetPropertyCapability()
    {
        var obj = await this.GetProperty<HostCapability>("capability").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ComplianceResult?> GetPropertyComplianceCheckResult()
    {
        var obj = await this.GetProperty<ComplianceResult>("complianceCheckResult").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostSystemComplianceCheckState?> GetPropertyComplianceCheckState()
    {
        var obj = await this.GetProperty<HostSystemComplianceCheckState>("complianceCheckState").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostConfigInfo?> GetPropertyConfig()
    {
        var obj = await this.GetProperty<HostConfigInfo>("config").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostConfigManager> GetPropertyConfigManager()
    {
        var obj = await this.GetProperty<HostConfigManager>("configManager").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore").ConfigureAwait(false);
        return datastore?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<HostDatastoreBrowser> GetPropertyDatastoreBrowser()
    {
        var datastoreBrowser = await this.GetProperty<ManagedObjectReference>("datastoreBrowser").ConfigureAwait(false);
        return ManagedObject.Create<HostDatastoreBrowser>(datastoreBrowser, this.Session)!;
    }

    public async System.Threading.Tasks.Task<HostHardwareInfo?> GetPropertyHardware()
    {
        var obj = await this.GetProperty<HostHardwareInfo>("hardware").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostLicensableResourceInfo> GetPropertyLicensableResource()
    {
        var obj = await this.GetProperty<HostLicensableResourceInfo>("licensableResource").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network").ConfigureAwait(false);
        return network?.Select(r => ManagedObject.Create<Network>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ApplyHostProfileConfigurationSpec?> GetPropertyPrecheckRemediationResult()
    {
        var obj = await this.GetProperty<ApplyHostProfileConfigurationSpec>("precheckRemediationResult").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ApplyHostProfileConfigurationResult?> GetPropertyRemediationResult()
    {
        var obj = await this.GetProperty<ApplyHostProfileConfigurationResult>("remediationResult").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostSystemRemediationState?> GetPropertyRemediationState()
    {
        var obj = await this.GetProperty<HostSystemRemediationState>("remediationState").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<HostRuntimeInfo>("runtime").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostListSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<HostListSummary>("summary").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HostSystemResourceInfo?> GetPropertySystemResources()
    {
        var obj = await this.GetProperty<HostSystemResourceInfo>("systemResources").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm").ConfigureAwait(false);
        return vm?.Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<HostServiceTicket?> AcquireCimServicesTicket()
    {
        return await this.Session.VimClient.AcquireCimServicesTicket(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ConfigureCryptoKey(CryptoKeyId? keyId)
    {
        await this.Session.VimClient.ConfigureCryptoKey(this.VimReference, keyId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> DisconnectHost_Task()
    {
        var res = await this.Session.VimClient.DisconnectHost_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task EnableCrypto(CryptoKeyPlain keyPlain)
    {
        await this.Session.VimClient.EnableCrypto(this.VimReference, keyPlain).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task EnterLockdownMode()
    {
        await this.Session.VimClient.EnterLockdownMode(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> EnterMaintenanceMode_Task(int timeout, bool? evacuatePoweredOffVms, HostMaintenanceSpec? maintenanceSpec)
    {
        var res = await this.Session.VimClient.EnterMaintenanceMode_Task(this.VimReference, timeout, evacuatePoweredOffVms ?? default, evacuatePoweredOffVms.HasValue, maintenanceSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ExitLockdownMode()
    {
        await this.Session.VimClient.ExitLockdownMode(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ExitMaintenanceMode_Task(int timeout)
    {
        var res = await this.Session.VimClient.ExitMaintenanceMode_Task(this.VimReference, timeout).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerDownHostToStandBy_Task(int timeoutSec, bool? evacuatePoweredOffVms)
    {
        var res = await this.Session.VimClient.PowerDownHostToStandBy_Task(this.VimReference, timeoutSec, evacuatePoweredOffVms ?? default, evacuatePoweredOffVms.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerUpHostFromStandBy_Task(int timeoutSec)
    {
        var res = await this.Session.VimClient.PowerUpHostFromStandBy_Task(this.VimReference, timeoutSec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task PrepareCrypto()
    {
        await this.Session.VimClient.PrepareCrypto(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryHostConnectionInfo()
    {
        return await this.Session.VimClient.QueryHostConnectionInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverhead(long memorySize, int? videoRamSize, int numVcpus)
    {
        return await this.Session.VimClient.QueryMemoryOverhead(this.VimReference, memorySize, videoRamSize ?? default, videoRamSize.HasValue, numVcpus).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverheadEx(VirtualMachineConfigInfo vmConfigInfo)
    {
        return await this.Session.VimClient.QueryMemoryOverheadEx(this.VimReference, vmConfigInfo).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryProductLockerLocation()
    {
        return await this.Session.VimClient.QueryProductLockerLocation(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostTpmAttestationReport?> QueryTpmAttestationReport()
    {
        return await this.Session.VimClient.QueryTpmAttestationReport(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RebootHost_Task(bool force)
    {
        var res = await this.Session.VimClient.RebootHost_Task(this.VimReference, force).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigureHostForDAS_Task()
    {
        var res = await this.Session.VimClient.ReconfigureHostForDAS_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconnectHost_Task(HostConnectSpec? cnxSpec, HostSystemReconnectSpec? reconnectSpec)
    {
        var res = await this.Session.VimClient.ReconnectHost_Task(this.VimReference, cnxSpec, reconnectSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<long> RetrieveFreeEpcMemory()
    {
        return await this.Session.VimClient.RetrieveFreeEpcMemory(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<long> RetrieveHardwareUptime()
    {
        return await this.Session.VimClient.RetrieveHardwareUptime(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ShutdownHost_Task(bool force)
    {
        var res = await this.Session.VimClient.ShutdownHost_Task(this.VimReference, force).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateFlags(HostFlagInfo flagInfo)
    {
        await this.Session.VimClient.UpdateFlags(this.VimReference, flagInfo).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateIpmi(HostIpmiInfo ipmiInfo)
    {
        await this.Session.VimClient.UpdateIpmi(this.VimReference, ipmiInfo).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateProductLockerLocation_Task(string path)
    {
        var res = await this.Session.VimClient.UpdateProductLockerLocation_Task(this.VimReference, path).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateSystemResources(HostSystemResourceInfo resourceInfo)
    {
        await this.Session.VimClient.UpdateSystemResources(this.VimReference, resourceInfo).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateSystemSwapConfiguration(HostSystemSwapConfiguration sysSwapConfig)
    {
        await this.Session.VimClient.UpdateSystemSwapConfiguration(this.VimReference, sysSwapConfig).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostVFlashManagerVFlashConfigInfo>("vFlashConfigInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureVFlashResourceEx_Task(string[]? devicePath)
    {
        var res = await this.Session.VimClient.ConfigureVFlashResourceEx_Task(this.VimReference, devicePath).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HostConfigureVFlashResource(HostVFlashManagerVFlashResourceConfigSpec spec)
    {
        await this.Session.VimClient.HostConfigureVFlashResource(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task HostConfigVFlashCache(HostVFlashManagerVFlashCacheConfigSpec spec)
    {
        await this.Session.VimClient.HostConfigVFlashCache(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualDiskVFlashCacheConfigInfo?> HostGetVFlashModuleDefaultConfig(string vFlashModule)
    {
        return await this.Session.VimClient.HostGetVFlashModuleDefaultConfig(this.VimReference, vFlashModule).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task HostRemoveVFlashResource()
    {
        await this.Session.VimClient.HostRemoveVFlashResource(this.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostVirtualNicManagerInfo>("info").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task DeselectVnicForNicType(string nicType, string device)
    {
        await this.Session.VimClient.DeselectVnicForNicType(this.VimReference, nicType, device).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualNicManagerNetConfig?> QueryNetConfig(string nicType)
    {
        return await this.Session.VimClient.QueryNetConfig(this.VimReference, nicType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SelectVnicForNicType(string nicType, string device)
    {
        await this.Session.VimClient.SelectVnicForNicType(this.VimReference, nicType, device).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HostIpConfig>("ipConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HostVMotionNetConfig?> GetPropertyNetConfig()
    {
        var obj = await this.GetProperty<HostVMotionNetConfig>("netConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task DeselectVnic()
    {
        await this.Session.VimClient.DeselectVnic(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SelectVnic(string device)
    {
        await this.Session.VimClient.SelectVnic(this.VimReference, device).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateIpConfig(HostIpConfig ipConfig)
    {
        await this.Session.VimClient.UpdateIpConfig(this.VimReference, ipConfig).ConfigureAwait(false);
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
        return await this.Session.VimClient.AbdicateDomOwnership(this.VimReference, uuids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> CanProvisionObjects(VsanNewPolicyBatch[] npbs, bool? ignoreSatisfiability)
    {
        return await this.Session.VimClient.CanProvisionObjects(this.VimReference, npbs, ignoreSatisfiability ?? default, ignoreSatisfiability.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemDeleteVsanObjectsResult[]?> DeleteVsanObjects(string[] uuids, bool? force)
    {
        return await this.Session.VimClient.DeleteVsanObjects(this.VimReference, uuids, force ?? default, force.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> GetVsanObjExtAttrs(string[] uuids)
    {
        return await this.Session.VimClient.GetVsanObjExtAttrs(this.VimReference, uuids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryCmmds(HostVsanInternalSystemCmmdsQuery[] queries)
    {
        return await this.Session.VimClient.QueryCmmds(this.VimReference, queries).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryObjectsOnPhysicalVsanDisk(string[] disks)
    {
        return await this.Session.VimClient.QueryObjectsOnPhysicalVsanDisk(this.VimReference, disks).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryPhysicalVsanDisks(string[]? props)
    {
        return await this.Session.VimClient.QueryPhysicalVsanDisks(this.VimReference, props).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QuerySyncingVsanObjects(string[]? uuids)
    {
        return await this.Session.VimClient.QuerySyncingVsanObjects(this.VimReference, uuids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryVsanObjects(string[]? uuids)
    {
        return await this.Session.VimClient.QueryVsanObjects(this.VimReference, uuids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryVsanObjectUuidsByFilter(string[]? uuids, int? limit, int? version)
    {
        return await this.Session.VimClient.QueryVsanObjectUuidsByFilter(this.VimReference, uuids, limit ?? default, limit.HasValue, version ?? default, version.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryVsanStatistics(string[] labels)
    {
        return await this.Session.VimClient.QueryVsanStatistics(this.VimReference, labels).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> ReconfigurationSatisfiable(VsanPolicyChangeBatch[] pcbs, bool? ignoreSatisfiability)
    {
        return await this.Session.VimClient.ReconfigurationSatisfiable(this.VimReference, pcbs, ignoreSatisfiability ?? default, ignoreSatisfiability.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReconfigureDomObject(string uuid, string policy)
    {
        await this.Session.VimClient.ReconfigureDomObject(this.VimReference, uuid, policy).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanPhysicalDiskDiagnosticsResult[]?> RunVsanPhysicalDiskDiagnostics(string[]? disks)
    {
        return await this.Session.VimClient.RunVsanPhysicalDiskDiagnostics(this.VimReference, disks).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanObjectOperationResult[]?> UpgradeVsanObjects(string[] uuids, int newVersion)
    {
        return await this.Session.VimClient.UpgradeVsanObjects(this.VimReference, uuids, newVersion).ConfigureAwait(false);
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
        var obj = await this.GetProperty<VsanHostConfigInfo>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task?> AddDisks_Task(HostScsiDisk[] disk)
    {
        var res = await this.Session.VimClient.AddDisks_Task(this.VimReference, disk).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> EvacuateVsanNode_Task(HostMaintenanceSpec maintenanceSpec, int timeout)
    {
        var res = await this.Session.VimClient.EvacuateVsanNode_Task(this.VimReference, maintenanceSpec, timeout).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InitializeDisks_Task(VsanHostDiskMapping[] mapping)
    {
        var res = await this.Session.VimClient.InitializeDisks_Task(this.VimReference, mapping).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VsanHostDiskResult[]?> QueryDisksForVsan(string[]? canonicalName)
    {
        return await this.Session.VimClient.QueryDisksForVsan(this.VimReference, canonicalName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VsanHostClusterStatus?> QueryHostStatus()
    {
        return await this.Session.VimClient.QueryHostStatus(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RecommissionVsanNode_Task()
    {
        var res = await this.Session.VimClient.RecommissionVsanNode_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveDisk_Task(HostScsiDisk[] disk, HostMaintenanceSpec? maintenanceSpec, int? timeout)
    {
        var res = await this.Session.VimClient.RemoveDisk_Task(this.VimReference, disk, maintenanceSpec, timeout ?? default, timeout.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveDiskMapping_Task(VsanHostDiskMapping[] mapping, HostMaintenanceSpec? maintenanceSpec, int? timeout)
    {
        var res = await this.Session.VimClient.RemoveDiskMapping_Task(this.VimReference, mapping, maintenanceSpec, timeout ?? default, timeout.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnmountDiskMapping_Task(VsanHostDiskMapping[] mapping)
    {
        var res = await this.Session.VimClient.UnmountDiskMapping_Task(this.VimReference, mapping).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVsan_Task(VsanHostConfigInfo config)
    {
        var res = await this.Session.VimClient.UpdateVsan_Task(this.VimReference, config).ConfigureAwait(false);
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
        await this.Session.VimClient.HostClearVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> HostCloneVStorageObject_Task(ID id, Datastore datastore, VslmCloneSpec spec)
    {
        var res = await this.Session.VimClient.HostCloneVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostCreateDisk_Task(VslmCreateSpec spec)
    {
        var res = await this.Session.VimClient.HostCreateDisk_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostDeleteVStorageObject_Task(ID id, Datastore datastore, bool? isLcParentAttached)
    {
        var res = await this.Session.VimClient.HostDeleteVStorageObject_Task(this.VimReference, id, datastore.VimReference, isLcParentAttached ?? default, isLcParentAttached.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostDeleteVStorageObjectEx_Task(ID id, Datastore datastore, bool? isLcParentAttached)
    {
        var res = await this.Session.VimClient.HostDeleteVStorageObjectEx_Task(this.VimReference, id, datastore.VimReference, isLcParentAttached ?? default, isLcParentAttached.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostExtendDisk_Task(ID id, Datastore datastore, long newCapacityInMB)
    {
        var res = await this.Session.VimClient.HostExtendDisk_Task(this.VimReference, id, datastore.VimReference, newCapacityInMB).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostInflateDisk_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.HostInflateDisk_Task(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ID[]?> HostListVStorageObject(Datastore datastore)
    {
        return await this.Session.VimClient.HostListVStorageObject(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> HostQueryVirtualDiskUuid(string name)
    {
        return await this.Session.VimClient.HostQueryVirtualDiskUuid(this.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> HostReconcileDatastoreInventory_Task(Datastore datastore, bool? deepCleansing)
    {
        var res = await this.Session.VimClient.HostReconcileDatastoreInventory_Task(this.VimReference, datastore.VimReference, deepCleansing ?? default, deepCleansing.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> HostRegisterDisk(string path, string? name, bool? modifyControlFlags, ID? id)
    {
        return await this.Session.VimClient.HostRegisterDisk(this.VimReference, path, name, modifyControlFlags ?? default, modifyControlFlags.HasValue, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> HostRelocateVStorageObject_Task(ID id, Datastore datastore, VslmRelocateSpec spec, bool? isLcParentAttached)
    {
        var res = await this.Session.VimClient.HostRelocateVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec, isLcParentAttached ?? default, isLcParentAttached.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HostRenameVStorageObject(ID id, Datastore datastore, string name)
    {
        await this.Session.VimClient.HostRenameVStorageObject(this.VimReference, id, datastore.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> HostRetrieveVStorageInfrastructureObjectPolicy(Datastore datastore)
    {
        return await this.Session.VimClient.HostRetrieveVStorageInfrastructureObjectPolicy(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> HostRetrieveVStorageObject(ID id, Datastore datastore, string[]? diskInfoFlags)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObject(this.VimReference, id, datastore.VimReference, diskInfoFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<KeyValue[]?> HostRetrieveVStorageObjectMetadata(ID id, Datastore datastore, ID? snapshotId, string? prefix)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObjectMetadata(this.VimReference, id, datastore.VimReference, snapshotId, prefix).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> HostRetrieveVStorageObjectMetadataValue(ID id, Datastore datastore, ID? snapshotId, string key)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObjectMetadataValue(this.VimReference, id, datastore.VimReference, snapshotId, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> HostRetrieveVStorageObjectState(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.HostRetrieveVStorageObjectState(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task HostScheduleReconcileDatastoreInventory(Datastore datastore, bool? deepCleansing)
    {
        await this.Session.VimClient.HostScheduleReconcileDatastoreInventory(this.VimReference, datastore.VimReference, deepCleansing ?? default, deepCleansing.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> HostSetVirtualDiskUuid_Task(string name, string? uuid)
    {
        var res = await this.Session.VimClient.HostSetVirtualDiskUuid_Task(this.VimReference, name, uuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HostSetVStorageObjectControlFlags(ID id, Datastore datastore, string[]? controlFlags)
    {
        await this.Session.VimClient.HostSetVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> HostUpdateVStorageObjectMetadata_Task(ID id, Datastore datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var res = await this.Session.VimClient.HostUpdateVStorageObjectMetadata_Task(this.VimReference, id, datastore.VimReference, metadata, deleteKeys).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostUpdateVStorageObjectMetadataEx_Task(ID id, Datastore datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var res = await this.Session.VimClient.HostUpdateVStorageObjectMetadataEx_Task(this.VimReference, id, datastore.VimReference, metadata, deleteKeys).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectCreateDiskFromSnapshot_Task(ID id, Datastore datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path, string? provisioningType, bool? isLinkedClone, ID? targetId, Datastore? targetDatastore)
    {
        var res = await this.Session.VimClient.HostVStorageObjectCreateDiskFromSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId, name, profile, crypto, path, provisioningType, isLinkedClone ?? default, isLinkedClone.HasValue, targetId, targetDatastore?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectCreateSnapshot_Task(ID id, Datastore datastore, string description)
    {
        var res = await this.Session.VimClient.HostVStorageObjectCreateSnapshot_Task(this.VimReference, id, datastore.VimReference, description).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectDeleteSnapshot_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.HostVStorageObjectDeleteSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> HostVStorageObjectRetrieveSnapshotInfo(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.HostVStorageObjectRetrieveSnapshotInfo(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> HostVStorageObjectRevert_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.HostVStorageObjectRevert_Task(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
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
        var obj = await this.GetProperty<HttpNfcLeaseCapabilities>("capabilities").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault?> GetPropertyError()
    {
        var obj = await this.GetProperty<LocalizedMethodFault>("error").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseInfo?> GetPropertyInfo()
    {
        var obj = await this.GetProperty<HttpNfcLeaseInfo>("info").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyInitializeProgress()
    {
        var obj = await this.GetProperty<int>("initializeProgress").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyMode()
    {
        var obj = await this.GetProperty<string>("mode").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseState> GetPropertyState()
    {
        var obj = await this.GetProperty<HttpNfcLeaseState>("state").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyTransferProgress()
    {
        var obj = await this.GetProperty<int>("transferProgress").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseAbort(LocalizedMethodFault? fault)
    {
        await this.Session.VimClient.HttpNfcLeaseAbort(this.VimReference, fault).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseComplete()
    {
        await this.Session.VimClient.HttpNfcLeaseComplete(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseManifestEntry[]?> HttpNfcLeaseGetManifest()
    {
        return await this.Session.VimClient.HttpNfcLeaseGetManifest(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseProbeResult[]?> HttpNfcLeaseProbeUrls(HttpNfcLeaseSourceFile[]? files, int? timeout)
    {
        return await this.Session.VimClient.HttpNfcLeaseProbeUrls(this.VimReference, files, timeout ?? default, timeout.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseProgress(int percent)
    {
        await this.Session.VimClient.HttpNfcLeaseProgress(this.VimReference, percent).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> HttpNfcLeasePullFromUrls_Task(HttpNfcLeaseSourceFile[]? files)
    {
        var res = await this.Session.VimClient.HttpNfcLeasePullFromUrls_Task(this.VimReference, files).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseSetManifestChecksumType(KeyValue[]? deviceUrlsToChecksumTypes)
    {
        await this.Session.VimClient.HttpNfcLeaseSetManifestChecksumType(this.VimReference, deviceUrlsToChecksumTypes).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.CloseInventoryViewFolder(this.VimReference, [.. entity.Select(m => m.VimReference)]).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> OpenInventoryViewFolder(ManagedEntity[] entity)
    {
        var res = await this.Session.VimClient.OpenInventoryViewFolder(this.VimReference, [.. entity.Select(m => m.VimReference)]).ConfigureAwait(false);
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

    public async System.Threading.Tasks.Task<Task?> InitiateTransitionToVLCM_Task(ClusterComputeResource cluster)
    {
        var res = await this.Session.VimClient.InitiateTransitionToVLCM_Task(this.VimReference, cluster.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InstallIoFilter_Task(string vibUrl, ComputeResource compRes, IoFilterManagerSslTrust? vibSslTrust)
    {
        var res = await this.Session.VimClient.InstallIoFilter_Task(this.VimReference, vibUrl, compRes.VimReference, vibSslTrust).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualDiskId[]?> QueryDisksUsingFilter(string filterId, ComputeResource compRes)
    {
        return await this.Session.VimClient.QueryDisksUsingFilter(this.VimReference, filterId, compRes.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ClusterIoFilterInfo[]?> QueryIoFilterInfo(ComputeResource compRes)
    {
        return await this.Session.VimClient.QueryIoFilterInfo(this.VimReference, compRes.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IoFilterQueryIssueResult?> QueryIoFilterIssues(string filterId, ComputeResource compRes)
    {
        return await this.Session.VimClient.QueryIoFilterIssues(this.VimReference, filterId, compRes.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ResolveInstallationErrorsOnCluster_Task(string filterId, ClusterComputeResource cluster)
    {
        var res = await this.Session.VimClient.ResolveInstallationErrorsOnCluster_Task(this.VimReference, filterId, cluster.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ResolveInstallationErrorsOnHost_Task(string filterId, HostSystem host)
    {
        var res = await this.Session.VimClient.ResolveInstallationErrorsOnHost_Task(this.VimReference, filterId, host.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UninstallIoFilter_Task(string filterId, ComputeResource compRes)
    {
        var res = await this.Session.VimClient.UninstallIoFilter_Task(this.VimReference, filterId, compRes.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpgradeIoFilter_Task(string filterId, ComputeResource compRes, string vibUrl, IoFilterManagerSslTrust? vibSslTrust)
    {
        var res = await this.Session.VimClient.UpgradeIoFilter_Task(this.VimReference, filterId, compRes.VimReference, vibUrl, vibSslTrust).ConfigureAwait(false);
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
        return await this.Session.VimClient.AllocateIpv4Address(this.VimReference, dc.VimReference, poolId, allocationId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> AllocateIpv6Address(Datacenter dc, int poolId, string allocationId)
    {
        return await this.Session.VimClient.AllocateIpv6Address(this.VimReference, dc.VimReference, poolId, allocationId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<int> CreateIpPool(Datacenter dc, IpPool pool)
    {
        return await this.Session.VimClient.CreateIpPool(this.VimReference, dc.VimReference, pool).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DestroyIpPool(Datacenter dc, int id, bool force)
    {
        await this.Session.VimClient.DestroyIpPool(this.VimReference, dc.VimReference, id, force).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IpPoolManagerIpAllocation[]?> QueryIPAllocations(Datacenter dc, int poolId, string extensionKey)
    {
        return await this.Session.VimClient.QueryIPAllocations(this.VimReference, dc.VimReference, poolId, extensionKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IpPool[]?> QueryIpPools(Datacenter dc)
    {
        return await this.Session.VimClient.QueryIpPools(this.VimReference, dc.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReleaseIpAllocation(Datacenter dc, int poolId, string allocationId)
    {
        await this.Session.VimClient.ReleaseIpAllocation(this.VimReference, dc.VimReference, poolId, allocationId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateIpPool(Datacenter dc, IpPool pool)
    {
        await this.Session.VimClient.UpdateIpPool(this.VimReference, dc.VimReference, pool).ConfigureAwait(false);
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
        await this.Session.VimClient.BindVnic(this.VimReference, iScsiHbaName, vnicDevice).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryBoundVnics(string iScsiHbaName)
    {
        return await this.Session.VimClient.QueryBoundVnics(this.VimReference, iScsiHbaName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryCandidateNics(string iScsiHbaName)
    {
        return await this.Session.VimClient.QueryCandidateNics(this.VimReference, iScsiHbaName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IscsiMigrationDependency?> QueryMigrationDependencies(string[] pnicDevice)
    {
        return await this.Session.VimClient.QueryMigrationDependencies(this.VimReference, pnicDevice).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IscsiStatus?> QueryPnicStatus(string pnicDevice)
    {
        return await this.Session.VimClient.QueryPnicStatus(this.VimReference, pnicDevice).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<IscsiStatus?> QueryVnicStatus(string vnicDevice)
    {
        return await this.Session.VimClient.QueryVnicStatus(this.VimReference, vnicDevice).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnbindVnic(string iScsiHbaName, string vnicDevice, bool force)
    {
        await this.Session.VimClient.UnbindVnic(this.VimReference, iScsiHbaName, vnicDevice, force).ConfigureAwait(false);
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
        return await this.Session.VimClient.QueryAssignedLicenses(this.VimReference, entityId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveAssignedLicense(string entityId)
    {
        await this.Session.VimClient.RemoveAssignedLicense(this.VimReference, entityId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateAssignedLicense(string entity, string licenseKey, string? entityDisplayName)
    {
        return await this.Session.VimClient.UpdateAssignedLicense(this.VimReference, entity, licenseKey, entityDisplayName).ConfigureAwait(false);
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
        var obj = await this.GetProperty<LicenseDiagnostics>("diagnostics").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<LicenseManagerEvaluationInfo> GetPropertyEvaluation()
    {
        var obj = await this.GetProperty<LicenseManagerEvaluationInfo>("evaluation").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseFeatureInfo[]?> GetPropertyFeatureInfo()
    {
        var obj = await this.GetProperty<LicenseFeatureInfo[]>("featureInfo").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<LicenseAssignmentManager?> GetPropertyLicenseAssignmentManager()
    {
        var licenseAssignmentManager = await this.GetProperty<ManagedObjectReference>("licenseAssignmentManager").ConfigureAwait(false);
        return ManagedObject.Create<LicenseAssignmentManager>(licenseAssignmentManager, this.Session);
    }

    public async System.Threading.Tasks.Task<string> GetPropertyLicensedEdition()
    {
        var obj = await this.GetProperty<string>("licensedEdition").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo[]> GetPropertyLicenses()
    {
        var obj = await this.GetProperty<LicenseManagerLicenseInfo[]>("licenses").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseSource> GetPropertySource()
    {
        var obj = await this.GetProperty<LicenseSource>("source").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<bool> GetPropertySourceAvailable()
    {
        var obj = await this.GetProperty<bool>("sourceAvailable").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> AddLicense(string licenseKey, KeyValue[]? labels)
    {
        return await this.Session.VimClient.AddLicense(this.VimReference, licenseKey, labels).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> CheckLicenseFeature(HostSystem? host, string featureKey)
    {
        return await this.Session.VimClient.CheckLicenseFeature(this.VimReference, host?.VimReference, featureKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ConfigureLicenseSource(HostSystem? host, LicenseSource licenseSource)
    {
        await this.Session.VimClient.ConfigureLicenseSource(this.VimReference, host?.VimReference, licenseSource).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> DecodeLicense(string licenseKey)
    {
        return await this.Session.VimClient.DecodeLicense(this.VimReference, licenseKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> DisableFeature(HostSystem? host, string featureKey)
    {
        return await this.Session.VimClient.DisableFeature(this.VimReference, host?.VimReference, featureKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> EnableFeature(HostSystem? host, string featureKey)
    {
        return await this.Session.VimClient.EnableFeature(this.VimReference, host?.VimReference, featureKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LicenseAvailabilityInfo[]?> QueryLicenseSourceAvailability(HostSystem? host)
    {
        return await this.Session.VimClient.QueryLicenseSourceAvailability(this.VimReference, host?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LicenseUsageInfo?> QueryLicenseUsage(HostSystem? host)
    {
        return await this.Session.VimClient.QueryLicenseUsage(this.VimReference, host?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LicenseFeatureInfo[]?> QuerySupportedFeatures(HostSystem? host)
    {
        return await this.Session.VimClient.QuerySupportedFeatures(this.VimReference, host?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveLicense(string licenseKey)
    {
        await this.Session.VimClient.RemoveLicense(this.VimReference, licenseKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveLicenseLabel(string licenseKey, string labelKey)
    {
        await this.Session.VimClient.RemoveLicenseLabel(this.VimReference, licenseKey, labelKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetLicenseEdition(HostSystem? host, string? featureKey)
    {
        await this.Session.VimClient.SetLicenseEdition(this.VimReference, host?.VimReference, featureKey).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateLicense(string licenseKey, KeyValue[]? labels)
    {
        return await this.Session.VimClient.UpdateLicense(this.VimReference, licenseKey, labels).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateLicenseLabel(string licenseKey, string labelKey, string labelValue)
    {
        await this.Session.VimClient.UpdateLicenseLabel(this.VimReference, licenseKey, labelKey, labelValue).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.ModifyListView(this.VimReference, add?.Select(m => m.VimReference).ToArray(), remove?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedObject[]?> ResetListView(ManagedObject[]? obj)
    {
        var res = await this.Session.VimClient.ResetListView(this.VimReference, obj?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task ResetListViewFromView(View view)
    {
        await this.Session.VimClient.ResetListViewFromView(this.VimReference, view.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<LocalizationManagerMessageCatalog[]>("catalog").ConfigureAwait(false);
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
        var obj = await this.GetProperty<bool>("alarmActionsEnabled").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Event[]?> GetPropertyConfigIssue()
    {
        var obj = await this.GetProperty<Event[]>("configIssue").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyConfigStatus()
    {
        var obj = await this.GetProperty<ManagedEntityStatus>("configStatus").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<CustomFieldValue[]?> GetPropertyCustomValue()
    {
        var obj = await this.GetProperty<CustomFieldValue[]>("customValue").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<AlarmState[]?> GetPropertyDeclaredAlarmState()
    {
        var obj = await this.GetProperty<AlarmState[]>("declaredAlarmState").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyDisabledMethod()
    {
        var obj = await this.GetProperty<string[]>("disabledMethod").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<int[]?> GetPropertyEffectiveRole()
    {
        var obj = await this.GetProperty<int[]>("effectiveRole").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        var obj = await this.GetProperty<string>("name").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyOverallStatus()
    {
        var obj = await this.GetProperty<ManagedEntityStatus>("overallStatus").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> GetPropertyParent()
    {
        var parent = await this.GetProperty<ManagedObjectReference>("parent").ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(parent, this.Session);
    }

    public async System.Threading.Tasks.Task<Permission[]?> GetPropertyPermission()
    {
        var obj = await this.GetProperty<Permission[]>("permission").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task[]?> GetPropertyRecentTask()
    {
        var recentTask = await this.GetProperty<ManagedObjectReference[]>("recentTask").ConfigureAwait(false);
        return recentTask?.Select(r => ManagedObject.Create<Task>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Tag[]?> GetPropertyTag()
    {
        var obj = await this.GetProperty<Tag[]>("tag").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<AlarmState[]?> GetPropertyTriggeredAlarmState()
    {
        var obj = await this.GetProperty<AlarmState[]>("triggeredAlarmState").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> Destroy_Task()
    {
        var res = await this.Session.VimClient.Destroy_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task Reload()
    {
        await this.Session.VimClient.Reload(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> Rename_Task(string newName)
    {
        var res = await this.Session.VimClient.Rename_Task(this.VimReference, newName).ConfigureAwait(false);
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
        var view = await this.GetProperty<ManagedObjectReference[]>("view").ConfigureAwait(false);
        return view?.Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)!).ToArray();
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
        var host = await this.GetProperty<ManagedObjectReference[]>("host").ConfigureAwait(false);
        return host?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)!).ToArray();
    }

    public new async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        var obj = await this.GetProperty<string>("name").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<NetworkSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<NetworkSummary>("summary").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm").ConfigureAwait(false);
        return vm?.Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task DestroyNetwork()
    {
        await this.Session.VimClient.DestroyNetwork(this.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<OpaqueNetworkCapability>("capability").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<OptionValue[]?> GetPropertyExtraConfig()
    {
        var obj = await this.GetProperty<OptionValue[]>("extraConfig").ConfigureAwait(false);
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
        var obj = await this.GetProperty<OptionValue[]>("setting").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<OptionDef[]?> GetPropertySupportedOption()
    {
        var obj = await this.GetProperty<OptionDef[]>("supportedOption").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<OptionValue[]?> QueryOptions(string? name)
    {
        return await this.Session.VimClient.QueryOptions(this.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateOptions(OptionValue[] changedValue)
    {
        await this.Session.VimClient.UpdateOptions(this.VimReference, changedValue).ConfigureAwait(false);
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
        return await this.Session.VimClient.LookupVmOverheadMemory(this.VimReference, vm.VimReference, host.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<OvfOptionInfo[]>("ovfExportOption").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<OvfOptionInfo[]?> GetPropertyOvfImportOption()
    {
        var obj = await this.GetProperty<OvfOptionInfo[]>("ovfImportOption").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<OvfCreateDescriptorResult?> CreateDescriptor(ManagedEntity obj, OvfCreateDescriptorParams cdp)
    {
        return await this.Session.VimClient.CreateDescriptor(this.VimReference, obj.VimReference, cdp).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<OvfCreateImportSpecResult?> CreateImportSpec(string ovfDescriptor, ResourcePool resourcePool, Datastore datastore, OvfCreateImportSpecParams cisp)
    {
        return await this.Session.VimClient.CreateImportSpec(this.VimReference, ovfDescriptor, resourcePool.VimReference, datastore.VimReference, cisp).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<OvfParseDescriptorResult?> ParseDescriptor(string ovfDescriptor, OvfParseDescriptorParams pdp)
    {
        return await this.Session.VimClient.ParseDescriptor(this.VimReference, ovfDescriptor, pdp).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<OvfValidateHostResult?> ValidateHost(string ovfDescriptor, HostSystem host, OvfValidateHostParams vhp)
    {
        return await this.Session.VimClient.ValidateHost(this.VimReference, ovfDescriptor, host.VimReference, vhp).ConfigureAwait(false);
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
        var obj = await this.GetProperty<PerformanceDescription>("description").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<PerfInterval[]?> GetPropertyHistoricalInterval()
    {
        var obj = await this.GetProperty<PerfInterval[]>("historicalInterval").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> GetPropertyPerfCounter()
    {
        var obj = await this.GetProperty<PerfCounterInfo[]>("perfCounter").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task CreatePerfInterval(PerfInterval intervalId)
    {
        await this.Session.VimClient.CreatePerfInterval(this.VimReference, intervalId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PerfMetricId[]?> QueryAvailablePerfMetric(ManagedObject entity, DateTime? beginTime, DateTime? endTime, int? intervalId)
    {
        return await this.Session.VimClient.QueryAvailablePerfMetric(this.VimReference, entity.VimReference, beginTime ?? default, beginTime.HasValue, endTime ?? default, endTime.HasValue, intervalId ?? default, intervalId.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PerfEntityMetricBase[]?> QueryPerf(PerfQuerySpec[] querySpec)
    {
        return await this.Session.VimClient.QueryPerf(this.VimReference, querySpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PerfCompositeMetric?> QueryPerfComposite(PerfQuerySpec querySpec)
    {
        return await this.Session.VimClient.QueryPerfComposite(this.VimReference, querySpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounter(int[] counterId)
    {
        return await this.Session.VimClient.QueryPerfCounter(this.VimReference, counterId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounterByLevel(int level)
    {
        return await this.Session.VimClient.QueryPerfCounterByLevel(this.VimReference, level).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PerfProviderSummary?> QueryPerfProviderSummary(ManagedObject entity)
    {
        return await this.Session.VimClient.QueryPerfProviderSummary(this.VimReference, entity.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemovePerfInterval(int samplePeriod)
    {
        await this.Session.VimClient.RemovePerfInterval(this.VimReference, samplePeriod).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ResetCounterLevelMapping(int[] counters)
    {
        await this.Session.VimClient.ResetCounterLevelMapping(this.VimReference, counters).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateCounterLevelMapping(PerformanceManagerCounterLevelMapping[] counterLevelMap)
    {
        await this.Session.VimClient.UpdateCounterLevelMapping(this.VimReference, counterLevelMap).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdatePerfInterval(PerfInterval interval)
    {
        await this.Session.VimClient.UpdatePerfInterval(this.VimReference, interval).ConfigureAwait(false);
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
        var obj = await this.GetProperty<string>("complianceStatus").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ProfileConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<ProfileConfigInfo>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyCreatedTime()
    {
        var obj = await this.GetProperty<DateTime>("createdTime").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ProfileDescription?> GetPropertyDescription()
    {
        var obj = await this.GetProperty<ProfileDescription>("description").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> GetPropertyEntity()
    {
        var entity = await this.GetProperty<ManagedObjectReference[]>("entity").ConfigureAwait(false);
        return entity?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyModifiedTime()
    {
        var obj = await this.GetProperty<DateTime>("modifiedTime").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        var obj = await this.GetProperty<string>("name").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task AssociateProfile(ManagedEntity[] entity)
    {
        await this.Session.VimClient.AssociateProfile(this.VimReference, [.. entity.Select(m => m.VimReference)]).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> CheckProfileCompliance_Task(ManagedEntity[]? entity)
    {
        var res = await this.Session.VimClient.CheckProfileCompliance_Task(this.VimReference, entity?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyProfile()
    {
        await this.Session.VimClient.DestroyProfile(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task DissociateProfile(ManagedEntity[]? entity)
    {
        await this.Session.VimClient.DissociateProfile(this.VimReference, entity?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> ExportProfile()
    {
        return await this.Session.VimClient.ExportProfile(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ProfileDescription?> RetrieveDescription()
    {
        return await this.Session.VimClient.RetrieveDescription(this.VimReference).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.CheckCompliance_Task(this.VimReference, profile?.Select(m => m.VimReference).ToArray(), entity?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ClearComplianceStatus(Profile[]? profile, ManagedEntity[]? entity)
    {
        await this.Session.VimClient.ClearComplianceStatus(this.VimReference, profile?.Select(m => m.VimReference).ToArray(), entity?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ComplianceResult[]?> QueryComplianceStatus(Profile[]? profile, ManagedEntity[]? entity)
    {
        return await this.Session.VimClient.QueryComplianceStatus(this.VimReference, profile?.Select(m => m.VimReference).ToArray(), entity?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ProfileExpressionMetadata[]?> QueryExpressionMetadata(string[]? expressionName, Profile? profile)
    {
        return await this.Session.VimClient.QueryExpressionMetadata(this.VimReference, expressionName, profile?.VimReference).ConfigureAwait(false);
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
        var profile = await this.GetProperty<ManagedObjectReference[]>("profile").ConfigureAwait(false);
        return profile?.Select(r => ManagedObject.Create<Profile>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Profile?> CreateProfile(ProfileCreateSpec createSpec)
    {
        var res = await this.Session.VimClient.CreateProfile(this.VimReference, createSpec).ConfigureAwait(false);
        return ManagedObject.Create<Profile>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Profile[]?> FindAssociatedProfile(ManagedEntity entity)
    {
        var res = await this.Session.VimClient.FindAssociatedProfile(this.VimReference, entity.VimReference).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<Profile>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ProfilePolicyMetadata[]?> QueryPolicyMetadata(string[]? policyName, Profile? profile)
    {
        return await this.Session.VimClient.QueryPolicyMetadata(this.VimReference, policyName, profile?.VimReference).ConfigureAwait(false);
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
        var filter = await this.GetProperty<ManagedObjectReference[]>("filter").ConfigureAwait(false);
        return filter?.Select(r => ManagedObject.Create<PropertyFilter>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task CancelRetrievePropertiesEx(string token)
    {
        await this.Session.VimClient.CancelRetrievePropertiesEx(this.VimReference, token).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task CancelWaitForUpdates()
    {
        await this.Session.VimClient.CancelWaitForUpdates(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UpdateSet?> CheckForUpdates(string? version)
    {
        return await this.Session.VimClient.CheckForUpdates(this.VimReference, version).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<RetrieveResult?> ContinueRetrievePropertiesEx(string token)
    {
        return await this.Session.VimClient.ContinueRetrievePropertiesEx(this.VimReference, token).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PropertyFilter?> CreateFilter(PropertyFilterSpec spec, bool partialUpdates)
    {
        var res = await this.Session.VimClient.CreateFilter(this.VimReference, spec, partialUpdates).ConfigureAwait(false);
        return ManagedObject.Create<PropertyFilter>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<PropertyCollector?> CreatePropertyCollector()
    {
        var res = await this.Session.VimClient.CreatePropertyCollector(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<PropertyCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyPropertyCollector()
    {
        await this.Session.VimClient.DestroyPropertyCollector(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ObjectContent[]?> RetrieveProperties(PropertyFilterSpec[] specSet)
    {
        return await this.Session.VimClient.RetrieveProperties(this.VimReference, specSet).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<RetrieveResult?> RetrievePropertiesEx(PropertyFilterSpec[] specSet, RetrieveOptions options)
    {
        return await this.Session.VimClient.RetrievePropertiesEx(this.VimReference, specSet, options).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UpdateSet?> WaitForUpdates(string? version)
    {
        return await this.Session.VimClient.WaitForUpdates(this.VimReference, version).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UpdateSet?> WaitForUpdatesEx(string? version, WaitOptions? options)
    {
        return await this.Session.VimClient.WaitForUpdatesEx(this.VimReference, version, options).ConfigureAwait(false);
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
        var obj = await this.GetProperty<bool>("partialUpdates").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<PropertyFilterSpec> GetPropertySpec()
    {
        var obj = await this.GetProperty<PropertyFilterSpec>("spec").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task DestroyPropertyFilter()
    {
        await this.Session.VimClient.DestroyPropertyFilter(this.VimReference).ConfigureAwait(false);
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
        return await this.Session.VimClient.EstimateDatabaseSize(this.VimReference, dbSizeParam).ConfigureAwait(false);
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
        var obj = await this.GetProperty<ResourceConfigSpec[]>("childConfiguration").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ResourceConfigSpec> GetPropertyConfig()
    {
        var obj = await this.GetProperty<ResourceConfigSpec>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyNamespace()
    {
        var obj = await this.GetProperty<string>("namespace").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ComputeResource> GetPropertyOwner()
    {
        var owner = await this.GetProperty<ManagedObjectReference>("owner").ConfigureAwait(false);
        return ManagedObject.Create<ComputeResource>(owner, this.Session)!;
    }

    public async System.Threading.Tasks.Task<ResourcePool[]?> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference[]>("resourcePool").ConfigureAwait(false);
        return resourcePool?.Select(r => ManagedObject.Create<ResourcePool>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ResourcePoolRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<ResourcePoolRuntimeInfo>("runtime").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ResourcePoolSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<ResourcePoolSummary>("summary").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]?> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm").ConfigureAwait(false);
        return vm?.Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Task?> CreateChildVM_Task(VirtualMachineConfigSpec config, HostSystem? host)
    {
        var res = await this.Session.VimClient.CreateChildVM_Task(this.VimReference, config, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ResourcePool?> CreateResourcePool(string name, ResourceConfigSpec spec)
    {
        var res = await this.Session.VimClient.CreateResourcePool(this.VimReference, name, spec).ConfigureAwait(false);
        return ManagedObject.Create<ResourcePool>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualApp?> CreateVApp(string name, ResourceConfigSpec resSpec, VAppConfigSpec configSpec, Folder? vmFolder)
    {
        var res = await this.Session.VimClient.CreateVApp(this.VimReference, name, resSpec, configSpec, vmFolder?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<VirtualApp>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyChildren()
    {
        await this.Session.VimClient.DestroyChildren(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ImportVApp(ImportSpec spec, Folder? folder, HostSystem? host)
    {
        var res = await this.Session.VimClient.ImportVApp(this.VimReference, spec, folder?.VimReference, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MoveIntoResourcePool(ManagedEntity[] list)
    {
        await this.Session.VimClient.MoveIntoResourcePool(this.VimReference, [.. list.Select(m => m.VimReference)]).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ResourceConfigOption?> QueryResourceConfigOption()
    {
        return await this.Session.VimClient.QueryResourceConfigOption(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshRuntime()
    {
        await this.Session.VimClient.RefreshRuntime(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RegisterChildVM_Task(string path, string? name, HostSystem? host)
    {
        var res = await this.Session.VimClient.RegisterChildVM_Task(this.VimReference, path, name, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateChildResourceConfiguration(ResourceConfigSpec[] spec)
    {
        await this.Session.VimClient.UpdateChildResourceConfiguration(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateConfig(string? name, ResourceConfigSpec? config)
    {
        await this.Session.VimClient.UpdateConfig(this.VimReference, name, config).ConfigureAwait(false);
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
        var obj = await this.GetProperty<ScheduledTaskInfo>("info").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task ReconfigureScheduledTask(ScheduledTaskSpec spec)
    {
        await this.Session.VimClient.ReconfigureScheduledTask(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RemoveScheduledTask()
    {
        await this.Session.VimClient.RemoveScheduledTask(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RunScheduledTask()
    {
        await this.Session.VimClient.RunScheduledTask(this.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<ScheduledTaskDescription>("description").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]?> GetPropertyScheduledTask()
    {
        var scheduledTask = await this.GetProperty<ManagedObjectReference[]>("scheduledTask").ConfigureAwait(false);
        return scheduledTask?.Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ScheduledTask?> CreateObjectScheduledTask(ManagedObject obj, ScheduledTaskSpec spec)
    {
        var res = await this.Session.VimClient.CreateObjectScheduledTask(this.VimReference, obj.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<ScheduledTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ScheduledTask?> CreateScheduledTask(ManagedEntity entity, ScheduledTaskSpec spec)
    {
        var res = await this.Session.VimClient.CreateScheduledTask(this.VimReference, entity.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<ScheduledTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]?> RetrieveEntityScheduledTask(ManagedEntity? entity)
    {
        var res = await this.Session.VimClient.RetrieveEntityScheduledTask(this.VimReference, entity?.VimReference).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]?> RetrieveObjectScheduledTask(ManagedObject? obj)
    {
        var res = await this.Session.VimClient.RetrieveObjectScheduledTask(this.VimReference, obj?.VimReference).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.FindAllByDnsName(this.VimReference, datacenter?.VimReference, dnsName, vmSearch).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> FindAllByIp(Datacenter? datacenter, string ip, bool vmSearch)
    {
        var res = await this.Session.VimClient.FindAllByIp(this.VimReference, datacenter?.VimReference, ip, vmSearch).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> FindAllByUuid(Datacenter? datacenter, string uuid, bool vmSearch, bool? instanceUuid)
    {
        var res = await this.Session.VimClient.FindAllByUuid(this.VimReference, datacenter?.VimReference, uuid, vmSearch, instanceUuid ?? default, instanceUuid.HasValue).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachine?> FindByDatastorePath(Datacenter datacenter, string path)
    {
        var res = await this.Session.VimClient.FindByDatastorePath(this.VimReference, datacenter.VimReference, path).ConfigureAwait(false);
        return ManagedObject.Create<VirtualMachine>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByDnsName(Datacenter? datacenter, string dnsName, bool vmSearch)
    {
        var res = await this.Session.VimClient.FindByDnsName(this.VimReference, datacenter?.VimReference, dnsName, vmSearch).ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByInventoryPath(string inventoryPath)
    {
        var res = await this.Session.VimClient.FindByInventoryPath(this.VimReference, inventoryPath).ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByIp(Datacenter? datacenter, string ip, bool vmSearch)
    {
        var res = await this.Session.VimClient.FindByIp(this.VimReference, datacenter?.VimReference, ip, vmSearch).ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindByUuid(Datacenter? datacenter, string uuid, bool vmSearch, bool? instanceUuid)
    {
        var res = await this.Session.VimClient.FindByUuid(this.VimReference, datacenter?.VimReference, uuid, vmSearch, instanceUuid ?? default, instanceUuid.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> FindChild(ManagedEntity entity, string name)
    {
        var res = await this.Session.VimClient.FindChild(this.VimReference, entity.VimReference, name).ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<SearchIndexResultSet?> Query(SearchIndexQuerySpec querySpec)
    {
        return await this.Session.VimClient.Query(this.VimReference, querySpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<SearchIndexResultSet?> QueryNext(SearchIndexIterationSpec iterationSpec)
    {
        return await this.Session.VimClient.QueryNext(this.VimReference, iterationSpec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<Capability>("capability").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ServiceContent> GetPropertyContent()
    {
        var obj = await this.GetProperty<ServiceContent>("content").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyServerClock()
    {
        var obj = await this.GetProperty<DateTime>("serverClock").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<DateTime> CurrentTime()
    {
        return await this.Session.VimClient.CurrentTime(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostVMotionCompatibility[]?> QueryVMotionCompatibility(VirtualMachine vm, HostSystem[] host, string[]? compatibility)
    {
        return await this.Session.VimClient.QueryVMotionCompatibility(this.VimReference, vm.VimReference, [.. host.Select(m => m.VimReference)], compatibility).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ProductComponentInfo[]?> RetrieveProductComponents()
    {
        return await this.Session.VimClient.RetrieveProductComponents(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ServiceContent?> RetrieveServiceContent()
    {
        return await this.Session.VimClient.RetrieveServiceContent(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Event[]?> ValidateMigration(VirtualMachine[] vm, VirtualMachinePowerState? state, string[]? testType, ResourcePool? pool, HostSystem? host)
    {
        return await this.Session.VimClient.ValidateMigration(this.VimReference, [.. vm.Select(m => m.VimReference)], state ?? default, state.HasValue, testType, pool?.VimReference, host?.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<ServiceManagerServiceInfo[]>("service").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo[]?> QueryServiceList(string? serviceName, string[]? location)
    {
        return await this.Session.VimClient.QueryServiceList(this.VimReference, serviceName, location).ConfigureAwait(false);
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
        var obj = await this.GetProperty<UserSession>("currentSession").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string> GetPropertyDefaultLocale()
    {
        var obj = await this.GetProperty<string>("defaultLocale").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> GetPropertyMessage()
    {
        var obj = await this.GetProperty<string>("message").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertyMessageLocaleList()
    {
        var obj = await this.GetProperty<string[]>("messageLocaleList").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<UserSession[]?> GetPropertySessionList()
    {
        var obj = await this.GetProperty<UserSession[]>("sessionList").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string[]?> GetPropertySupportedLocaleList()
    {
        var obj = await this.GetProperty<string[]>("supportedLocaleList").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<string?> AcquireCloneTicket()
    {
        return await this.Session.VimClient.AcquireCloneTicket(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<SessionManagerGenericServiceTicket?> AcquireGenericServiceTicket(SessionManagerServiceRequestSpec spec)
    {
        return await this.Session.VimClient.AcquireGenericServiceTicket(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<SessionManagerLocalTicket?> AcquireLocalTicket(string userName)
    {
        return await this.Session.VimClient.AcquireLocalTicket(this.VimReference, userName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> CloneSession(string cloneTicket)
    {
        return await this.Session.VimClient.CloneSession(this.VimReference, cloneTicket).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> ImpersonateUser(string userName, string? locale)
    {
        return await this.Session.VimClient.ImpersonateUser(this.VimReference, userName, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> Login(string userName, string password, string? locale)
    {
        return await this.Session.VimClient.Login(this.VimReference, userName, password, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginBySSPI(string base64Token, string? locale)
    {
        return await this.Session.VimClient.LoginBySSPI(this.VimReference, base64Token, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginByToken(string? locale)
    {
        return await this.Session.VimClient.LoginByToken(this.VimReference, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginExtensionByCertificate(string extensionKey, string? locale)
    {
        return await this.Session.VimClient.LoginExtensionByCertificate(this.VimReference, extensionKey, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginExtensionBySubjectName(string extensionKey, string? locale)
    {
        return await this.Session.VimClient.LoginExtensionBySubjectName(this.VimReference, extensionKey, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task Logout()
    {
        await this.Session.VimClient.Logout(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<bool> SessionIsActive(string sessionID, string userName)
    {
        return await this.Session.VimClient.SessionIsActive(this.VimReference, sessionID, userName).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetLocale(string locale)
    {
        await this.Session.VimClient.SetLocale(this.VimReference, locale).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task TerminateSession(string[] sessionId)
    {
        await this.Session.VimClient.TerminateSession(this.VimReference, sessionId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateServiceMessage(string message)
    {
        await this.Session.VimClient.UpdateServiceMessage(this.VimReference, message).ConfigureAwait(false);
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
        var obj = await this.GetProperty<string>("encodingType").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo> GetPropertyEntity()
    {
        var obj = await this.GetProperty<ServiceManagerServiceInfo>("entity").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<string?> ExecuteSimpleCommand(string[]? arguments)
    {
        return await this.Session.VimClient.ExecuteSimpleCommand(this.VimReference, arguments).ConfigureAwait(false);
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
        return await this.Session.VimClient.GetSiteInfo(this.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<PodStorageDrsEntry>("podStorageDrsEntry").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<StoragePodSummary?> GetPropertySummary()
    {
        var obj = await this.GetProperty<StoragePodSummary>("summary").ConfigureAwait(false);
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
        var res = await this.Session.VimClient.QueryHostsWithAttachedLun(this.VimReference, lunUuid).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.ApplyStorageDrsRecommendation_Task(this.VimReference, key).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ApplyStorageDrsRecommendationToPod_Task(StoragePod pod, string key)
    {
        var res = await this.Session.VimClient.ApplyStorageDrsRecommendationToPod_Task(this.VimReference, pod.VimReference, key).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CancelStorageDrsRecommendation(string[] key)
    {
        await this.Session.VimClient.CancelStorageDrsRecommendation(this.VimReference, key).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureDatastoreIORM_Task(Datastore datastore, StorageIORMConfigSpec spec)
    {
        var res = await this.Session.VimClient.ConfigureDatastoreIORM_Task(this.VimReference, datastore.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ConfigureStorageDrsForPod_Task(StoragePod pod, StorageDrsConfigSpec spec, bool modify)
    {
        var res = await this.Session.VimClient.ConfigureStorageDrsForPod_Task(this.VimReference, pod.VimReference, spec, modify).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<StoragePerformanceSummary[]?> QueryDatastorePerformanceSummary(Datastore datastore)
    {
        return await this.Session.VimClient.QueryDatastorePerformanceSummary(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<StorageIORMConfigOption?> QueryIORMConfigOption(HostSystem host)
    {
        return await this.Session.VimClient.QueryIORMConfigOption(this.VimReference, host.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult?> RecommendDatastores(StoragePlacementSpec storageSpec)
    {
        return await this.Session.VimClient.RecommendDatastores(this.VimReference, storageSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RefreshStorageDrsRecommendation(StoragePod pod)
    {
        await this.Session.VimClient.RefreshStorageDrsRecommendation(this.VimReference, pod.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RefreshStorageDrsRecommendationsForPod_Task(StoragePod pod)
    {
        var res = await this.Session.VimClient.RefreshStorageDrsRecommendationsForPod_Task(this.VimReference, pod.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault?> ValidateStoragePodConfig(StoragePod pod, StorageDrsConfigSpec spec)
    {
        return await this.Session.VimClient.ValidateStoragePodConfig(this.VimReference, pod.VimReference, spec).ConfigureAwait(false);
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
        var obj = await this.GetProperty<TaskInfo>("info").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task CancelTask()
    {
        await this.Session.VimClient.CancelTask(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetTaskDescription(LocalizableMessage description)
    {
        await this.Session.VimClient.SetTaskDescription(this.VimReference, description).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetTaskState(TaskInfoState state, object? result, LocalizedMethodFault? fault)
    {
        await this.Session.VimClient.SetTaskState(this.VimReference, state, result, fault).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateProgress(int percentDone)
    {
        await this.Session.VimClient.UpdateProgress(this.VimReference, percentDone).ConfigureAwait(false);
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
        var obj = await this.GetProperty<TaskInfo[]>("latestPage").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadNextTasks(int maxCount)
    {
        return await this.Session.VimClient.ReadNextTasks(this.VimReference, maxCount).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadPreviousTasks(int maxCount)
    {
        return await this.Session.VimClient.ReadPreviousTasks(this.VimReference, maxCount).ConfigureAwait(false);
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
        var obj = await this.GetProperty<TaskDescription>("description").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<int> GetPropertyMaxCollector()
    {
        var obj = await this.GetProperty<int>("maxCollector").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<Task[]?> GetPropertyRecentTask()
    {
        var recentTask = await this.GetProperty<ManagedObjectReference[]>("recentTask").ConfigureAwait(false);
        return recentTask?.Select(r => ManagedObject.Create<Task>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<TaskHistoryCollector?> CreateCollectorForTasks(TaskFilterSpec filter)
    {
        var res = await this.Session.VimClient.CreateCollectorForTasks(this.VimReference, filter).ConfigureAwait(false);
        return ManagedObject.Create<TaskHistoryCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<TaskHistoryCollector?> CreateCollectorWithInfoFilterForTasks(TaskFilterSpec filter, TaskInfoFilterSpec? infoFilter)
    {
        var res = await this.Session.VimClient.CreateCollectorWithInfoFilterForTasks(this.VimReference, filter, infoFilter).ConfigureAwait(false);
        return ManagedObject.Create<TaskHistoryCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<TaskInfo?> CreateTask(ManagedObject obj, string taskTypeId, string? initiatedBy, bool cancelable, string? parentTaskKey, string? activationId)
    {
        return await this.Session.VimClient.CreateTask(this.VimReference, obj.VimReference, taskTypeId, initiatedBy, cancelable, parentTaskKey, activationId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadNextTasksByViewSpec(TaskManagerTaskViewSpec viewSpec, TaskFilterSpec filterSpec, TaskInfoFilterSpec? infoFilterSpec)
    {
        return await this.Session.VimClient.ReadNextTasksByViewSpec(this.VimReference, viewSpec, filterSpec, infoFilterSpec).ConfigureAwait(false);
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
        await this.Session.VimClient.MarkServiceProviderEntities(this.VimReference, entity?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]?> RetrieveServiceProviderEntities()
    {
        var res = await this.Session.VimClient.RetrieveServiceProviderEntities(this.VimReference).ConfigureAwait(false);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task UnmarkServiceProviderEntities(ManagedEntity[]? entity)
    {
        await this.Session.VimClient.UnmarkServiceProviderEntities(this.VimReference, entity?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }
}

public partial class TransitGateway : ManagedEntity
{
    protected TransitGateway(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<TransitGatewayConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<TransitGatewayConfigInfo>("config").ConfigureAwait(false);
        return obj!;
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
        var obj = await this.GetProperty<string[]>("domainList").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<UserSearchResult[]?> RetrieveUserGroups(string? domain, string searchStr, string? belongsToGroup, string? belongsToUser, bool exactMatch, bool findUsers, bool findGroups)
    {
        return await this.Session.VimClient.RetrieveUserGroups(this.VimReference, domain, searchStr, belongsToGroup, belongsToUser, exactMatch, findUsers, findGroups).ConfigureAwait(false);
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
        await this.Session.VimClient.AttachTagToVStorageObject(this.VimReference, id, category, tag).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ClearVStorageObjectControlFlags(ID id, Datastore datastore, string[]? controlFlags)
    {
        await this.Session.VimClient.ClearVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> CloneVStorageObject_Task(ID id, Datastore datastore, VslmCloneSpec spec)
    {
        var res = await this.Session.VimClient.CloneVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDisk_Task(VslmCreateSpec spec)
    {
        var res = await this.Session.VimClient.CreateDisk_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateDiskFromSnapshot_Task(ID id, Datastore datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path, bool? isLinkedClone, ID? targetId, Datastore? targetDatastore)
    {
        var res = await this.Session.VimClient.CreateDiskFromSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId, name, profile, crypto, path, isLinkedClone ?? default, isLinkedClone.HasValue, targetId, targetDatastore?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteSnapshot_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.DeleteSnapshot_Task(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteVStorageObject_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.DeleteVStorageObject_Task(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteVStorageObjectEx_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.DeleteVStorageObjectEx_Task(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DetachTagFromVStorageObject(ID id, string category, string tag)
    {
        await this.Session.VimClient.DetachTagFromVStorageObject(this.VimReference, id, category, tag).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ExtendDisk_Task(ID id, Datastore datastore, long newCapacityInMB)
    {
        var res = await this.Session.VimClient.ExtendDisk_Task(this.VimReference, id, datastore.VimReference, newCapacityInMB).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> InflateDisk_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.InflateDisk_Task(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTagEntry[]?> ListTagsAttachedToVStorageObject(ID id)
    {
        return await this.Session.VimClient.ListTagsAttachedToVStorageObject(this.VimReference, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ID[]?> ListVStorageObject(Datastore datastore)
    {
        return await this.Session.VimClient.ListVStorageObject(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<ID[]?> ListVStorageObjectsAttachedToTag(string category, string tag)
    {
        return await this.Session.VimClient.ListVStorageObjectsAttachedToTag(this.VimReference, category, tag).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryVirtualDiskUuidEx(string name, Datacenter? datacenter)
    {
        return await this.Session.VimClient.QueryVirtualDiskUuidEx(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ReconcileDatastoreInventory_Task(Datastore datastore, bool? deepCleansing)
    {
        var res = await this.Session.VimClient.ReconcileDatastoreInventory_Task(this.VimReference, datastore.VimReference, deepCleansing ?? default, deepCleansing.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ReconcileDatastoreInventoryEx_Task(VStorageObjectReconcileSpec spec)
    {
        var res = await this.Session.VimClient.ReconcileDatastoreInventoryEx_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> RegisterDisk(string path, string? name, ID? id)
    {
        return await this.Session.VimClient.RegisterDisk(this.VimReference, path, name, id).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RelocateVStorageObject_Task(ID id, Datastore datastore, VslmRelocateSpec spec)
    {
        var res = await this.Session.VimClient.RelocateVStorageObject_Task(this.VimReference, id, datastore.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RenameVStorageObject(ID id, Datastore datastore, string name)
    {
        await this.Session.VimClient.RenameVStorageObject(this.VimReference, id, datastore.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotDetails?> RetrieveSnapshotDetails(ID id, Datastore datastore, ID snapshotId)
    {
        return await this.Session.VimClient.RetrieveSnapshotDetails(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> RetrieveSnapshotInfo(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.RetrieveSnapshotInfo(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> RetrieveVStorageInfrastructureObjectPolicy(Datastore datastore)
    {
        return await this.Session.VimClient.RetrieveVStorageInfrastructureObjectPolicy(this.VimReference, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObject?> RetrieveVStorageObject(ID id, Datastore datastore, string[]? diskInfoFlags)
    {
        return await this.Session.VimClient.RetrieveVStorageObject(this.VimReference, id, datastore.VimReference, diskInfoFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectAssociations[]?> RetrieveVStorageObjectAssociations(RetrieveVStorageObjSpec[]? ids)
    {
        return await this.Session.VimClient.RetrieveVStorageObjectAssociations(this.VimReference, ids).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> RetrieveVStorageObjectState(ID id, Datastore datastore)
    {
        return await this.Session.VimClient.RetrieveVStorageObjectState(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RevertVStorageObject_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.RevertVStorageObject_Task(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ScheduleReconcileDatastoreInventory(Datastore datastore, bool? deepCleansing)
    {
        await this.Session.VimClient.ScheduleReconcileDatastoreInventory(this.VimReference, datastore.VimReference, deepCleansing ?? default, deepCleansing.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> SetVirtualDiskUuidEx_Task(string name, Datacenter? datacenter, string? uuid)
    {
        var res = await this.Session.VimClient.SetVirtualDiskUuidEx_Task(this.VimReference, name, datacenter?.VimReference, uuid).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task SetVStorageObjectControlFlags(ID id, Datastore datastore, string[]? controlFlags)
    {
        await this.Session.VimClient.SetVStorageObjectControlFlags(this.VimReference, id, datastore.VimReference, controlFlags).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVStorageInfrastructureObjectPolicy_Task(vslmInfrastructureObjectPolicySpec spec)
    {
        var res = await this.Session.VimClient.UpdateVStorageInfrastructureObjectPolicy_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVStorageObjectCrypto_Task(ID id, Datastore datastore, VirtualMachineProfileSpec[]? profile, DiskCryptoSpec? disksCrypto)
    {
        var res = await this.Session.VimClient.UpdateVStorageObjectCrypto_Task(this.VimReference, id, datastore.VimReference, profile, disksCrypto).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpdateVStorageObjectPolicy_Task(ID id, Datastore datastore, VirtualMachineProfileSpec[]? profile)
    {
        var res = await this.Session.VimClient.UpdateVStorageObjectPolicy_Task(this.VimReference, id, datastore.VimReference, profile).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VCenterUpdateVStorageObjectMetadataEx_Task(ID id, Datastore datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var res = await this.Session.VimClient.VCenterUpdateVStorageObjectMetadataEx_Task(this.VimReference, id, datastore.VimReference, metadata, deleteKeys).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VStorageObjectCreateSnapshot_Task(ID id, Datastore datastore, string description)
    {
        var res = await this.Session.VimClient.VStorageObjectCreateSnapshot_Task(this.VimReference, id, datastore.VimReference, description).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> VstorageObjectVCenterQueryChangedDiskAreas(ID id, Datastore datastore, ID snapshotId, long startOffset, string changeId)
    {
        return await this.Session.VimClient.VstorageObjectVCenterQueryChangedDiskAreas(this.VimReference, id, datastore.VimReference, snapshotId, startOffset, changeId).ConfigureAwait(false);
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
        await this.Session.VimClient.DestroyView(this.VimReference).ConfigureAwait(false);
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
        var viewList = await this.GetProperty<ManagedObjectReference[]>("viewList").ConfigureAwait(false);
        return viewList?.Select(r => ManagedObject.Create<View>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ContainerView?> CreateContainerView(ManagedEntity container, string[]? type, bool recursive)
    {
        var res = await this.Session.VimClient.CreateContainerView(this.VimReference, container.VimReference, type, recursive).ConfigureAwait(false);
        return ManagedObject.Create<ContainerView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<InventoryView?> CreateInventoryView()
    {
        var res = await this.Session.VimClient.CreateInventoryView(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<InventoryView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ListView?> CreateListView(ManagedObject[]? obj)
    {
        var res = await this.Session.VimClient.CreateListView(this.VimReference, obj?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return ManagedObject.Create<ListView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ListView?> CreateListViewFromView(View view)
    {
        var res = await this.Session.VimClient.CreateListViewFromView(this.VimReference, view.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<VirtualAppLinkInfo[]>("childLink").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore").ConfigureAwait(false);
        return datastore?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network").ConfigureAwait(false);
        return network?.Select(r => ManagedObject.Create<Network>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<Folder?> GetPropertyParentFolder()
    {
        var parentFolder = await this.GetProperty<ManagedObjectReference>("parentFolder").ConfigureAwait(false);
        return ManagedObject.Create<Folder>(parentFolder, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> GetPropertyParentVApp()
    {
        var parentVApp = await this.GetProperty<ManagedObjectReference>("parentVApp").ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(parentVApp, this.Session);
    }

    public async System.Threading.Tasks.Task<VAppConfigInfo?> GetPropertyVAppConfig()
    {
        var obj = await this.GetProperty<VAppConfigInfo>("vAppConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Task?> CloneVApp_Task(string name, ResourcePool target, VAppCloneSpec spec)
    {
        var res = await this.Session.VimClient.CloneVApp_Task(this.VimReference, name, target.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ExportVApp()
    {
        var res = await this.Session.VimClient.ExportVApp(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOffVApp_Task(bool force)
    {
        var res = await this.Session.VimClient.PowerOffVApp_Task(this.VimReference, force).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOnVApp_Task()
    {
        var res = await this.Session.VimClient.PowerOnVApp_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SuspendVApp_Task()
    {
        var res = await this.Session.VimClient.SuspendVApp_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnregisterVApp_Task()
    {
        var res = await this.Session.VimClient.UnregisterVApp_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateLinkedChildren(VirtualAppLinkInfo[]? addChangeSet, ManagedEntity[]? removeSet)
    {
        await this.Session.VimClient.UpdateLinkedChildren(this.VimReference, addChangeSet, removeSet?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UpdateVAppConfig(VAppConfigSpec spec)
    {
        await this.Session.VimClient.UpdateVAppConfig(this.VimReference, spec).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.CopyVirtualDisk_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destName, destDatacenter?.VimReference, destSpec, force ?? default, force.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateVirtualDisk_Task(string name, Datacenter? datacenter, VirtualDiskSpec spec)
    {
        var res = await this.Session.VimClient.CreateVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DefragmentVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.DefragmentVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DeleteVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.DeleteVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> EagerZeroVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.EagerZeroVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ExtendVirtualDisk_Task(string name, Datacenter? datacenter, long newCapacityKb, bool? eagerZero)
    {
        var res = await this.Session.VimClient.ExtendVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference, newCapacityKb, eagerZero ?? default, eagerZero.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ImportUnmanagedSnapshot(string vdisk, Datacenter? datacenter, string vvolId)
    {
        await this.Session.VimClient.ImportUnmanagedSnapshot(this.VimReference, vdisk, datacenter?.VimReference, vvolId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> InflateVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.InflateVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MoveVirtualDisk_Task(string sourceName, Datacenter? sourceDatacenter, string destName, Datacenter? destDatacenter, bool? force, VirtualMachineProfileSpec[]? profile)
    {
        var res = await this.Session.VimClient.MoveVirtualDisk_Task(this.VimReference, sourceName, sourceDatacenter?.VimReference, destName, destDatacenter?.VimReference, force ?? default, force.HasValue, profile).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int> QueryVirtualDiskFragmentation(string name, Datacenter? datacenter)
    {
        return await this.Session.VimClient.QueryVirtualDiskFragmentation(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<HostDiskDimensionsChs?> QueryVirtualDiskGeometry(string name, Datacenter? datacenter)
    {
        return await this.Session.VimClient.QueryVirtualDiskGeometry(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string?> QueryVirtualDiskUuid(string name, Datacenter? datacenter)
    {
        return await this.Session.VimClient.QueryVirtualDiskUuid(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ReleaseManagedSnapshot(string vdisk, Datacenter? datacenter)
    {
        await this.Session.VimClient.ReleaseManagedSnapshot(this.VimReference, vdisk, datacenter?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetVirtualDiskUuid(string name, Datacenter? datacenter, string uuid)
    {
        await this.Session.VimClient.SetVirtualDiskUuid(this.VimReference, name, datacenter?.VimReference, uuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ShrinkVirtualDisk_Task(string name, Datacenter? datacenter, bool? copy)
    {
        var res = await this.Session.VimClient.ShrinkVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference, copy ?? default, copy.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ZeroFillVirtualDisk_Task(string name, Datacenter? datacenter)
    {
        var res = await this.Session.VimClient.ZeroFillVirtualDisk_Task(this.VimReference, name, datacenter?.VimReference).ConfigureAwait(false);
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
        var obj = await this.GetProperty<VirtualMachineCapability>("capability").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigInfo?> GetPropertyConfig()
    {
        var obj = await this.GetProperty<VirtualMachineConfigInfo>("config").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Datastore[]?> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore").ConfigureAwait(false);
        return datastore?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<EnvironmentBrowser> GetPropertyEnvironmentBrowser()
    {
        var environmentBrowser = await this.GetProperty<ManagedObjectReference>("environmentBrowser").ConfigureAwait(false);
        return ManagedObject.Create<EnvironmentBrowser>(environmentBrowser, this.Session)!;
    }

    public async System.Threading.Tasks.Task<GuestInfo?> GetPropertyGuest()
    {
        var obj = await this.GetProperty<GuestInfo>("guest").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyGuestHeartbeatStatus()
    {
        var obj = await this.GetProperty<ManagedEntityStatus>("guestHeartbeatStatus").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineFileLayout?> GetPropertyLayout()
    {
        var obj = await this.GetProperty<VirtualMachineFileLayout>("layout").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineFileLayoutEx?> GetPropertyLayoutEx()
    {
        var obj = await this.GetProperty<VirtualMachineFileLayoutEx>("layoutEx").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<Network[]?> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network").ConfigureAwait(false);
        return network?.Select(r => ManagedObject.Create<Network>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity?> GetPropertyParentVApp()
    {
        var parentVApp = await this.GetProperty<ManagedObjectReference>("parentVApp").ConfigureAwait(false);
        return ManagedObject.Create<ManagedEntity>(parentVApp, this.Session);
    }

    public async System.Threading.Tasks.Task<ResourceConfigSpec?> GetPropertyResourceConfig()
    {
        var obj = await this.GetProperty<ResourceConfigSpec>("resourceConfig").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<ResourcePool?> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference>("resourcePool").ConfigureAwait(false);
        return ManagedObject.Create<ResourcePool>(resourcePool, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualMachineSnapshot[]?> GetPropertyRootSnapshot()
    {
        var rootSnapshot = await this.GetProperty<ManagedObjectReference[]>("rootSnapshot").ConfigureAwait(false);
        return rootSnapshot?.Select(r => ManagedObject.Create<VirtualMachineSnapshot>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachineRuntimeInfo> GetPropertyRuntime()
    {
        var obj = await this.GetProperty<VirtualMachineRuntimeInfo>("runtime").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineSnapshotInfo?> GetPropertySnapshot()
    {
        var obj = await this.GetProperty<VirtualMachineSnapshotInfo>("snapshot").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineStorageInfo?> GetPropertyStorage()
    {
        var obj = await this.GetProperty<VirtualMachineStorageInfo>("storage").ConfigureAwait(false);
        return obj;
    }

    public async System.Threading.Tasks.Task<VirtualMachineSummary> GetPropertySummary()
    {
        var obj = await this.GetProperty<VirtualMachineSummary>("summary").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachineMksTicket?> AcquireMksTicket()
    {
        return await this.Session.VimClient.AcquireMksTicket(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineTicket?> AcquireTicket(string ticketType)
    {
        return await this.Session.VimClient.AcquireTicket(this.VimReference, ticketType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task AnswerVM(string questionId, string answerChoice)
    {
        await this.Session.VimClient.AnswerVM(this.VimReference, questionId, answerChoice).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ApplyEvcModeVM_Task(HostFeatureMask[]? mask, bool? completeMasks)
    {
        var res = await this.Session.VimClient.ApplyEvcModeVM_Task(this.VimReference, mask, completeMasks ?? default, completeMasks.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> AttachDisk_Task(ID diskId, Datastore datastore, int? controllerKey, int? unitNumber)
    {
        var res = await this.Session.VimClient.AttachDisk_Task(this.VimReference, diskId, datastore.VimReference, controllerKey ?? default, controllerKey.HasValue, unitNumber ?? default, unitNumber.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CheckCustomizationSpec(CustomizationSpec spec)
    {
        await this.Session.VimClient.CheckCustomizationSpec(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> CloneVM_Task(Folder folder, string name, VirtualMachineCloneSpec spec)
    {
        var res = await this.Session.VimClient.CloneVM_Task(this.VimReference, folder.VimReference, name, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> ConsolidateVMDisks_Task()
    {
        var res = await this.Session.VimClient.ConsolidateVMDisks_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateScreenshot_Task()
    {
        var res = await this.Session.VimClient.CreateScreenshot_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSecondaryVM_Task(HostSystem? host)
    {
        var res = await this.Session.VimClient.CreateSecondaryVM_Task(this.VimReference, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSecondaryVMEx_Task(HostSystem? host, FaultToleranceConfigSpec? spec)
    {
        var res = await this.Session.VimClient.CreateSecondaryVMEx_Task(this.VimReference, host?.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSnapshot_Task(string name, string? description, bool memory, bool quiesce)
    {
        var res = await this.Session.VimClient.CreateSnapshot_Task(this.VimReference, name, description, memory, quiesce).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CreateSnapshotEx_Task(string name, string? description, bool memory, VirtualMachineGuestQuiesceSpec? quiesceSpec)
    {
        var res = await this.Session.VimClient.CreateSnapshotEx_Task(this.VimReference, name, description, memory, quiesceSpec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CryptoUnlock_Task()
    {
        var res = await this.Session.VimClient.CryptoUnlock_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CustomizeVM_Task(CustomizationSpec spec)
    {
        var res = await this.Session.VimClient.CustomizeVM_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DefragmentAllDisks()
    {
        await this.Session.VimClient.DefragmentAllDisks(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> DetachDisk_Task(ID diskId)
    {
        var res = await this.Session.VimClient.DetachDisk_Task(this.VimReference, diskId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> DisableSecondaryVM_Task(VirtualMachine vm)
    {
        var res = await this.Session.VimClient.DisableSecondaryVM_Task(this.VimReference, vm.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<bool> DropConnections(VirtualMachineConnection[]? listOfConnections)
    {
        return await this.Session.VimClient.DropConnections(this.VimReference, listOfConnections).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> EnableSecondaryVM_Task(VirtualMachine vm, HostSystem? host)
    {
        var res = await this.Session.VimClient.EnableSecondaryVM_Task(this.VimReference, vm.VimReference, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> EstimateStorageForConsolidateSnapshots_Task()
    {
        var res = await this.Session.VimClient.EstimateStorageForConsolidateSnapshots_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ExportVm()
    {
        var res = await this.Session.VimClient.ExportVm(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string?> ExtractOvfEnvironment()
    {
        return await this.Session.VimClient.ExtractOvfEnvironment(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> InstantClone_Task(VirtualMachineInstantCloneSpec spec)
    {
        var res = await this.Session.VimClient.InstantClone_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> MakePrimaryVM_Task(VirtualMachine vm)
    {
        var res = await this.Session.VimClient.MakePrimaryVM_Task(this.VimReference, vm.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MarkAsTemplate()
    {
        await this.Session.VimClient.MarkAsTemplate(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task MarkAsVirtualMachine(ResourcePool pool, HostSystem? host)
    {
        await this.Session.VimClient.MarkAsVirtualMachine(this.VimReference, pool.VimReference, host?.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> MigrateVM_Task(ResourcePool? pool, HostSystem? host, VirtualMachineMovePriority priority, VirtualMachinePowerState? state)
    {
        var res = await this.Session.VimClient.MigrateVM_Task(this.VimReference, pool?.VimReference, host?.VimReference, priority, state ?? default, state.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MountToolsInstaller()
    {
        await this.Session.VimClient.MountToolsInstaller(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOffVM_Task()
    {
        var res = await this.Session.VimClient.PowerOffVM_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PowerOnVM_Task(HostSystem? host)
    {
        var res = await this.Session.VimClient.PowerOnVM_Task(this.VimReference, host?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> PromoteDisks_Task(bool unlink, VirtualDisk[]? disks)
    {
        var res = await this.Session.VimClient.PromoteDisks_Task(this.VimReference, unlink, disks).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int> PutUsbScanCodes(UsbScanCodeSpec spec)
    {
        return await this.Session.VimClient.PutUsbScanCodes(this.VimReference, spec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> QueryChangedDiskAreas(VirtualMachineSnapshot? snapshot, int deviceKey, long startOffset, string changeId)
    {
        return await this.Session.VimClient.QueryChangedDiskAreas(this.VimReference, snapshot?.VimReference, deviceKey, startOffset, changeId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConnection[]?> QueryConnections()
    {
        return await this.Session.VimClient.QueryConnections(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibility()
    {
        return await this.Session.VimClient.QueryFaultToleranceCompatibility(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibilityEx(bool? forLegacyFt)
    {
        return await this.Session.VimClient.QueryFaultToleranceCompatibilityEx(this.VimReference, forLegacyFt ?? default, forLegacyFt.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<string[]?> QueryUnownedFiles()
    {
        return await this.Session.VimClient.QueryUnownedFiles(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task RebootGuest()
    {
        await this.Session.VimClient.RebootGuest(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ReconfigVM_Task(VirtualMachineConfigSpec spec)
    {
        var res = await this.Session.VimClient.ReconfigVM_Task(this.VimReference, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshStorageInfo()
    {
        await this.Session.VimClient.RefreshStorageInfo(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ReloadVirtualMachineFromPath_Task(string configurationPath)
    {
        var res = await this.Session.VimClient.ReloadVirtualMachineFromPath_Task(this.VimReference, configurationPath).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RelocateVM_Task(VirtualMachineRelocateSpec spec, VirtualMachineMovePriority? priority)
    {
        var res = await this.Session.VimClient.RelocateVM_Task(this.VimReference, spec, priority ?? default, priority.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveAllSnapshots_Task(bool? consolidate, SnapshotSelectionSpec? spec)
    {
        var res = await this.Session.VimClient.RemoveAllSnapshots_Task(this.VimReference, consolidate ?? default, consolidate.HasValue, spec).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RepairVmDiskChains_Task()
    {
        var res = await this.Session.VimClient.RepairVmDiskChains_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ResetGuestInformation()
    {
        await this.Session.VimClient.ResetGuestInformation(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> ResetVM_Task()
    {
        var res = await this.Session.VimClient.ResetVM_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RevertToCurrentSnapshot_Task(HostSystem? host, bool? suppressPowerOn)
    {
        var res = await this.Session.VimClient.RevertToCurrentSnapshot_Task(this.VimReference, host?.VimReference, suppressPowerOn ?? default, suppressPowerOn.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task SendNMI()
    {
        await this.Session.VimClient.SendNMI(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetDisplayTopology(VirtualMachineDisplayTopology[] displays)
    {
        await this.Session.VimClient.SetDisplayTopology(this.VimReference, displays).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task SetScreenResolution(int width, int height)
    {
        await this.Session.VimClient.SetScreenResolution(this.VimReference, width, height).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task ShutdownGuest()
    {
        await this.Session.VimClient.ShutdownGuest(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task StandbyGuest()
    {
        await this.Session.VimClient.StandbyGuest(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> StartRecording_Task(string name, string? description)
    {
        var res = await this.Session.VimClient.StartRecording_Task(this.VimReference, name, description).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StartReplaying_Task(VirtualMachineSnapshot replaySnapshot)
    {
        var res = await this.Session.VimClient.StartReplaying_Task(this.VimReference, replaySnapshot.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StopRecording_Task()
    {
        var res = await this.Session.VimClient.StopRecording_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StopReplaying_Task()
    {
        var res = await this.Session.VimClient.StopReplaying_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> SuspendVM_Task()
    {
        var res = await this.Session.VimClient.SuspendVM_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> TerminateFaultTolerantVM_Task(VirtualMachine? vm)
    {
        var res = await this.Session.VimClient.TerminateFaultTolerantVM_Task(this.VimReference, vm?.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task TerminateVM()
    {
        await this.Session.VimClient.TerminateVM(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> TurnOffFaultToleranceForVM_Task()
    {
        var res = await this.Session.VimClient.TurnOffFaultToleranceForVM_Task(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UnmountToolsInstaller()
    {
        await this.Session.VimClient.UnmountToolsInstaller(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task UnregisterVM()
    {
        await this.Session.VimClient.UnregisterVM(this.VimReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> UpgradeTools_Task(string? installerOptions)
    {
        var res = await this.Session.VimClient.UpgradeTools_Task(this.VimReference, installerOptions).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UpgradeVM_Task(string? version)
    {
        var res = await this.Session.VimClient.UpgradeVM_Task(this.VimReference, version).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.CheckCompatibility_Task(this.VimReference, vm.VimReference, host?.VimReference, pool?.VimReference, testType).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckPowerOn_Task(VirtualMachine vm, HostSystem? host, ResourcePool? pool, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckPowerOn_Task(this.VimReference, vm.VimReference, host?.VimReference, pool?.VimReference, testType).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckVmConfig_Task(VirtualMachineConfigSpec spec, VirtualMachine? vm, HostSystem? host, ResourcePool? pool, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckVmConfig_Task(this.VimReference, spec, vm?.VimReference, host?.VimReference, pool?.VimReference, testType).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.AbortCustomization_Task(this.VimReference, vm.VimReference, auth).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CustomizeGuest_Task(VirtualMachine vm, GuestAuthentication auth, CustomizationSpec spec, OptionValue[]? configParams)
    {
        var res = await this.Session.VimClient.CustomizeGuest_Task(this.VimReference, vm.VimReference, auth, spec, configParams).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> StartGuestNetwork_Task(VirtualMachine vm, GuestAuthentication auth)
    {
        var res = await this.Session.VimClient.StartGuestNetwork_Task(this.VimReference, vm.VimReference, auth).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.CheckClone_Task(this.VimReference, vm.VimReference, folder.VimReference, name, spec, testType).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckInstantClone_Task(VirtualMachine vm, VirtualMachineInstantCloneSpec spec, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckInstantClone_Task(this.VimReference, vm.VimReference, spec, testType).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckMigrate_Task(VirtualMachine vm, HostSystem? host, ResourcePool? pool, VirtualMachinePowerState? state, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckMigrate_Task(this.VimReference, vm.VimReference, host?.VimReference, pool?.VimReference, state ?? default, state.HasValue, testType).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> CheckRelocate_Task(VirtualMachine vm, VirtualMachineRelocateSpec spec, string[]? testType)
    {
        var res = await this.Session.VimClient.CheckRelocate_Task(this.VimReference, vm.VimReference, spec, testType).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> QueryVMotionCompatibilityEx_Task(VirtualMachine[] vm, HostSystem[] host)
    {
        var res = await this.Session.VimClient.QueryVMotionCompatibilityEx_Task(this.VimReference, [.. vm.Select(m => m.VimReference)], [.. host.Select(m => m.VimReference)]).ConfigureAwait(false);
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
        var childSnapshot = await this.GetProperty<ManagedObjectReference[]>("childSnapshot").ConfigureAwait(false);
        return childSnapshot?.Select(r => ManagedObject.Create<VirtualMachineSnapshot>(r, this.Session)!).ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigInfo> GetPropertyConfig()
    {
        var obj = await this.GetProperty<VirtualMachineConfigInfo>("config").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<VirtualMachine> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference>("vm").ConfigureAwait(false);
        return ManagedObject.Create<VirtualMachine>(vm, this.Session)!;
    }

    public async System.Threading.Tasks.Task<HttpNfcLease?> ExportSnapshot()
    {
        var res = await this.Session.VimClient.ExportSnapshot(this.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RemoveSnapshot_Task(bool removeChildren, bool? consolidate)
    {
        var res = await this.Session.VimClient.RemoveSnapshot_Task(this.VimReference, removeChildren, consolidate ?? default, consolidate.HasValue).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RenameSnapshot(string? name, string? description)
    {
        await this.Session.VimClient.RenameSnapshot(this.VimReference, name, description).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RevertToSnapshot_Task(HostSystem? host, bool? suppressPowerOn)
    {
        var res = await this.Session.VimClient.RevertToSnapshot_Task(this.VimReference, host?.VimReference, suppressPowerOn ?? default, suppressPowerOn.HasValue).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.UpdateDVSLacpGroupConfig_Task(this.VimReference, lacpGroupSpec).ConfigureAwait(false);
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
        var res = await this.Session.VimClient.PerformVsanUpgrade_Task(this.VimReference, cluster.VimReference, performObjectUpgrade ?? default, performObjectUpgrade.HasValue, downgradeFormat ?? default, downgradeFormat.HasValue, allowReducedRedundancy ?? default, allowReducedRedundancy.HasValue, excludeHosts?.Select(m => m.VimReference).ToArray()).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemPreflightCheckResult?> PerformVsanUpgradePreflightCheck(ClusterComputeResource cluster, bool? downgradeFormat)
    {
        return await this.Session.VimClient.PerformVsanUpgradePreflightCheck(this.VimReference, cluster.VimReference, downgradeFormat ?? default, downgradeFormat.HasValue).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemUpgradeStatus?> QueryVsanUpgradeStatus(ClusterComputeResource cluster)
    {
        return await this.Session.VimClient.QueryVsanUpgradeStatus(this.VimReference, cluster.VimReference).ConfigureAwait(false);
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

    public async System.Threading.Tasks.Task<vslmVClockInfo?> RenameVStorageObjectEx(ID id, Datastore datastore, string name)
    {
        return await this.Session.VimClient.RenameVStorageObjectEx(this.VimReference, id, datastore.VimReference, name).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<Task?> RepairVStorageObjectChain_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.RepairVStorageObjectChain_Task(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> RevertVStorageObjectEx_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.RevertVStorageObjectEx_Task(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> UnregisterDisk_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.VimClient.UnregisterDisk_Task(this.VimReference, id, datastore.VimReference).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VStorageObjectCreateSnapshotEx_Task(ID id, Datastore datastore, string description, ID? snapshotId)
    {
        var res = await this.Session.VimClient.VStorageObjectCreateSnapshotEx_Task(this.VimReference, id, datastore.VimReference, description, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VStorageObjectDeleteSnapshotEx_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.VStorageObjectDeleteSnapshotEx_Task(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VStorageObjectDeleteSnapshotEx2_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.VimClient.VStorageObjectDeleteSnapshotEx2_Task(this.VimReference, id, datastore.VimReference, snapshotId).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task?> VStorageObjectExtendDiskEx_Task(ID id, Datastore datastore, long newCapacityInMB)
    {
        var res = await this.Session.VimClient.VStorageObjectExtendDiskEx_Task(this.VimReference, id, datastore.VimReference, newCapacityInMB).ConfigureAwait(false);
        return ManagedObject.Create<Task>(res, this.Session);
    }
}

#pragma warning restore IDE0058 // Expression value is never used

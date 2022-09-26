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
        return await this.GetProperty<AlarmInfo>("info");
    }

    public async System.Threading.Tasks.Task ReconfigureAlarm(AlarmSpec spec)
    {
        await this.Session.Client.ReconfigureAlarm(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task RemoveAlarm()
    {
        await this.Session.Client.RemoveAlarm(this.Reference);
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

    public async System.Threading.Tasks.Task<AlarmExpression[]> GetPropertyDefaultExpression()
    {
        return await this.GetProperty<AlarmExpression[]>("defaultExpression");
    }

    public async System.Threading.Tasks.Task<AlarmDescription> GetPropertyDescription()
    {
        return await this.GetProperty<AlarmDescription>("description");
    }

    public async System.Threading.Tasks.Task AcknowledgeAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.Client.AcknowledgeAlarm(this.Reference, alarm?.Reference, entity?.Reference);
    }

    public async System.Threading.Tasks.Task<bool> AreAlarmActionsEnabled(ManagedEntity entity)
    {
        return await this.Session.Client.AreAlarmActionsEnabled(this.Reference, entity?.Reference);
    }

    public async System.Threading.Tasks.Task ClearTriggeredAlarms(AlarmFilterSpec filter)
    {
        await this.Session.Client.ClearTriggeredAlarms(this.Reference, filter);
    }

    public async System.Threading.Tasks.Task<Alarm> CreateAlarm(ManagedEntity entity, AlarmSpec spec)
    {
        var res = await this.Session.Client.CreateAlarm(this.Reference, entity?.Reference, spec);
        return ManagedObject.Create<Alarm>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.Client.DisableAlarm(this.Reference, alarm?.Reference, entity?.Reference);
    }

    public async System.Threading.Tasks.Task EnableAlarm(Alarm alarm, ManagedEntity entity)
    {
        await this.Session.Client.EnableAlarm(this.Reference, alarm?.Reference, entity?.Reference);
    }

    public async System.Threading.Tasks.Task EnableAlarmActions(ManagedEntity entity, bool enabled)
    {
        await this.Session.Client.EnableAlarmActions(this.Reference, entity?.Reference, enabled);
    }

    public async System.Threading.Tasks.Task<Alarm[]> GetAlarm(ManagedEntity entity)
    {
        var res = await this.Session.Client.GetAlarm(this.Reference, entity?.Reference);
        return res?.Select(r => ManagedObject.Create<Alarm>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<AlarmState[]> GetAlarmState(ManagedEntity entity)
    {
        return await this.Session.Client.GetAlarmState(this.Reference, entity?.Reference);
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
        return await this.GetProperty<AuthorizationDescription>("description");
    }

    public async System.Threading.Tasks.Task<AuthorizationPrivilege[]> GetPropertyPrivilegeList()
    {
        return await this.GetProperty<AuthorizationPrivilege[]>("privilegeList");
    }

    public async System.Threading.Tasks.Task<AuthorizationRole[]> GetPropertyRoleList()
    {
        return await this.GetProperty<AuthorizationRole[]>("roleList");
    }

    public async System.Threading.Tasks.Task<int> AddAuthorizationRole(string name, string[] privIds)
    {
        return await this.Session.Client.AddAuthorizationRole(this.Reference, name, privIds);
    }

    public async System.Threading.Tasks.Task<UserPrivilegeResult[]> FetchUserPrivilegeOnEntities(ManagedEntity[] entities, string userName)
    {
        return await this.Session.Client.FetchUserPrivilegeOnEntities(this.Reference, entities?.Select(m => m.Reference).ToArray(), userName);
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]> HasPrivilegeOnEntities(ManagedEntity[] entity, string sessionId, string[] privId)
    {
        return await this.Session.Client.HasPrivilegeOnEntities(this.Reference, entity?.Select(m => m.Reference).ToArray(), sessionId, privId);
    }

    public async System.Threading.Tasks.Task<bool[]> HasPrivilegeOnEntity(ManagedEntity entity, string sessionId, string[] privId)
    {
        return await this.Session.Client.HasPrivilegeOnEntity(this.Reference, entity?.Reference, sessionId, privId);
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]> HasUserPrivilegeOnEntities(ManagedObject[] entities, string userName, string[] privId)
    {
        return await this.Session.Client.HasUserPrivilegeOnEntities(this.Reference, entities?.Select(m => m.Reference).ToArray(), userName, privId);
    }

    public async System.Threading.Tasks.Task MergePermissions(int srcRoleId, int dstRoleId)
    {
        await this.Session.Client.MergePermissions(this.Reference, srcRoleId, dstRoleId);
    }

    public async System.Threading.Tasks.Task RemoveAuthorizationRole(int roleId, bool failIfUsed)
    {
        await this.Session.Client.RemoveAuthorizationRole(this.Reference, roleId, failIfUsed);
    }

    public async System.Threading.Tasks.Task RemoveEntityPermission(ManagedEntity entity, string user, bool isGroup)
    {
        await this.Session.Client.RemoveEntityPermission(this.Reference, entity?.Reference, user, isGroup);
    }

    public async System.Threading.Tasks.Task ResetEntityPermissions(ManagedEntity entity, Permission[] permission)
    {
        await this.Session.Client.ResetEntityPermissions(this.Reference, entity?.Reference, permission);
    }

    public async System.Threading.Tasks.Task<Permission[]> RetrieveAllPermissions()
    {
        return await this.Session.Client.RetrieveAllPermissions(this.Reference);
    }

    public async System.Threading.Tasks.Task<Permission[]> RetrieveEntityPermissions(ManagedEntity entity, bool inherited)
    {
        return await this.Session.Client.RetrieveEntityPermissions(this.Reference, entity?.Reference, inherited);
    }

    public async System.Threading.Tasks.Task<Permission[]> RetrieveRolePermissions(int roleId)
    {
        return await this.Session.Client.RetrieveRolePermissions(this.Reference, roleId);
    }

    public async System.Threading.Tasks.Task SetEntityPermissions(ManagedEntity entity, Permission[] permission)
    {
        await this.Session.Client.SetEntityPermissions(this.Reference, entity?.Reference, permission);
    }

    public async System.Threading.Tasks.Task UpdateAuthorizationRole(int roleId, string newName, string[] privIds)
    {
        await this.Session.Client.UpdateAuthorizationRole(this.Reference, roleId, newName, privIds);
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

    public async System.Threading.Tasks.Task<Task> CertMgrRefreshCACertificatesAndCRLs_Task(HostSystem[] host)
    {
        var res = await this.Session.Client.CertMgrRefreshCACertificatesAndCRLs_Task(this.Reference, host?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CertMgrRefreshCertificates_Task(HostSystem[] host)
    {
        var res = await this.Session.Client.CertMgrRefreshCertificates_Task(this.Reference, host?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CertMgrRevokeCertificates_Task(HostSystem[] host)
    {
        var res = await this.Session.Client.CertMgrRevokeCertificates_Task(this.Reference, host?.Select(m => m.Reference).ToArray());
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

    public async System.Threading.Tasks.Task<ClusterActionHistory[]> GetPropertyActionHistory()
    {
        return await this.GetProperty<ClusterActionHistory[]>("actionHistory");
    }

    public async System.Threading.Tasks.Task<ClusterConfigInfo> GetPropertyConfiguration()
    {
        return await this.GetProperty<ClusterConfigInfo>("configuration");
    }

    public async System.Threading.Tasks.Task<ClusterDrsFaults[]> GetPropertyDrsFault()
    {
        return await this.GetProperty<ClusterDrsFaults[]>("drsFault");
    }

    public async System.Threading.Tasks.Task<ClusterDrsRecommendation[]> GetPropertyDrsRecommendation()
    {
        return await this.GetProperty<ClusterDrsRecommendation[]>("drsRecommendation");
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceHCIConfigInfo> GetPropertyHciConfig()
    {
        return await this.GetProperty<ClusterComputeResourceHCIConfigInfo>("hciConfig");
    }

    public async System.Threading.Tasks.Task<ClusterDrsMigration[]> GetPropertyMigrationHistory()
    {
        return await this.GetProperty<ClusterDrsMigration[]>("migrationHistory");
    }

    public async System.Threading.Tasks.Task<ClusterRecommendation[]> GetPropertyRecommendation()
    {
        return await this.GetProperty<ClusterRecommendation[]>("recommendation");
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceSummary> GetPropertySummaryEx()
    {
        return await this.GetProperty<ClusterComputeResourceSummary>("summaryEx");
    }

    public async System.Threading.Tasks.Task AbandonHciWorkflow()
    {
        await this.Session.Client.AbandonHciWorkflow(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> AddHost_Task(HostConnectSpec spec, bool asConnected, ResourcePool resourcePool, string license)
    {
        var res = await this.Session.Client.AddHost_Task(this.Reference, spec, asConnected, resourcePool?.Reference, license);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ApplyRecommendation(string key)
    {
        await this.Session.Client.ApplyRecommendation(this.Reference, key);
    }

    public async System.Threading.Tasks.Task CancelRecommendation(string key)
    {
        await this.Session.Client.CancelRecommendation(this.Reference, key);
    }

    public async System.Threading.Tasks.Task<ClusterEnterMaintenanceResult> ClusterEnterMaintenanceMode(HostSystem[] host, OptionValue[] option)
    {
        return await this.Session.Client.ClusterEnterMaintenanceMode(this.Reference, host?.Select(m => m.Reference).ToArray(), option);
    }

    public async System.Threading.Tasks.Task<Task> ConfigureHCI_Task(ClusterComputeResourceHCIConfigSpec clusterSpec, ClusterComputeResourceHostConfigurationInput[] hostInputs)
    {
        var res = await this.Session.Client.ConfigureHCI_Task(this.Reference, clusterSpec, hostInputs);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterEVCManager> EvcManager()
    {
        var res = await this.Session.Client.EvcManager(this.Reference);
        return ManagedObject.Create<ClusterEVCManager>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ExtendHCI_Task(ClusterComputeResourceHostConfigurationInput[] hostInputs, SDDCBase vSanConfigSpec)
    {
        var res = await this.Session.Client.ExtendHCI_Task(this.Reference, hostInputs, vSanConfigSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterRuleInfo[]> FindRulesForVm(VirtualMachine vm)
    {
        return await this.Session.Client.FindRulesForVm(this.Reference, vm?.Reference);
    }

    public async System.Threading.Tasks.Task<ClusterResourceUsageSummary> GetResourceUsage()
    {
        return await this.Session.Client.GetResourceUsage(this.Reference);
    }

    public async System.Threading.Tasks.Task<Datastore[]> GetSystemVMsRestrictedDatastores()
    {
        var res = await this.Session.Client.GetSystemVMsRestrictedDatastores(this.Reference);
        return res?.Select(r => ManagedObject.Create<Datastore>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<Task> MoveHostInto_Task(HostSystem host, ResourcePool resourcePool)
    {
        var res = await this.Session.Client.MoveHostInto_Task(this.Reference, host?.Reference, resourcePool?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MoveInto_Task(HostSystem[] host)
    {
        var res = await this.Session.Client.MoveInto_Task(this.Reference, host?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<PlacementResult> PlaceVm(PlacementSpec placementSpec)
    {
        return await this.Session.Client.PlaceVm(this.Reference, placementSpec);
    }

    public async System.Threading.Tasks.Task<ClusterHostRecommendation[]> RecommendHostsForVm(VirtualMachine vm, ResourcePool pool)
    {
        return await this.Session.Client.RecommendHostsForVm(this.Reference, vm?.Reference, pool?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ReconfigureCluster_Task(ClusterConfigSpec spec, bool modify)
    {
        var res = await this.Session.Client.ReconfigureCluster_Task(this.Reference, spec, modify);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshRecommendation()
    {
        await this.Session.Client.RefreshRecommendation(this.Reference);
    }

    public async System.Threading.Tasks.Task<ClusterDasAdvancedRuntimeInfo> RetrieveDasAdvancedRuntimeInfo()
    {
        return await this.Session.Client.RetrieveDasAdvancedRuntimeInfo(this.Reference);
    }

    public async System.Threading.Tasks.Task SetCryptoMode(string cryptoMode)
    {
        await this.Session.Client.SetCryptoMode(this.Reference, cryptoMode);
    }

    public async System.Threading.Tasks.Task<Task> StampAllRulesWithUuid_Task()
    {
        var res = await this.Session.Client.StampAllRulesWithUuid_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceValidationResultBase[]> ValidateHCIConfiguration(ClusterComputeResourceHCIConfigSpec hciConfigSpec, HostSystem[] hosts)
    {
        return await this.Session.Client.ValidateHCIConfiguration(this.Reference, hciConfigSpec, hosts?.Select(m => m.Reference).ToArray());
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
        return await this.GetProperty<ClusterEVCManagerEVCState>("evcState");
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource> GetPropertyManagedCluster()
    {
        var managedCluster = await this.GetProperty<ManagedObjectReference>("managedCluster");
        return ManagedObject.Create<ClusterComputeResource>(managedCluster, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckAddHostEvc_Task(HostConnectSpec cnxSpec)
    {
        var res = await this.Session.Client.CheckAddHostEvc_Task(this.Reference, cnxSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckConfigureEvcMode_Task(string evcModeKey, string evcGraphicsModeKey)
    {
        var res = await this.Session.Client.CheckConfigureEvcMode_Task(this.Reference, evcModeKey, evcGraphicsModeKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ConfigureEvcMode_Task(string evcModeKey, string evcGraphicsModeKey)
    {
        var res = await this.Session.Client.ConfigureEvcMode_Task(this.Reference, evcModeKey, evcGraphicsModeKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DisableEvcMode_Task()
    {
        var res = await this.Session.Client.DisableEvcMode_Task(this.Reference);
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
        await this.Session.Client.UpdateClusterProfile(this.Reference, config);
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

    public async System.Threading.Tasks.Task<ComputeResourceConfigInfo> GetPropertyConfigurationEx()
    {
        return await this.GetProperty<ComputeResourceConfigInfo>("configurationEx");
    }

    public async System.Threading.Tasks.Task<Datastore[]> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<EnvironmentBrowser> GetPropertyEnvironmentBrowser()
    {
        var environmentBrowser = await this.GetProperty<ManagedObjectReference>("environmentBrowser");
        return ManagedObject.Create<EnvironmentBrowser>(environmentBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<HostSystem[]> GetPropertyHost()
    {
        var host = await this.GetProperty<ManagedObjectReference[]>("host");
        return host
            .Select(r => ManagedObject.Create<HostSystem>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyLifecycleManaged()
    {
        return await this.GetProperty<bool>("lifecycleManaged");
    }

    public async System.Threading.Tasks.Task<Network[]> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network
            .Select(r => ManagedObject.Create<Network>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ResourcePool> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference>("resourcePool");
        return ManagedObject.Create<ResourcePool>(resourcePool, this.Session);
    }

    public async System.Threading.Tasks.Task<ComputeResourceSummary> GetPropertySummary()
    {
        return await this.GetProperty<ComputeResourceSummary>("summary");
    }

    public async System.Threading.Tasks.Task<Task> ReconfigureComputeResource_Task(ComputeResourceConfigSpec spec, bool modify)
    {
        var res = await this.Session.Client.ReconfigureComputeResource_Task(this.Reference, spec, modify);
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
        return ManagedObject.Create<ManagedEntity>(container, this.Session);
    }

    public async System.Threading.Tasks.Task<bool> GetPropertyRecursive()
    {
        return await this.GetProperty<bool>("recursive");
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertyType()
    {
        return await this.GetProperty<string[]>("type");
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
        return await this.GetProperty<bool>("enabled");
    }

    public async System.Threading.Tasks.Task AddKey(CryptoKeyPlain key)
    {
        await this.Session.Client.AddKey(this.Reference, key);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]> AddKeys(CryptoKeyPlain[] keys)
    {
        return await this.Session.Client.AddKeys(this.Reference, keys);
    }

    public async System.Threading.Tasks.Task<CryptoKeyId[]> ListKeys(int? limit)
    {
        return await this.Session.Client.ListKeys(this.Reference, limit ?? default, limit.HasValue);
    }

    public async System.Threading.Tasks.Task RemoveKey(CryptoKeyId key, bool force)
    {
        await this.Session.Client.RemoveKey(this.Reference, key, force);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]> RemoveKeys(CryptoKeyId[] keys, bool force)
    {
        return await this.Session.Client.RemoveKeys(this.Reference, keys, force);
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

    public async System.Threading.Tasks.Task<Task> ChangeKey_Task(CryptoKeyPlain newKey)
    {
        var res = await this.Session.Client.ChangeKey_Task(this.Reference, newKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostDisable()
    {
        await this.Session.Client.CryptoManagerHostDisable(this.Reference);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostEnable(CryptoKeyPlain initialKey)
    {
        await this.Session.Client.CryptoManagerHostEnable(this.Reference, initialKey);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostPrepare()
    {
        await this.Session.Client.CryptoManagerHostPrepare(this.Reference);
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

    public async System.Threading.Tasks.Task<KmipClusterInfo[]> GetPropertyKmipServers()
    {
        return await this.GetProperty<KmipClusterInfo[]>("kmipServers");
    }

    public async System.Threading.Tasks.Task<string> GenerateClientCsr(KeyProviderId cluster)
    {
        return await this.Session.Client.GenerateClientCsr(this.Reference, cluster);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult> GenerateKey(KeyProviderId keyProvider)
    {
        return await this.Session.Client.GenerateKey(this.Reference, keyProvider);
    }

    public async System.Threading.Tasks.Task<string> GenerateSelfSignedClientCert(KeyProviderId cluster)
    {
        return await this.Session.Client.GenerateSelfSignedClientCert(this.Reference, cluster);
    }

    public async System.Threading.Tasks.Task<KeyProviderId> GetDefaultKmsCluster(ManagedEntity entity, bool? defaultsToParent)
    {
        return await this.Session.Client.GetDefaultKmsCluster(this.Reference, entity?.Reference, defaultsToParent ?? default, defaultsToParent.HasValue);
    }

    public async System.Threading.Tasks.Task<bool> IsKmsClusterActive(KeyProviderId cluster)
    {
        return await this.Session.Client.IsKmsClusterActive(this.Reference, cluster);
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]> ListKmipServers(int? limit)
    {
        return await this.Session.Client.ListKmipServers(this.Reference, limit ?? default, limit.HasValue);
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]> ListKmsClusters(bool? includeKmsServers, int? managementTypeFilter, int? statusFilter)
    {
        return await this.Session.Client.ListKmsClusters(this.Reference, includeKmsServers ?? default, includeKmsServers.HasValue, managementTypeFilter ?? default, managementTypeFilter.HasValue, statusFilter ?? default, statusFilter.HasValue);
    }

    public async System.Threading.Tasks.Task MarkDefault(KeyProviderId clusterId)
    {
        await this.Session.Client.MarkDefault(this.Reference, clusterId);
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipCryptoKeyStatus[]> QueryCryptoKeyStatus(CryptoKeyId[] keyIds, int checkKeyBitMap)
    {
        return await this.Session.Client.QueryCryptoKeyStatus(this.Reference, keyIds, checkKeyBitMap);
    }

    public async System.Threading.Tasks.Task RegisterKmipServer(KmipServerSpec server)
    {
        await this.Session.Client.RegisterKmipServer(this.Reference, server);
    }

    public async System.Threading.Tasks.Task RegisterKmsCluster(KeyProviderId clusterId, string managementType)
    {
        await this.Session.Client.RegisterKmsCluster(this.Reference, clusterId, managementType);
    }

    public async System.Threading.Tasks.Task RemoveKmipServer(KeyProviderId clusterId, string serverName)
    {
        await this.Session.Client.RemoveKmipServer(this.Reference, clusterId, serverName);
    }

    public async System.Threading.Tasks.Task<string> RetrieveClientCert(KeyProviderId cluster)
    {
        return await this.Session.Client.RetrieveClientCert(this.Reference, cluster);
    }

    public async System.Threading.Tasks.Task<string> RetrieveClientCsr(KeyProviderId cluster)
    {
        return await this.Session.Client.RetrieveClientCsr(this.Reference, cluster);
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipServerCertInfo> RetrieveKmipServerCert(KeyProviderId keyProvider, KmipServerInfo server)
    {
        return await this.Session.Client.RetrieveKmipServerCert(this.Reference, keyProvider, server);
    }

    public async System.Threading.Tasks.Task<Task> RetrieveKmipServersStatus_Task(KmipClusterInfo[] clusters)
    {
        var res = await this.Session.Client.RetrieveKmipServersStatus_Task(this.Reference, clusters);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string> RetrieveSelfSignedClientCert(KeyProviderId cluster)
    {
        return await this.Session.Client.RetrieveSelfSignedClientCert(this.Reference, cluster);
    }

    public async System.Threading.Tasks.Task SetDefaultKmsCluster(ManagedEntity entity, KeyProviderId clusterId)
    {
        await this.Session.Client.SetDefaultKmsCluster(this.Reference, entity?.Reference, clusterId);
    }

    public async System.Threading.Tasks.Task UnregisterKmsCluster(KeyProviderId clusterId)
    {
        await this.Session.Client.UnregisterKmsCluster(this.Reference, clusterId);
    }

    public async System.Threading.Tasks.Task UpdateKmipServer(KmipServerSpec server)
    {
        await this.Session.Client.UpdateKmipServer(this.Reference, server);
    }

    public async System.Threading.Tasks.Task UpdateKmsSignedCsrClientCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.Client.UpdateKmsSignedCsrClientCert(this.Reference, cluster, certificate);
    }

    public async System.Threading.Tasks.Task UpdateSelfSignedClientCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.Client.UpdateSelfSignedClientCert(this.Reference, cluster, certificate);
    }

    public async System.Threading.Tasks.Task UploadClientCert(KeyProviderId cluster, string certificate, string privateKey)
    {
        await this.Session.Client.UploadClientCert(this.Reference, cluster, certificate, privateKey);
    }

    public async System.Threading.Tasks.Task UploadKmipServerCert(KeyProviderId cluster, string certificate)
    {
        await this.Session.Client.UploadKmipServerCert(this.Reference, cluster, certificate);
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

    public async System.Threading.Tasks.Task<CustomFieldDef[]> GetPropertyField()
    {
        return await this.GetProperty<CustomFieldDef[]>("field");
    }

    public async System.Threading.Tasks.Task<CustomFieldDef> AddCustomFieldDef(string name, string moType, PrivilegePolicyDef fieldDefPolicy, PrivilegePolicyDef fieldPolicy)
    {
        return await this.Session.Client.AddCustomFieldDef(this.Reference, name, moType, fieldDefPolicy, fieldPolicy);
    }

    public async System.Threading.Tasks.Task RemoveCustomFieldDef(int key)
    {
        await this.Session.Client.RemoveCustomFieldDef(this.Reference, key);
    }

    public async System.Threading.Tasks.Task RenameCustomFieldDef(int key, string name)
    {
        await this.Session.Client.RenameCustomFieldDef(this.Reference, key, name);
    }

    public async System.Threading.Tasks.Task SetField(ManagedEntity entity, int key, string value)
    {
        await this.Session.Client.SetField(this.Reference, entity?.Reference, key, value);
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

    public async System.Threading.Tasks.Task<byte[]> GetPropertyEncryptionKey()
    {
        return await this.GetProperty<byte[]>("encryptionKey");
    }

    public async System.Threading.Tasks.Task<CustomizationSpecInfo[]> GetPropertyInfo()
    {
        return await this.GetProperty<CustomizationSpecInfo[]>("info");
    }

    public async System.Threading.Tasks.Task CheckCustomizationResources(string guestOs)
    {
        await this.Session.Client.CheckCustomizationResources(this.Reference, guestOs);
    }

    public async System.Threading.Tasks.Task CreateCustomizationSpec(CustomizationSpecItem item)
    {
        await this.Session.Client.CreateCustomizationSpec(this.Reference, item);
    }

    public async System.Threading.Tasks.Task<string> CustomizationSpecItemToXml(CustomizationSpecItem item)
    {
        return await this.Session.Client.CustomizationSpecItemToXml(this.Reference, item);
    }

    public async System.Threading.Tasks.Task DeleteCustomizationSpec(string name)
    {
        await this.Session.Client.DeleteCustomizationSpec(this.Reference, name);
    }

    public async System.Threading.Tasks.Task<bool> DoesCustomizationSpecExist(string name)
    {
        return await this.Session.Client.DoesCustomizationSpecExist(this.Reference, name);
    }

    public async System.Threading.Tasks.Task DuplicateCustomizationSpec(string name, string newName)
    {
        await this.Session.Client.DuplicateCustomizationSpec(this.Reference, name, newName);
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem> GetCustomizationSpec(string name)
    {
        return await this.Session.Client.GetCustomizationSpec(this.Reference, name);
    }

    public async System.Threading.Tasks.Task OverwriteCustomizationSpec(CustomizationSpecItem item)
    {
        await this.Session.Client.OverwriteCustomizationSpec(this.Reference, item);
    }

    public async System.Threading.Tasks.Task RenameCustomizationSpec(string name, string newName)
    {
        await this.Session.Client.RenameCustomizationSpec(this.Reference, name, newName);
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem> XmlToCustomizationSpecItem(string specItemXml)
    {
        return await this.Session.Client.XmlToCustomizationSpecItem(this.Reference, specItemXml);
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
        return await this.GetProperty<DatacenterConfigInfo>("configuration");
    }

    public async System.Threading.Tasks.Task<Datastore[]> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyDatastoreFolder()
    {
        var datastoreFolder = await this.GetProperty<ManagedObjectReference>("datastoreFolder");
        return ManagedObject.Create<Folder>(datastoreFolder, this.Session);
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyHostFolder()
    {
        var hostFolder = await this.GetProperty<ManagedObjectReference>("hostFolder");
        return ManagedObject.Create<Folder>(hostFolder, this.Session);
    }

    public async System.Threading.Tasks.Task<Network[]> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network
            .Select(r => ManagedObject.Create<Network>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyNetworkFolder()
    {
        var networkFolder = await this.GetProperty<ManagedObjectReference>("networkFolder");
        return ManagedObject.Create<Folder>(networkFolder, this.Session);
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyVmFolder()
    {
        var vmFolder = await this.GetProperty<ManagedObjectReference>("vmFolder");
        return ManagedObject.Create<Folder>(vmFolder, this.Session);
    }

    public async System.Threading.Tasks.Task<DatacenterBasicConnectInfo[]> BatchQueryConnectInfo(HostConnectSpec[] hostSpecs)
    {
        return await this.Session.Client.BatchQueryConnectInfo(this.Reference, hostSpecs);
    }

    public async System.Threading.Tasks.Task<Task> PowerOnMultiVM_Task(VirtualMachine[] vm, OptionValue[] option)
    {
        var res = await this.Session.Client.PowerOnMultiVM_Task(this.Reference, vm?.Select(m => m.Reference).ToArray(), option);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo> QueryConnectionInfo(string hostname, int port, string username, string password, string sslThumbprint)
    {
        return await this.Session.Client.QueryConnectionInfo(this.Reference, hostname, port, username, password, sslThumbprint);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo> QueryConnectionInfoViaSpec(HostConnectSpec spec)
    {
        return await this.Session.Client.QueryConnectionInfoViaSpec(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]> QueryDatacenterConfigOptionDescriptor()
    {
        return await this.Session.Client.QueryDatacenterConfigOptionDescriptor(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ReconfigureDatacenter_Task(DatacenterConfigSpec spec, bool modify)
    {
        var res = await this.Session.Client.ReconfigureDatacenter_Task(this.Reference, spec, modify);
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
        return ManagedObject.Create<HostDatastoreBrowser>(browser, this.Session);
    }

    public async System.Threading.Tasks.Task<DatastoreCapability> GetPropertyCapability()
    {
        return await this.GetProperty<DatastoreCapability>("capability");
    }

    public async System.Threading.Tasks.Task<DatastoreHostMount[]> GetPropertyHost()
    {
        return await this.GetProperty<DatastoreHostMount[]>("host");
    }

    public async System.Threading.Tasks.Task<DatastoreInfo> GetPropertyInfo()
    {
        return await this.GetProperty<DatastoreInfo>("info");
    }

    public async System.Threading.Tasks.Task<StorageIORMInfo> GetPropertyIormConfiguration()
    {
        return await this.GetProperty<StorageIORMInfo>("iormConfiguration");
    }

    public async System.Threading.Tasks.Task<DatastoreSummary> GetPropertySummary()
    {
        return await this.GetProperty<DatastoreSummary>("summary");
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult> DatastoreEnterMaintenanceMode()
    {
        return await this.Session.Client.DatastoreEnterMaintenanceMode(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> DatastoreExitMaintenanceMode_Task()
    {
        var res = await this.Session.Client.DatastoreExitMaintenanceMode_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyDatastore()
    {
        await this.Session.Client.DestroyDatastore(this.Reference);
    }

    public async System.Threading.Tasks.Task RefreshDatastore()
    {
        await this.Session.Client.RefreshDatastore(this.Reference);
    }

    public async System.Threading.Tasks.Task RefreshDatastoreStorageInfo()
    {
        await this.Session.Client.RefreshDatastoreStorageInfo(this.Reference);
    }

    public async System.Threading.Tasks.Task RenameDatastore(string newName)
    {
        await this.Session.Client.RenameDatastore(this.Reference, newName);
    }

    public async System.Threading.Tasks.Task<Task> UpdateVirtualMachineFiles_Task(DatastoreMountPathDatastorePair[] mountPathDatastoreMapping)
    {
        var res = await this.Session.Client.UpdateVirtualMachineFiles_Task(this.Reference, mountPathDatastoreMapping);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UpdateVVolVirtualMachineFiles_Task(DatastoreVVolContainerFailoverPair[] failoverPair)
    {
        var res = await this.Session.Client.UpdateVVolVirtualMachineFiles_Task(this.Reference, failoverPair);
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

    public async System.Threading.Tasks.Task<string> ConvertNamespacePathToUuidPath(Datacenter datacenter, string namespaceUrl)
    {
        return await this.Session.Client.ConvertNamespacePathToUuidPath(this.Reference, datacenter?.Reference, namespaceUrl);
    }

    public async System.Threading.Tasks.Task<string> CreateDirectory(Datastore datastore, string displayName, string policy, long size)
    {
        return await this.Session.Client.CreateDirectory(this.Reference, datastore?.Reference, displayName, policy, size);
    }

    public async System.Threading.Tasks.Task DeleteDirectory(Datacenter datacenter, string datastorePath)
    {
        await this.Session.Client.DeleteDirectory(this.Reference, datacenter?.Reference, datastorePath);
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

    public async System.Threading.Tasks.Task<DiagnosticManagerLogHeader> BrowseDiagnosticLog(HostSystem host, string key, int? start, int? lines)
    {
        return await this.Session.Client.BrowseDiagnosticLog(this.Reference, host?.Reference, key, start ?? default, start.HasValue, lines ?? default, lines.HasValue);
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerAuditRecordResult> FetchAuditRecords(string token)
    {
        return await this.Session.Client.FetchAuditRecords(this.Reference, token);
    }

    public async System.Threading.Tasks.Task<Task> GenerateLogBundles_Task(bool includeDefault, HostSystem[] host)
    {
        var res = await this.Session.Client.GenerateLogBundles_Task(this.Reference, includeDefault, host?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerLogDescriptor[]> QueryDescriptions(HostSystem host)
    {
        return await this.Session.Client.QueryDescriptions(this.Reference, host?.Reference);
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
        return await this.GetProperty<DVPortgroupConfigInfo>("config");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyKey()
    {
        return await this.GetProperty<string>("key");
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertyPortKeys()
    {
        return await this.GetProperty<string[]>("portKeys");
    }

    public async System.Threading.Tasks.Task<Task> DVPortgroupRollback_Task(EntityBackupConfig entityBackup)
    {
        var res = await this.Session.Client.DVPortgroupRollback_Task(this.Reference, entityBackup);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ReconfigureDVPortgroup_Task(DVPortgroupConfigSpec spec)
    {
        var res = await this.Session.Client.ReconfigureDVPortgroup_Task(this.Reference, spec);
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
        return await this.GetProperty<DVSCapability>("capability");
    }

    public async System.Threading.Tasks.Task<DVSConfigInfo> GetPropertyConfig()
    {
        return await this.GetProperty<DVSConfigInfo>("config");
    }

    public async System.Threading.Tasks.Task<DVSNetworkResourcePool[]> GetPropertyNetworkResourcePool()
    {
        return await this.GetProperty<DVSNetworkResourcePool[]>("networkResourcePool");
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup[]> GetPropertyPortgroup()
    {
        var portgroup = await this.GetProperty<ManagedObjectReference[]>("portgroup");
        return portgroup
            .Select(r => ManagedObject.Create<DistributedVirtualPortgroup>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<DVSRuntimeInfo> GetPropertyRuntime()
    {
        return await this.GetProperty<DVSRuntimeInfo>("runtime");
    }

    public async System.Threading.Tasks.Task<DVSSummary> GetPropertySummary()
    {
        return await this.GetProperty<DVSSummary>("summary");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyUuid()
    {
        return await this.GetProperty<string>("uuid");
    }

    public async System.Threading.Tasks.Task<Task> AddDVPortgroup_Task(DVPortgroupConfigSpec[] spec)
    {
        var res = await this.Session.Client.AddDVPortgroup_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task AddNetworkResourcePool(DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        await this.Session.Client.AddNetworkResourcePool(this.Reference, configSpec);
    }

    public async System.Threading.Tasks.Task<Task> CreateDVPortgroup_Task(DVPortgroupConfigSpec spec)
    {
        var res = await this.Session.Client.CreateDVPortgroup_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DvsReconfigureVmVnicNetworkResourcePool_Task(DvsVmVnicResourcePoolConfigSpec[] configSpec)
    {
        var res = await this.Session.Client.DvsReconfigureVmVnicNetworkResourcePool_Task(this.Reference, configSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DVSRollback_Task(EntityBackupConfig entityBackup)
    {
        var res = await this.Session.Client.DVSRollback_Task(this.Reference, entityBackup);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task EnableNetworkResourceManagement(bool enable)
    {
        await this.Session.Client.EnableNetworkResourceManagement(this.Reference, enable);
    }

    public async System.Threading.Tasks.Task<string[]> FetchDVPortKeys(DistributedVirtualSwitchPortCriteria criteria)
    {
        return await this.Session.Client.FetchDVPortKeys(this.Reference, criteria);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPort[]> FetchDVPorts(DistributedVirtualSwitchPortCriteria criteria)
    {
        return await this.Session.Client.FetchDVPorts(this.Reference, criteria);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup> LookupDvPortGroup(string portgroupKey)
    {
        var res = await this.Session.Client.LookupDvPortGroup(this.Reference, portgroupKey);
        return ManagedObject.Create<DistributedVirtualPortgroup>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MergeDvs_Task(DistributedVirtualSwitch dvs)
    {
        var res = await this.Session.Client.MergeDvs_Task(this.Reference, dvs?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MoveDVPort_Task(string[] portKey, string destinationPortgroupKey)
    {
        var res = await this.Session.Client.MoveDVPort_Task(this.Reference, portKey, destinationPortgroupKey);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> PerformDvsProductSpecOperation_Task(string operation, DistributedVirtualSwitchProductSpec productSpec)
    {
        var res = await this.Session.Client.PerformDvsProductSpecOperation_Task(this.Reference, operation, productSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int[]> QueryUsedVlanIdInDvs()
    {
        return await this.Session.Client.QueryUsedVlanIdInDvs(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ReconfigureDVPort_Task(DVPortConfigSpec[] port)
    {
        var res = await this.Session.Client.ReconfigureDVPort_Task(this.Reference, port);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ReconfigureDvs_Task(DVSConfigSpec spec)
    {
        var res = await this.Session.Client.ReconfigureDvs_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RectifyDvsHost_Task(HostSystem[] hosts)
    {
        var res = await this.Session.Client.RectifyDvsHost_Task(this.Reference, hosts?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshDVPortState(string[] portKeys)
    {
        await this.Session.Client.RefreshDVPortState(this.Reference, portKeys);
    }

    public async System.Threading.Tasks.Task RemoveNetworkResourcePool(string[] key)
    {
        await this.Session.Client.RemoveNetworkResourcePool(this.Reference, key);
    }

    public async System.Threading.Tasks.Task UpdateDvsCapability(DVSCapability capability)
    {
        await this.Session.Client.UpdateDvsCapability(this.Reference, capability);
    }

    public async System.Threading.Tasks.Task<Task> UpdateDVSHealthCheckConfig_Task(DVSHealthCheckConfig[] healthCheckConfig)
    {
        var res = await this.Session.Client.UpdateDVSHealthCheckConfig_Task(this.Reference, healthCheckConfig);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateNetworkResourcePool(DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        await this.Session.Client.UpdateNetworkResourcePool(this.Reference, configSpec);
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

    public async System.Threading.Tasks.Task<Task> DVSManagerExportEntity_Task(SelectionSet[] selectionSet)
    {
        var res = await this.Session.Client.DVSManagerExportEntity_Task(this.Reference, selectionSet);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DVSManagerImportEntity_Task(EntityBackupConfig[] entityBackup, string importType)
    {
        var res = await this.Session.Client.DVSManagerImportEntity_Task(this.Reference, entityBackup, importType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPortgroup> DVSManagerLookupDvPortGroup(string switchUuid, string portgroupKey)
    {
        var res = await this.Session.Client.DVSManagerLookupDvPortGroup(this.Reference, switchUuid, portgroupKey);
        return ManagedObject.Create<DistributedVirtualPortgroup>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchProductSpec[]> QueryAvailableDvsSpec(bool? recommended)
    {
        return await this.Session.Client.QueryAvailableDvsSpec(this.Reference, recommended ?? default, recommended.HasValue);
    }

    public async System.Threading.Tasks.Task<HostSystem[]> QueryCompatibleHostForExistingDvs(ManagedEntity container, bool recursive, DistributedVirtualSwitch dvs)
    {
        var res = await this.Session.Client.QueryCompatibleHostForExistingDvs(this.Reference, container?.Reference, recursive, dvs?.Reference);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<HostSystem[]> QueryCompatibleHostForNewDvs(ManagedEntity container, bool recursive, DistributedVirtualSwitchProductSpec switchProductSpec)
    {
        var res = await this.Session.Client.QueryCompatibleHostForNewDvs(this.Reference, container?.Reference, recursive, switchProductSpec);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitch> QueryDvsByUuid(string uuid)
    {
        var res = await this.Session.Client.QueryDvsByUuid(this.Reference, uuid);
        return ManagedObject.Create<DistributedVirtualSwitch>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchManagerCompatibilityResult[]> QueryDvsCheckCompatibility(DistributedVirtualSwitchManagerHostContainer hostContainer, DistributedVirtualSwitchManagerDvsProductSpec dvsProductSpec, DistributedVirtualSwitchManagerHostDvsFilterSpec[] hostFilterSpec)
    {
        return await this.Session.Client.QueryDvsCheckCompatibility(this.Reference, hostContainer, dvsProductSpec, hostFilterSpec);
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchHostProductSpec[]> QueryDvsCompatibleHostSpec(DistributedVirtualSwitchProductSpec switchProductSpec)
    {
        return await this.Session.Client.QueryDvsCompatibleHostSpec(this.Reference, switchProductSpec);
    }

    public async System.Threading.Tasks.Task<DVSManagerDvsConfigTarget> QueryDvsConfigTarget(HostSystem host, DistributedVirtualSwitch dvs)
    {
        return await this.Session.Client.QueryDvsConfigTarget(this.Reference, host?.Reference, dvs?.Reference);
    }

    public async System.Threading.Tasks.Task<DVSFeatureCapability> QueryDvsFeatureCapability(DistributedVirtualSwitchProductSpec switchProductSpec)
    {
        return await this.Session.Client.QueryDvsFeatureCapability(this.Reference, switchProductSpec);
    }

    public async System.Threading.Tasks.Task<Task> RectifyDvsOnHost_Task(HostSystem[] hosts)
    {
        var res = await this.Session.Client.RectifyDvsOnHost_Task(this.Reference, hosts?.Select(m => m.Reference).ToArray());
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

    public async System.Threading.Tasks.Task<HostDatastoreBrowser> GetPropertyDatastoreBrowser()
    {
        var datastoreBrowser = await this.GetProperty<ManagedObjectReference>("datastoreBrowser");
        return ManagedObject.Create<HostDatastoreBrowser>(datastoreBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption> QueryConfigOption(string key, HostSystem host)
    {
        return await this.Session.Client.QueryConfigOption(this.Reference, key, host?.Reference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]> QueryConfigOptionDescriptor()
    {
        return await this.Session.Client.QueryConfigOptionDescriptor(this.Reference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption> QueryConfigOptionEx(EnvironmentBrowserConfigOptionQuerySpec spec)
    {
        return await this.Session.Client.QueryConfigOptionEx(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task<ConfigTarget> QueryConfigTarget(HostSystem host)
    {
        return await this.Session.Client.QueryConfigTarget(this.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task<HostCapability> QueryTargetCapabilities(HostSystem host)
    {
        return await this.Session.Client.QueryTargetCapabilities(this.Reference, host?.Reference);
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

    public async System.Threading.Tasks.Task<Event[]> GetPropertyLatestPage()
    {
        return await this.GetProperty<Event[]>("latestPage");
    }

    public async System.Threading.Tasks.Task<Event[]> ReadNextEvents(int maxCount)
    {
        return await this.Session.Client.ReadNextEvents(this.Reference, maxCount);
    }

    public async System.Threading.Tasks.Task<Event[]> ReadPreviousEvents(int maxCount)
    {
        return await this.Session.Client.ReadPreviousEvents(this.Reference, maxCount);
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
        return await this.GetProperty<EventDescription>("description");
    }

    public async System.Threading.Tasks.Task<Event> GetPropertyLatestEvent()
    {
        return await this.GetProperty<Event>("latestEvent");
    }

    public async System.Threading.Tasks.Task<int> GetPropertyMaxCollector()
    {
        return await this.GetProperty<int>("maxCollector");
    }

    public async System.Threading.Tasks.Task<EventHistoryCollector> CreateCollectorForEvents(EventFilterSpec filter)
    {
        var res = await this.Session.Client.CreateCollectorForEvents(this.Reference, filter);
        return ManagedObject.Create<EventHistoryCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task LogUserEvent(ManagedEntity entity, string msg)
    {
        await this.Session.Client.LogUserEvent(this.Reference, entity?.Reference, msg);
    }

    public async System.Threading.Tasks.Task PostEvent(Event eventToPost, TaskInfo taskInfo)
    {
        await this.Session.Client.PostEvent(this.Reference, eventToPost, taskInfo);
    }

    public async System.Threading.Tasks.Task<Event[]> QueryEvents(EventFilterSpec filter)
    {
        return await this.Session.Client.QueryEvents(this.Reference, filter);
    }

    public async System.Threading.Tasks.Task<EventArgDesc[]> RetrieveArgumentDescription(string eventTypeId)
    {
        return await this.Session.Client.RetrieveArgumentDescription(this.Reference, eventTypeId);
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

    public async System.Threading.Tasks.Task<CustomFieldDef[]> GetPropertyAvailableField()
    {
        return await this.GetProperty<CustomFieldDef[]>("availableField");
    }

    public async System.Threading.Tasks.Task<CustomFieldValue[]> GetPropertyValue()
    {
        return await this.GetProperty<CustomFieldValue[]>("value");
    }

    public async System.Threading.Tasks.Task SetCustomValue(string key, string value)
    {
        await this.Session.Client.SetCustomValue(this.Reference, key, value);
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

    public async System.Threading.Tasks.Task<Extension[]> GetPropertyExtensionList()
    {
        return await this.GetProperty<Extension[]>("extensionList");
    }

    public async System.Threading.Tasks.Task<Extension> FindExtension(string extensionKey)
    {
        return await this.Session.Client.FindExtension(this.Reference, extensionKey);
    }

    public async System.Threading.Tasks.Task<string> GetPublicKey()
    {
        return await this.Session.Client.GetPublicKey(this.Reference);
    }

    public async System.Threading.Tasks.Task<ExtensionManagerIpAllocationUsage[]> QueryExtensionIpAllocationUsage(string[] extensionKeys)
    {
        return await this.Session.Client.QueryExtensionIpAllocationUsage(this.Reference, extensionKeys);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> QueryManagedBy(string extensionKey)
    {
        var res = await this.Session.Client.QueryManagedBy(this.Reference, extensionKey);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task RegisterExtension(Extension extension)
    {
        await this.Session.Client.RegisterExtension(this.Reference, extension);
    }

    public async System.Threading.Tasks.Task SetExtensionCertificate(string extensionKey, string certificatePem)
    {
        await this.Session.Client.SetExtensionCertificate(this.Reference, extensionKey, certificatePem);
    }

    public async System.Threading.Tasks.Task SetPublicKey(string extensionKey, string publicKey)
    {
        await this.Session.Client.SetPublicKey(this.Reference, extensionKey, publicKey);
    }

    public async System.Threading.Tasks.Task UnregisterExtension(string extensionKey)
    {
        await this.Session.Client.UnregisterExtension(this.Reference, extensionKey);
    }

    public async System.Threading.Tasks.Task UpdateExtension(Extension extension)
    {
        await this.Session.Client.UpdateExtension(this.Reference, extension);
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

    public async System.Threading.Tasks.Task<string[]> GetPropertyDisabledConfigureMethod()
    {
        return await this.GetProperty<string[]>("disabledConfigureMethod");
    }

    public async System.Threading.Tasks.Task<Task> ConfigureVcha_Task(VchaClusterConfigSpec configSpec)
    {
        var res = await this.Session.Client.ConfigureVcha_Task(this.Reference, configSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreatePassiveNode_Task(PassiveNodeDeploymentSpec passiveDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var res = await this.Session.Client.CreatePassiveNode_Task(this.Reference, passiveDeploymentSpec, sourceVcSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateWitnessNode_Task(NodeDeploymentSpec witnessDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var res = await this.Session.Client.CreateWitnessNode_Task(this.Reference, witnessDeploymentSpec, sourceVcSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeployVcha_Task(VchaClusterDeploymentSpec deploymentSpec)
    {
        var res = await this.Session.Client.DeployVcha_Task(this.Reference, deploymentSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DestroyVcha_Task()
    {
        var res = await this.Session.Client.DestroyVcha_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VchaClusterConfigInfo> GetVchaConfig()
    {
        return await this.Session.Client.GetVchaConfig(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> PrepareVcha_Task(VchaClusterNetworkSpec networkSpec)
    {
        var res = await this.Session.Client.PrepareVcha_Task(this.Reference, networkSpec);
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

    public async System.Threading.Tasks.Task<string[]> GetPropertyDisabledClusterMethod()
    {
        return await this.GetProperty<string[]>("disabledClusterMethod");
    }

    public async System.Threading.Tasks.Task<string> GetClusterMode()
    {
        return await this.Session.Client.GetClusterMode(this.Reference);
    }

    public async System.Threading.Tasks.Task<VchaClusterHealth> GetVchaClusterHealth()
    {
        return await this.Session.Client.GetVchaClusterHealth(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> InitiateFailover_Task(bool planned)
    {
        var res = await this.Session.Client.InitiateFailover_Task(this.Reference, planned);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> SetClusterMode_Task(string mode)
    {
        var res = await this.Session.Client.SetClusterMode_Task(this.Reference, mode);
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

    public async System.Threading.Tasks.Task ChangeOwner(string name, Datacenter datacenter, string owner)
    {
        await this.Session.Client.ChangeOwner(this.Reference, name, datacenter?.Reference, owner);
    }

    public async System.Threading.Tasks.Task<Task> CopyDatastoreFile_Task(string sourceName, Datacenter sourceDatacenter, string destinationName, Datacenter destinationDatacenter, bool? force)
    {
        var res = await this.Session.Client.CopyDatastoreFile_Task(this.Reference, sourceName, sourceDatacenter?.Reference, destinationName, destinationDatacenter?.Reference, force ?? default, force.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeleteDatastoreFile_Task(string name, Datacenter datacenter)
    {
        var res = await this.Session.Client.DeleteDatastoreFile_Task(this.Reference, name, datacenter?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MakeDirectory(string name, Datacenter datacenter, bool? createParentDirectories)
    {
        await this.Session.Client.MakeDirectory(this.Reference, name, datacenter?.Reference, createParentDirectories ?? default, createParentDirectories.HasValue);
    }

    public async System.Threading.Tasks.Task<Task> MoveDatastoreFile_Task(string sourceName, Datacenter sourceDatacenter, string destinationName, Datacenter destinationDatacenter, bool? force)
    {
        var res = await this.Session.Client.MoveDatastoreFile_Task(this.Reference, sourceName, sourceDatacenter?.Reference, destinationName, destinationDatacenter?.Reference, force ?? default, force.HasValue);
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

    public async System.Threading.Tasks.Task<ManagedEntity[]> GetPropertyChildEntity()
    {
        var childEntity = await this.GetProperty<ManagedObjectReference[]>("childEntity");
        return childEntity
            .Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertyChildType()
    {
        return await this.GetProperty<string[]>("childType");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyNamespace()
    {
        return await this.GetProperty<string>("namespace");
    }

    public async System.Threading.Tasks.Task<Task> AddStandaloneHost_Task(HostConnectSpec spec, ComputeResourceConfigSpec compResSpec, bool addConnected, string license)
    {
        var res = await this.Session.Client.AddStandaloneHost_Task(this.Reference, spec, compResSpec, addConnected, license);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> BatchAddHostsToCluster_Task(ClusterComputeResource cluster, FolderNewHostSpec[] newHosts, HostSystem[] existingHosts, ComputeResourceConfigSpec compResSpec, string desiredState)
    {
        var res = await this.Session.Client.BatchAddHostsToCluster_Task(this.Reference, cluster?.Reference, newHosts, existingHosts?.Select(m => m.Reference).ToArray(), compResSpec, desiredState);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> BatchAddStandaloneHosts_Task(FolderNewHostSpec[] newHosts, ComputeResourceConfigSpec compResSpec, bool addConnected)
    {
        var res = await this.Session.Client.BatchAddStandaloneHosts_Task(this.Reference, newHosts, compResSpec, addConnected);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource> CreateCluster(string name, ClusterConfigSpec spec)
    {
        var res = await this.Session.Client.CreateCluster(this.Reference, name, spec);
        return ManagedObject.Create<ClusterComputeResource>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResource> CreateClusterEx(string name, ClusterConfigSpecEx spec)
    {
        var res = await this.Session.Client.CreateClusterEx(this.Reference, name, spec);
        return ManagedObject.Create<ClusterComputeResource>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datacenter> CreateDatacenter(string name)
    {
        var res = await this.Session.Client.CreateDatacenter(this.Reference, name);
        return ManagedObject.Create<Datacenter>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateDVS_Task(DVSCreateSpec spec)
    {
        var res = await this.Session.Client.CreateDVS_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Folder> CreateFolder(string name)
    {
        var res = await this.Session.Client.CreateFolder(this.Reference, name);
        return ManagedObject.Create<Folder>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<StoragePod> CreateStoragePod(string name)
    {
        var res = await this.Session.Client.CreateStoragePod(this.Reference, name);
        return ManagedObject.Create<StoragePod>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateVM_Task(VirtualMachineConfigSpec config, ResourcePool pool, HostSystem host)
    {
        var res = await this.Session.Client.CreateVM_Task(this.Reference, config, pool?.Reference, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MoveIntoFolder_Task(ManagedEntity[] list)
    {
        var res = await this.Session.Client.MoveIntoFolder_Task(this.Reference, list?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RegisterVM_Task(string path, string name, bool asTemplate, ResourcePool pool, HostSystem host)
    {
        var res = await this.Session.Client.RegisterVM_Task(this.Reference, path, name, asTemplate, pool?.Reference, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UnregisterAndDestroy_Task()
    {
        var res = await this.Session.Client.UnregisterAndDestroy_Task(this.Reference);
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
        await this.Session.Client.AddGuestAlias(this.Reference, vm?.Reference, auth, username, mapCert, base64Cert, aliasInfo);
    }

    public async System.Threading.Tasks.Task<GuestAliases[]> ListGuestAliases(VirtualMachine vm, GuestAuthentication auth, string username)
    {
        return await this.Session.Client.ListGuestAliases(this.Reference, vm?.Reference, auth, username);
    }

    public async System.Threading.Tasks.Task<GuestMappedAliases[]> ListGuestMappedAliases(VirtualMachine vm, GuestAuthentication auth)
    {
        return await this.Session.Client.ListGuestMappedAliases(this.Reference, vm?.Reference, auth);
    }

    public async System.Threading.Tasks.Task RemoveGuestAlias(VirtualMachine vm, GuestAuthentication auth, string username, string base64Cert, GuestAuthSubject subject)
    {
        await this.Session.Client.RemoveGuestAlias(this.Reference, vm?.Reference, auth, username, base64Cert, subject);
    }

    public async System.Threading.Tasks.Task RemoveGuestAliasByCert(VirtualMachine vm, GuestAuthentication auth, string username, string base64Cert)
    {
        await this.Session.Client.RemoveGuestAliasByCert(this.Reference, vm?.Reference, auth, username, base64Cert);
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

    public async System.Threading.Tasks.Task<GuestAuthentication> AcquireCredentialsInGuest(VirtualMachine vm, GuestAuthentication requestedAuth, long sessionID)
    {
        return await this.Session.Client.AcquireCredentialsInGuest(this.Reference, vm?.Reference, requestedAuth, sessionID);
    }

    public async System.Threading.Tasks.Task ReleaseCredentialsInGuest(VirtualMachine vm, GuestAuthentication auth)
    {
        await this.Session.Client.ReleaseCredentialsInGuest(this.Reference, vm?.Reference, auth);
    }

    public async System.Threading.Tasks.Task ValidateCredentialsInGuest(VirtualMachine vm, GuestAuthentication auth)
    {
        await this.Session.Client.ValidateCredentialsInGuest(this.Reference, vm?.Reference, auth);
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
        await this.Session.Client.ChangeFileAttributesInGuest(this.Reference, vm?.Reference, auth, guestFilePath, fileAttributes);
    }

    public async System.Threading.Tasks.Task<string> CreateTemporaryDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string prefix, string suffix, string directoryPath)
    {
        return await this.Session.Client.CreateTemporaryDirectoryInGuest(this.Reference, vm?.Reference, auth, prefix, suffix, directoryPath);
    }

    public async System.Threading.Tasks.Task<string> CreateTemporaryFileInGuest(VirtualMachine vm, GuestAuthentication auth, string prefix, string suffix, string directoryPath)
    {
        return await this.Session.Client.CreateTemporaryFileInGuest(this.Reference, vm?.Reference, auth, prefix, suffix, directoryPath);
    }

    public async System.Threading.Tasks.Task DeleteDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string directoryPath, bool recursive)
    {
        await this.Session.Client.DeleteDirectoryInGuest(this.Reference, vm?.Reference, auth, directoryPath, recursive);
    }

    public async System.Threading.Tasks.Task DeleteFileInGuest(VirtualMachine vm, GuestAuthentication auth, string filePath)
    {
        await this.Session.Client.DeleteFileInGuest(this.Reference, vm?.Reference, auth, filePath);
    }

    public async System.Threading.Tasks.Task<FileTransferInformation> InitiateFileTransferFromGuest(VirtualMachine vm, GuestAuthentication auth, string guestFilePath)
    {
        return await this.Session.Client.InitiateFileTransferFromGuest(this.Reference, vm?.Reference, auth, guestFilePath);
    }

    public async System.Threading.Tasks.Task<string> InitiateFileTransferToGuest(VirtualMachine vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes, long fileSize, bool overwrite)
    {
        return await this.Session.Client.InitiateFileTransferToGuest(this.Reference, vm?.Reference, auth, guestFilePath, fileAttributes, fileSize, overwrite);
    }

    public async System.Threading.Tasks.Task<GuestListFileInfo> ListFilesInGuest(VirtualMachine vm, GuestAuthentication auth, string filePath, int? index, int? maxResults, string matchPattern)
    {
        return await this.Session.Client.ListFilesInGuest(this.Reference, vm?.Reference, auth, filePath, index ?? default, index.HasValue, maxResults ?? default, maxResults.HasValue, matchPattern);
    }

    public async System.Threading.Tasks.Task MakeDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string directoryPath, bool createParentDirectories)
    {
        await this.Session.Client.MakeDirectoryInGuest(this.Reference, vm?.Reference, auth, directoryPath, createParentDirectories);
    }

    public async System.Threading.Tasks.Task MoveDirectoryInGuest(VirtualMachine vm, GuestAuthentication auth, string srcDirectoryPath, string dstDirectoryPath)
    {
        await this.Session.Client.MoveDirectoryInGuest(this.Reference, vm?.Reference, auth, srcDirectoryPath, dstDirectoryPath);
    }

    public async System.Threading.Tasks.Task MoveFileInGuest(VirtualMachine vm, GuestAuthentication auth, string srcFilePath, string dstFilePath, bool overwrite)
    {
        await this.Session.Client.MoveFileInGuest(this.Reference, vm?.Reference, auth, srcFilePath, dstFilePath, overwrite);
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

    public async System.Threading.Tasks.Task<GuestAliasManager> GetPropertyAliasManager()
    {
        var aliasManager = await this.GetProperty<ManagedObjectReference>("aliasManager");
        return ManagedObject.Create<GuestAliasManager>(aliasManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestAuthManager> GetPropertyAuthManager()
    {
        var authManager = await this.GetProperty<ManagedObjectReference>("authManager");
        return ManagedObject.Create<GuestAuthManager>(authManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestFileManager> GetPropertyFileManager()
    {
        var fileManager = await this.GetProperty<ManagedObjectReference>("fileManager");
        return ManagedObject.Create<GuestFileManager>(fileManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestWindowsRegistryManager> GetPropertyGuestWindowsRegistryManager()
    {
        var guestWindowsRegistryManager = await this.GetProperty<ManagedObjectReference>("guestWindowsRegistryManager");
        return ManagedObject.Create<GuestWindowsRegistryManager>(guestWindowsRegistryManager, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestProcessManager> GetPropertyProcessManager()
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

    public async System.Threading.Tasks.Task<GuestProcessInfo[]> ListProcessesInGuest(VirtualMachine vm, GuestAuthentication auth, long[] pids)
    {
        return await this.Session.Client.ListProcessesInGuest(this.Reference, vm?.Reference, auth, pids);
    }

    public async System.Threading.Tasks.Task<string[]> ReadEnvironmentVariableInGuest(VirtualMachine vm, GuestAuthentication auth, string[] names)
    {
        return await this.Session.Client.ReadEnvironmentVariableInGuest(this.Reference, vm?.Reference, auth, names);
    }

    public async System.Threading.Tasks.Task<long> StartProgramInGuest(VirtualMachine vm, GuestAuthentication auth, GuestProgramSpec spec)
    {
        return await this.Session.Client.StartProgramInGuest(this.Reference, vm?.Reference, auth, spec);
    }

    public async System.Threading.Tasks.Task TerminateProcessInGuest(VirtualMachine vm, GuestAuthentication auth, long pid)
    {
        await this.Session.Client.TerminateProcessInGuest(this.Reference, vm?.Reference, auth, pid);
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

    public async System.Threading.Tasks.Task CreateRegistryKeyInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool isVolatile, string classType)
    {
        await this.Session.Client.CreateRegistryKeyInGuest(this.Reference, vm?.Reference, auth, keyName, isVolatile, classType);
    }

    public async System.Threading.Tasks.Task DeleteRegistryKeyInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive)
    {
        await this.Session.Client.DeleteRegistryKeyInGuest(this.Reference, vm?.Reference, auth, keyName, recursive);
    }

    public async System.Threading.Tasks.Task DeleteRegistryValueInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegValueNameSpec valueName)
    {
        await this.Session.Client.DeleteRegistryValueInGuest(this.Reference, vm?.Reference, auth, valueName);
    }

    public async System.Threading.Tasks.Task<GuestRegKeyRecordSpec[]> ListRegistryKeysInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive, string matchPattern)
    {
        return await this.Session.Client.ListRegistryKeysInGuest(this.Reference, vm?.Reference, auth, keyName, recursive, matchPattern);
    }

    public async System.Threading.Tasks.Task<GuestRegValueSpec[]> ListRegistryValuesInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool expandStrings, string matchPattern)
    {
        return await this.Session.Client.ListRegistryValuesInGuest(this.Reference, vm?.Reference, auth, keyName, expandStrings, matchPattern);
    }

    public async System.Threading.Tasks.Task SetRegistryValueInGuest(VirtualMachine vm, GuestAuthentication auth, GuestRegValueSpec value)
    {
        await this.Session.Client.SetRegistryValueInGuest(this.Reference, vm?.Reference, auth, value);
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

    public async System.Threading.Tasks.Task<string> AddFilter(string providerId, string filterName, string[] infoIds)
    {
        return await this.Session.Client.AddFilter(this.Reference, providerId, filterName, infoIds);
    }

    public async System.Threading.Tasks.Task AddFilterEntities(string filterId, ManagedEntity[] entities)
    {
        await this.Session.Client.AddFilterEntities(this.Reference, filterId, entities?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task AddMonitoredEntities(string providerId, ManagedEntity[] entities)
    {
        await this.Session.Client.AddMonitoredEntities(this.Reference, providerId, entities?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<bool> HasMonitoredEntity(string providerId, ManagedEntity entity)
    {
        return await this.Session.Client.HasMonitoredEntity(this.Reference, providerId, entity?.Reference);
    }

    public async System.Threading.Tasks.Task<bool> HasProvider(string id)
    {
        return await this.Session.Client.HasProvider(this.Reference, id);
    }

    public async System.Threading.Tasks.Task PostHealthUpdates(string providerId, HealthUpdate[] updates)
    {
        await this.Session.Client.PostHealthUpdates(this.Reference, providerId, updates);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> QueryFilterEntities(string filterId)
    {
        var res = await this.Session.Client.QueryFilterEntities(this.Reference, filterId);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<string[]> QueryFilterInfoIds(string filterId)
    {
        return await this.Session.Client.QueryFilterInfoIds(this.Reference, filterId);
    }

    public async System.Threading.Tasks.Task<string[]> QueryFilterList(string providerId)
    {
        return await this.Session.Client.QueryFilterList(this.Reference, providerId);
    }

    public async System.Threading.Tasks.Task<string> QueryFilterName(string filterId)
    {
        return await this.Session.Client.QueryFilterName(this.Reference, filterId);
    }

    public async System.Threading.Tasks.Task<HealthUpdateInfo[]> QueryHealthUpdateInfos(string providerId)
    {
        return await this.Session.Client.QueryHealthUpdateInfos(this.Reference, providerId);
    }

    public async System.Threading.Tasks.Task<HealthUpdate[]> QueryHealthUpdates(string providerId)
    {
        return await this.Session.Client.QueryHealthUpdates(this.Reference, providerId);
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> QueryMonitoredEntities(string providerId)
    {
        var res = await this.Session.Client.QueryMonitoredEntities(this.Reference, providerId);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<string[]> QueryProviderList()
    {
        return await this.Session.Client.QueryProviderList(this.Reference);
    }

    public async System.Threading.Tasks.Task<string> QueryProviderName(string id)
    {
        return await this.Session.Client.QueryProviderName(this.Reference, id);
    }

    public async System.Threading.Tasks.Task<HostSystem[]> QueryUnmonitoredHosts(string providerId, ClusterComputeResource cluster)
    {
        var res = await this.Session.Client.QueryUnmonitoredHosts(this.Reference, providerId, cluster?.Reference);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<string> RegisterHealthUpdateProvider(string name, HealthUpdateInfo[] healthUpdateInfo)
    {
        return await this.Session.Client.RegisterHealthUpdateProvider(this.Reference, name, healthUpdateInfo);
    }

    public async System.Threading.Tasks.Task RemoveFilter(string filterId)
    {
        await this.Session.Client.RemoveFilter(this.Reference, filterId);
    }

    public async System.Threading.Tasks.Task RemoveFilterEntities(string filterId, ManagedEntity[] entities)
    {
        await this.Session.Client.RemoveFilterEntities(this.Reference, filterId, entities?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task RemoveMonitoredEntities(string providerId, ManagedEntity[] entities)
    {
        await this.Session.Client.RemoveMonitoredEntities(this.Reference, providerId, entities?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task UnregisterHealthUpdateProvider(string providerId)
    {
        await this.Session.Client.UnregisterHealthUpdateProvider(this.Reference, providerId);
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
        return await this.GetProperty<object>("filter");
    }

    public async System.Threading.Tasks.Task DestroyCollector()
    {
        await this.Session.Client.DestroyCollector(this.Reference);
    }

    public async System.Threading.Tasks.Task ResetCollector()
    {
        await this.Session.Client.ResetCollector(this.Reference);
    }

    public async System.Threading.Tasks.Task RewindCollector()
    {
        await this.Session.Client.RewindCollector(this.Reference);
    }

    public async System.Threading.Tasks.Task SetCollectorPageSize(int maxCount)
    {
        await this.Session.Client.SetCollectorPageSize(this.Reference, maxCount);
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
        return await this.GetProperty<HostLockdownMode>("lockdownMode");
    }

    public async System.Threading.Tasks.Task ChangeAccessMode(string principal, bool isGroup, HostAccessMode accessMode)
    {
        await this.Session.Client.ChangeAccessMode(this.Reference, principal, isGroup, accessMode);
    }

    public async System.Threading.Tasks.Task ChangeLockdownMode(HostLockdownMode mode)
    {
        await this.Session.Client.ChangeLockdownMode(this.Reference, mode);
    }

    public async System.Threading.Tasks.Task<string[]> QueryLockdownExceptions()
    {
        return await this.Session.Client.QueryLockdownExceptions(this.Reference);
    }

    public async System.Threading.Tasks.Task<string[]> QuerySystemUsers()
    {
        return await this.Session.Client.QuerySystemUsers(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostAccessControlEntry[]> RetrieveHostAccessControlEntries()
    {
        return await this.Session.Client.RetrieveHostAccessControlEntries(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateLockdownExceptions(string[] users)
    {
        await this.Session.Client.UpdateLockdownExceptions(this.Reference, users);
    }

    public async System.Threading.Tasks.Task UpdateSystemUsers(string[] users)
    {
        await this.Session.Client.UpdateSystemUsers(this.Reference, users);
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
        await this.Session.Client.DisableSmartCardAuthentication(this.Reference);
    }

    public async System.Threading.Tasks.Task EnableSmartCardAuthentication()
    {
        await this.Session.Client.EnableSmartCardAuthentication(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ImportCertificateForCAM_Task(string certPath, string camServer)
    {
        var res = await this.Session.Client.ImportCertificateForCAM_Task(this.Reference, certPath, camServer);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task InstallSmartCardTrustAnchor(string cert)
    {
        await this.Session.Client.InstallSmartCardTrustAnchor(this.Reference, cert);
    }

    public async System.Threading.Tasks.Task<Task> JoinDomain_Task(string domainName, string userName, string password)
    {
        var res = await this.Session.Client.JoinDomain_Task(this.Reference, domainName, userName, password);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> JoinDomainWithCAM_Task(string domainName, string camServer)
    {
        var res = await this.Session.Client.JoinDomainWithCAM_Task(this.Reference, domainName, camServer);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> LeaveCurrentDomain_Task(bool force)
    {
        var res = await this.Session.Client.LeaveCurrentDomain_Task(this.Reference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string[]> ListSmartCardTrustAnchors()
    {
        return await this.Session.Client.ListSmartCardTrustAnchors(this.Reference);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchor(string issuer, string serial)
    {
        await this.Session.Client.RemoveSmartCardTrustAnchor(this.Reference, issuer, serial);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchorByFingerprint(string fingerprint, string digest)
    {
        await this.Session.Client.RemoveSmartCardTrustAnchorByFingerprint(this.Reference, fingerprint, digest);
    }

    public async System.Threading.Tasks.Task ReplaceSmartCardTrustAnchors(string[] certs)
    {
        await this.Session.Client.ReplaceSmartCardTrustAnchors(this.Reference, certs);
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

    public async System.Threading.Tasks.Task<HostAssignableHardwareBinding[]> GetPropertyBinding()
    {
        return await this.GetProperty<HostAssignableHardwareBinding[]>("binding");
    }

    public async System.Threading.Tasks.Task<HostAssignableHardwareConfig> GetPropertyConfig()
    {
        return await this.GetProperty<HostAssignableHardwareConfig>("config");
    }

    public async System.Threading.Tasks.Task<byte[]> DownloadDescriptionTree()
    {
        return await this.Session.Client.DownloadDescriptionTree(this.Reference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineDynamicPassthroughInfo[]> RetrieveDynamicPassthroughInfo()
    {
        return await this.Session.Client.RetrieveDynamicPassthroughInfo(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateAssignableHardwareConfig(HostAssignableHardwareConfig config)
    {
        await this.Session.Client.UpdateAssignableHardwareConfig(this.Reference, config);
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
        return await this.GetProperty<HostAuthenticationManagerInfo>("info");
    }

    public async System.Threading.Tasks.Task<HostAuthenticationStore[]> GetPropertySupportedStore()
    {
        var supportedStore = await this.GetProperty<ManagedObjectReference[]>("supportedStore");
        return supportedStore
            .Select(r => ManagedObject.Create<HostAuthenticationStore>(r, this.Session))
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
        return await this.GetProperty<HostAuthenticationStoreInfo>("info");
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
        return await this.GetProperty<HostAutoStartManagerConfig>("config");
    }

    public async System.Threading.Tasks.Task AutoStartPowerOff()
    {
        await this.Session.Client.AutoStartPowerOff(this.Reference);
    }

    public async System.Threading.Tasks.Task AutoStartPowerOn()
    {
        await this.Session.Client.AutoStartPowerOn(this.Reference);
    }

    public async System.Threading.Tasks.Task ReconfigureAutostart(HostAutoStartManagerConfig spec)
    {
        await this.Session.Client.ReconfigureAutostart(this.Reference, spec);
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

    public async System.Threading.Tasks.Task<HostBootDeviceInfo> QueryBootDevices()
    {
        return await this.Session.Client.QueryBootDevices(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateBootDevice(string key)
    {
        await this.Session.Client.UpdateBootDevice(this.Reference, key);
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

    public async System.Threading.Tasks.Task<HostCacheConfigurationInfo[]> GetPropertyCacheConfigurationInfo()
    {
        return await this.GetProperty<HostCacheConfigurationInfo[]>("cacheConfigurationInfo");
    }

    public async System.Threading.Tasks.Task<Task> ConfigureHostCache_Task(HostCacheConfigurationSpec spec)
    {
        var res = await this.Session.Client.ConfigureHostCache_Task(this.Reference, spec);
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
        return await this.GetProperty<HostCertificateManagerCertificateInfo>("certificateInfo");
    }

    public async System.Threading.Tasks.Task<string> GenerateCertificateSigningRequest(bool useIpAddressAsCommonName)
    {
        return await this.Session.Client.GenerateCertificateSigningRequest(this.Reference, useIpAddressAsCommonName);
    }

    public async System.Threading.Tasks.Task<string> GenerateCertificateSigningRequestByDn(string distinguishedName)
    {
        return await this.Session.Client.GenerateCertificateSigningRequestByDn(this.Reference, distinguishedName);
    }

    public async System.Threading.Tasks.Task InstallServerCertificate(string cert)
    {
        await this.Session.Client.InstallServerCertificate(this.Reference, cert);
    }

    public async System.Threading.Tasks.Task<string[]> ListCACertificateRevocationLists()
    {
        return await this.Session.Client.ListCACertificateRevocationLists(this.Reference);
    }

    public async System.Threading.Tasks.Task<string[]> ListCACertificates()
    {
        return await this.Session.Client.ListCACertificates(this.Reference);
    }

    public async System.Threading.Tasks.Task ReplaceCACertificatesAndCRLs(string[] caCert, string[] caCrl)
    {
        await this.Session.Client.ReplaceCACertificatesAndCRLs(this.Reference, caCert, caCrl);
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

    public async System.Threading.Tasks.Task<HostHyperThreadScheduleInfo> GetPropertyHyperthreadInfo()
    {
        return await this.GetProperty<HostHyperThreadScheduleInfo>("hyperthreadInfo");
    }

    public async System.Threading.Tasks.Task DisableHyperThreading()
    {
        await this.Session.Client.DisableHyperThreading(this.Reference);
    }

    public async System.Threading.Tasks.Task EnableHyperThreading()
    {
        await this.Session.Client.EnableHyperThreading(this.Reference);
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

    public async System.Threading.Tasks.Task<Datastore[]> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<FileQuery[]> GetPropertySupportedType()
    {
        return await this.GetProperty<FileQuery[]>("supportedType");
    }

    public async System.Threading.Tasks.Task DeleteFile(string datastorePath)
    {
        await this.Session.Client.DeleteFile(this.Reference, datastorePath);
    }

    public async System.Threading.Tasks.Task<Task> SearchDatastore_Task(string datastorePath, HostDatastoreBrowserSearchSpec searchSpec)
    {
        var res = await this.Session.Client.SearchDatastore_Task(this.Reference, datastorePath, searchSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> SearchDatastoreSubFolders_Task(string datastorePath, HostDatastoreBrowserSearchSpec searchSpec)
    {
        var res = await this.Session.Client.SearchDatastoreSubFolders_Task(this.Reference, datastorePath, searchSpec);
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
        return await this.GetProperty<HostDatastoreSystemCapabilities>("capabilities");
    }

    public async System.Threading.Tasks.Task<Datastore[]> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task ConfigureDatastorePrincipal(string userName, string password)
    {
        await this.Session.Client.ConfigureDatastorePrincipal(this.Reference, userName, password);
    }

    public async System.Threading.Tasks.Task<Datastore> CreateLocalDatastore(string name, string path)
    {
        var res = await this.Session.Client.CreateLocalDatastore(this.Reference, name, path);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore> CreateNasDatastore(HostNasVolumeSpec spec)
    {
        var res = await this.Session.Client.CreateNasDatastore(this.Reference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore> CreateVmfsDatastore(VmfsDatastoreCreateSpec spec)
    {
        var res = await this.Session.Client.CreateVmfsDatastore(this.Reference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore> CreateVvolDatastore(HostDatastoreSystemVvolDatastoreSpec spec)
    {
        var res = await this.Session.Client.CreateVvolDatastore(this.Reference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableClusteredVmdkSupport(Datastore datastore)
    {
        await this.Session.Client.DisableClusteredVmdkSupport(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task EnableClusteredVmdkSupport(Datastore datastore)
    {
        await this.Session.Client.EnableClusteredVmdkSupport(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<Datastore> ExpandVmfsDatastore(Datastore datastore, VmfsDatastoreExpandSpec spec)
    {
        var res = await this.Session.Client.ExpandVmfsDatastore(this.Reference, datastore?.Reference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Datastore> ExtendVmfsDatastore(Datastore datastore, VmfsDatastoreExtendSpec spec)
    {
        var res = await this.Session.Client.ExtendVmfsDatastore(this.Reference, datastore?.Reference, spec);
        return ManagedObject.Create<Datastore>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]> QueryAvailableDisksForVmfs(Datastore datastore)
    {
        return await this.Session.Client.QueryAvailableDisksForVmfs(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]> QueryUnresolvedVmfsVolumes()
    {
        return await this.Session.Client.QueryUnresolvedVmfsVolumes(this.Reference);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]> QueryVmfsDatastoreCreateOptions(string devicePath, int? vmfsMajorVersion)
    {
        return await this.Session.Client.QueryVmfsDatastoreCreateOptions(this.Reference, devicePath, vmfsMajorVersion ?? default, vmfsMajorVersion.HasValue);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]> QueryVmfsDatastoreExpandOptions(Datastore datastore)
    {
        return await this.Session.Client.QueryVmfsDatastoreExpandOptions(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]> QueryVmfsDatastoreExtendOptions(Datastore datastore, string devicePath, bool? suppressExpandCandidates)
    {
        return await this.Session.Client.QueryVmfsDatastoreExtendOptions(this.Reference, datastore?.Reference, devicePath, suppressExpandCandidates ?? default, suppressExpandCandidates.HasValue);
    }

    public async System.Threading.Tasks.Task RemoveDatastore(Datastore datastore)
    {
        await this.Session.Client.RemoveDatastore(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> RemoveDatastoreEx_Task(Datastore[] datastore)
    {
        var res = await this.Session.Client.RemoveDatastoreEx_Task(this.Reference, datastore?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ResignatureUnresolvedVmfsVolume_Task(HostUnresolvedVmfsResignatureSpec resolutionSpec)
    {
        var res = await this.Session.Client.ResignatureUnresolvedVmfsVolume_Task(this.Reference, resolutionSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateLocalSwapDatastore(Datastore datastore)
    {
        await this.Session.Client.UpdateLocalSwapDatastore(this.Reference, datastore?.Reference);
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
        return await this.GetProperty<HostDateTimeInfo>("dateTimeInfo");
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemTimeZone[]> QueryAvailableTimeZones()
    {
        return await this.Session.Client.QueryAvailableTimeZones(this.Reference);
    }

    public async System.Threading.Tasks.Task<DateTime> QueryDateTime()
    {
        return await this.Session.Client.QueryDateTime(this.Reference);
    }

    public async System.Threading.Tasks.Task RefreshDateTimeSystem()
    {
        await this.Session.Client.RefreshDateTimeSystem(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemServiceTestResult> TestTimeService()
    {
        return await this.Session.Client.TestTimeService(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateDateTime(DateTime dateTime)
    {
        await this.Session.Client.UpdateDateTime(this.Reference, dateTime);
    }

    public async System.Threading.Tasks.Task UpdateDateTimeConfig(HostDateTimeConfig config)
    {
        await this.Session.Client.UpdateDateTimeConfig(this.Reference, config);
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

    public async System.Threading.Tasks.Task<HostDiagnosticPartition> GetPropertyActivePartition()
    {
        return await this.GetProperty<HostDiagnosticPartition>("activePartition");
    }

    public async System.Threading.Tasks.Task CreateDiagnosticPartition(HostDiagnosticPartitionCreateSpec spec)
    {
        await this.Session.Client.CreateDiagnosticPartition(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartition[]> QueryAvailablePartition()
    {
        return await this.Session.Client.QueryAvailablePartition(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateDescription> QueryPartitionCreateDesc(string diskUuid, string diagnosticType)
    {
        return await this.Session.Client.QueryPartitionCreateDesc(this.Reference, diskUuid, diagnosticType);
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateOption[]> QueryPartitionCreateOptions(string storageType, string diagnosticType)
    {
        return await this.Session.Client.QueryPartitionCreateOptions(this.Reference, storageType, diagnosticType);
    }

    public async System.Threading.Tasks.Task SelectActivePartition(HostScsiDiskPartition partition)
    {
        await this.Session.Client.SelectActivePartition(this.Reference, partition);
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
        return await this.GetProperty<HostEsxAgentHostManagerConfigInfo>("configInfo");
    }

    public async System.Threading.Tasks.Task EsxAgentHostManagerUpdateConfig(HostEsxAgentHostManagerConfigInfo configInfo)
    {
        await this.Session.Client.EsxAgentHostManagerUpdateConfig(this.Reference, configInfo);
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

    public async System.Threading.Tasks.Task<HostFirewallInfo> GetPropertyFirewallInfo()
    {
        return await this.GetProperty<HostFirewallInfo>("firewallInfo");
    }

    public async System.Threading.Tasks.Task DisableRuleset(string id)
    {
        await this.Session.Client.DisableRuleset(this.Reference, id);
    }

    public async System.Threading.Tasks.Task EnableRuleset(string id)
    {
        await this.Session.Client.EnableRuleset(this.Reference, id);
    }

    public async System.Threading.Tasks.Task RefreshFirewall()
    {
        await this.Session.Client.RefreshFirewall(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateDefaultPolicy(HostFirewallDefaultPolicy defaultPolicy)
    {
        await this.Session.Client.UpdateDefaultPolicy(this.Reference, defaultPolicy);
    }

    public async System.Threading.Tasks.Task UpdateRuleset(string id, HostFirewallRulesetRulesetSpec spec)
    {
        await this.Session.Client.UpdateRuleset(this.Reference, id, spec);
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

    public async System.Threading.Tasks.Task<string> BackupFirmwareConfiguration()
    {
        return await this.Session.Client.BackupFirmwareConfiguration(this.Reference);
    }

    public async System.Threading.Tasks.Task<string> QueryFirmwareConfigUploadURL()
    {
        return await this.Session.Client.QueryFirmwareConfigUploadURL(this.Reference);
    }

    public async System.Threading.Tasks.Task ResetFirmwareToFactoryDefaults()
    {
        await this.Session.Client.ResetFirmwareToFactoryDefaults(this.Reference);
    }

    public async System.Threading.Tasks.Task RestoreFirmwareConfiguration(bool force)
    {
        await this.Session.Client.RestoreFirmwareConfiguration(this.Reference, force);
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

    public async System.Threading.Tasks.Task<HostGraphicsConfig> GetPropertyGraphicsConfig()
    {
        return await this.GetProperty<HostGraphicsConfig>("graphicsConfig");
    }

    public async System.Threading.Tasks.Task<HostGraphicsInfo[]> GetPropertyGraphicsInfo()
    {
        return await this.GetProperty<HostGraphicsInfo[]>("graphicsInfo");
    }

    public async System.Threading.Tasks.Task<HostSharedGpuCapabilities[]> GetPropertySharedGpuCapabilities()
    {
        return await this.GetProperty<HostSharedGpuCapabilities[]>("sharedGpuCapabilities");
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertySharedPassthruGpuTypes()
    {
        return await this.GetProperty<string[]>("sharedPassthruGpuTypes");
    }

    public async System.Threading.Tasks.Task<bool> IsSharedGraphicsActive()
    {
        return await this.Session.Client.IsSharedGraphicsActive(this.Reference);
    }

    public async System.Threading.Tasks.Task RefreshGraphicsManager()
    {
        await this.Session.Client.RefreshGraphicsManager(this.Reference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuDeviceInfo[]> RetrieveVgpuDeviceInfo()
    {
        return await this.Session.Client.RetrieveVgpuDeviceInfo(this.Reference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuProfileInfo[]> RetrieveVgpuProfileInfo()
    {
        return await this.Session.Client.RetrieveVgpuProfileInfo(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateGraphicsConfig(HostGraphicsConfig config)
    {
        await this.Session.Client.UpdateGraphicsConfig(this.Reference, config);
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
        return await this.GetProperty<HealthSystemRuntime>("runtime");
    }

    public async System.Threading.Tasks.Task ClearSystemEventLog()
    {
        await this.Session.Client.ClearSystemEventLog(this.Reference);
    }

    public async System.Threading.Tasks.Task<SystemEventInfo[]> FetchSystemEventLog()
    {
        return await this.Session.Client.FetchSystemEventLog(this.Reference);
    }

    public async System.Threading.Tasks.Task RefreshHealthStatusSystem()
    {
        await this.Session.Client.RefreshHealthStatusSystem(this.Reference);
    }

    public async System.Threading.Tasks.Task ResetSystemHealthInfo()
    {
        await this.Session.Client.ResetSystemHealthInfo(this.Reference);
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

    public async System.Threading.Tasks.Task<SoftwarePackage[]> FetchSoftwarePackages()
    {
        return await this.Session.Client.FetchSoftwarePackages(this.Reference);
    }

    public async System.Threading.Tasks.Task<string> HostImageConfigGetAcceptance()
    {
        return await this.Session.Client.HostImageConfigGetAcceptance(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostImageProfileSummary> HostImageConfigGetProfile()
    {
        return await this.Session.Client.HostImageConfigGetProfile(this.Reference);
    }

    public async System.Threading.Tasks.Task<DateTime> InstallDate()
    {
        return await this.Session.Client.InstallDate(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateHostImageAcceptanceLevel(string newAcceptanceLevel)
    {
        await this.Session.Client.UpdateHostImageAcceptanceLevel(this.Reference, newAcceptanceLevel);
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

    public async System.Threading.Tasks.Task<string> QueryConfiguredModuleOptionString(string name)
    {
        return await this.Session.Client.QueryConfiguredModuleOptionString(this.Reference, name);
    }

    public async System.Threading.Tasks.Task<KernelModuleInfo[]> QueryModules()
    {
        return await this.Session.Client.QueryModules(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateModuleOptionString(string name, string options)
    {
        await this.Session.Client.UpdateModuleOptionString(this.Reference, name, options);
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
        await this.Session.Client.AssignUserToGroup(this.Reference, user, group);
    }

    public async System.Threading.Tasks.Task ChangePassword(string user, string oldPassword, string newPassword)
    {
        await this.Session.Client.ChangePassword(this.Reference, user, oldPassword, newPassword);
    }

    public async System.Threading.Tasks.Task CreateGroup(HostAccountSpec group)
    {
        await this.Session.Client.CreateGroup(this.Reference, group);
    }

    public async System.Threading.Tasks.Task CreateUser(HostAccountSpec user)
    {
        await this.Session.Client.CreateUser(this.Reference, user);
    }

    public async System.Threading.Tasks.Task RemoveGroup(string groupName)
    {
        await this.Session.Client.RemoveGroup(this.Reference, groupName);
    }

    public async System.Threading.Tasks.Task RemoveUser(string userName)
    {
        await this.Session.Client.RemoveUser(this.Reference, userName);
    }

    public async System.Threading.Tasks.Task UnassignUserFromGroup(string user, string group)
    {
        await this.Session.Client.UnassignUserFromGroup(this.Reference, user, group);
    }

    public async System.Threading.Tasks.Task UpdateUser(HostAccountSpec user)
    {
        await this.Session.Client.UpdateUser(this.Reference, user);
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

    public async System.Threading.Tasks.Task<ServiceConsoleReservationInfo> GetPropertyConsoleReservationInfo()
    {
        return await this.GetProperty<ServiceConsoleReservationInfo>("consoleReservationInfo");
    }

    public async System.Threading.Tasks.Task<VirtualMachineMemoryReservationInfo> GetPropertyVirtualMachineReservationInfo()
    {
        return await this.GetProperty<VirtualMachineMemoryReservationInfo>("virtualMachineReservationInfo");
    }

    public async System.Threading.Tasks.Task ReconfigureServiceConsoleReservation(long cfgBytes)
    {
        await this.Session.Client.ReconfigureServiceConsoleReservation(this.Reference, cfgBytes);
    }

    public async System.Threading.Tasks.Task ReconfigureVirtualMachineReservation(VirtualMachineMemoryReservationSpec spec)
    {
        await this.Session.Client.ReconfigureVirtualMachineReservation(this.Reference, spec);
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

    public async System.Threading.Tasks.Task<HostNetCapabilities> GetPropertyCapabilities()
    {
        return await this.GetProperty<HostNetCapabilities>("capabilities");
    }

    public async System.Threading.Tasks.Task<HostIpRouteConfig> GetPropertyConsoleIpRouteConfig()
    {
        return await this.GetProperty<HostIpRouteConfig>("consoleIpRouteConfig");
    }

    public async System.Threading.Tasks.Task<HostDnsConfig> GetPropertyDnsConfig()
    {
        return await this.GetProperty<HostDnsConfig>("dnsConfig");
    }

    public async System.Threading.Tasks.Task<HostIpRouteConfig> GetPropertyIpRouteConfig()
    {
        return await this.GetProperty<HostIpRouteConfig>("ipRouteConfig");
    }

    public async System.Threading.Tasks.Task<HostNetworkConfig> GetPropertyNetworkConfig()
    {
        return await this.GetProperty<HostNetworkConfig>("networkConfig");
    }

    public async System.Threading.Tasks.Task<HostNetworkInfo> GetPropertyNetworkInfo()
    {
        return await this.GetProperty<HostNetworkInfo>("networkInfo");
    }

    public async System.Threading.Tasks.Task<HostNetOffloadCapabilities> GetPropertyOffloadCapabilities()
    {
        return await this.GetProperty<HostNetOffloadCapabilities>("offloadCapabilities");
    }

    public async System.Threading.Tasks.Task AddPortGroup(HostPortGroupSpec portgrp)
    {
        await this.Session.Client.AddPortGroup(this.Reference, portgrp);
    }

    public async System.Threading.Tasks.Task<string> AddServiceConsoleVirtualNic(string portgroup, HostVirtualNicSpec nic)
    {
        return await this.Session.Client.AddServiceConsoleVirtualNic(this.Reference, portgroup, nic);
    }

    public async System.Threading.Tasks.Task<string> AddVirtualNic(string portgroup, HostVirtualNicSpec nic)
    {
        return await this.Session.Client.AddVirtualNic(this.Reference, portgroup, nic);
    }

    public async System.Threading.Tasks.Task AddVirtualSwitch(string vswitchName, HostVirtualSwitchSpec spec)
    {
        await this.Session.Client.AddVirtualSwitch(this.Reference, vswitchName, spec);
    }

    public async System.Threading.Tasks.Task<PhysicalNicHintInfo[]> QueryNetworkHint(string[] device)
    {
        return await this.Session.Client.QueryNetworkHint(this.Reference, device);
    }

    public async System.Threading.Tasks.Task RefreshNetworkSystem()
    {
        await this.Session.Client.RefreshNetworkSystem(this.Reference);
    }

    public async System.Threading.Tasks.Task RemovePortGroup(string pgName)
    {
        await this.Session.Client.RemovePortGroup(this.Reference, pgName);
    }

    public async System.Threading.Tasks.Task RemoveServiceConsoleVirtualNic(string device)
    {
        await this.Session.Client.RemoveServiceConsoleVirtualNic(this.Reference, device);
    }

    public async System.Threading.Tasks.Task RemoveVirtualNic(string device)
    {
        await this.Session.Client.RemoveVirtualNic(this.Reference, device);
    }

    public async System.Threading.Tasks.Task RemoveVirtualSwitch(string vswitchName)
    {
        await this.Session.Client.RemoveVirtualSwitch(this.Reference, vswitchName);
    }

    public async System.Threading.Tasks.Task RestartServiceConsoleVirtualNic(string device)
    {
        await this.Session.Client.RestartServiceConsoleVirtualNic(this.Reference, device);
    }

    public async System.Threading.Tasks.Task UpdateConsoleIpRouteConfig(HostIpRouteConfig config)
    {
        await this.Session.Client.UpdateConsoleIpRouteConfig(this.Reference, config);
    }

    public async System.Threading.Tasks.Task UpdateDnsConfig(HostDnsConfig config)
    {
        await this.Session.Client.UpdateDnsConfig(this.Reference, config);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteConfig(HostIpRouteConfig config)
    {
        await this.Session.Client.UpdateIpRouteConfig(this.Reference, config);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteTableConfig(HostIpRouteTableConfig config)
    {
        await this.Session.Client.UpdateIpRouteTableConfig(this.Reference, config);
    }

    public async System.Threading.Tasks.Task<HostNetworkConfigResult> UpdateNetworkConfig(HostNetworkConfig config, string changeMode)
    {
        return await this.Session.Client.UpdateNetworkConfig(this.Reference, config, changeMode);
    }

    public async System.Threading.Tasks.Task UpdatePhysicalNicLinkSpeed(string device, PhysicalNicLinkInfo linkSpeed)
    {
        await this.Session.Client.UpdatePhysicalNicLinkSpeed(this.Reference, device, linkSpeed);
    }

    public async System.Threading.Tasks.Task UpdatePortGroup(string pgName, HostPortGroupSpec portgrp)
    {
        await this.Session.Client.UpdatePortGroup(this.Reference, pgName, portgrp);
    }

    public async System.Threading.Tasks.Task UpdateServiceConsoleVirtualNic(string device, HostVirtualNicSpec nic)
    {
        await this.Session.Client.UpdateServiceConsoleVirtualNic(this.Reference, device, nic);
    }

    public async System.Threading.Tasks.Task UpdateVirtualNic(string device, HostVirtualNicSpec nic)
    {
        await this.Session.Client.UpdateVirtualNic(this.Reference, device, nic);
    }

    public async System.Threading.Tasks.Task UpdateVirtualSwitch(string vswitchName, HostVirtualSwitchSpec spec)
    {
        await this.Session.Client.UpdateVirtualSwitch(this.Reference, vswitchName, spec);
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
        return await this.GetProperty<NvdimmSystemInfo>("nvdimmSystemInfo");
    }

    public async System.Threading.Tasks.Task<Task> CreateNvdimmNamespace_Task(NvdimmNamespaceCreateSpec createSpec)
    {
        var res = await this.Session.Client.CreateNvdimmNamespace_Task(this.Reference, createSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateNvdimmPMemNamespace_Task(NvdimmPMemNamespaceCreateSpec createSpec)
    {
        var res = await this.Session.Client.CreateNvdimmPMemNamespace_Task(this.Reference, createSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeleteNvdimmBlockNamespaces_Task()
    {
        var res = await this.Session.Client.DeleteNvdimmBlockNamespaces_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeleteNvdimmNamespace_Task(NvdimmNamespaceDeleteSpec deleteSpec)
    {
        var res = await this.Session.Client.DeleteNvdimmNamespace_Task(this.Reference, deleteSpec);
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

    public async System.Threading.Tasks.Task<Task> CheckHostPatch_Task(string[] metaUrls, string[] bundleUrls, HostPatchManagerPatchManagerOperationSpec spec)
    {
        var res = await this.Session.Client.CheckHostPatch_Task(this.Reference, metaUrls, bundleUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> InstallHostPatch_Task(HostPatchManagerLocator repository, string updateID, bool? force)
    {
        var res = await this.Session.Client.InstallHostPatch_Task(this.Reference, repository, updateID, force ?? default, force.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> InstallHostPatchV2_Task(string[] metaUrls, string[] bundleUrls, string[] vibUrls, HostPatchManagerPatchManagerOperationSpec spec)
    {
        var res = await this.Session.Client.InstallHostPatchV2_Task(this.Reference, metaUrls, bundleUrls, vibUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> QueryHostPatch_Task(HostPatchManagerPatchManagerOperationSpec spec)
    {
        var res = await this.Session.Client.QueryHostPatch_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ScanHostPatch_Task(HostPatchManagerLocator repository, string[] updateID)
    {
        var res = await this.Session.Client.ScanHostPatch_Task(this.Reference, repository, updateID);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ScanHostPatchV2_Task(string[] metaUrls, string[] bundleUrls, HostPatchManagerPatchManagerOperationSpec spec)
    {
        var res = await this.Session.Client.ScanHostPatchV2_Task(this.Reference, metaUrls, bundleUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> StageHostPatch_Task(string[] metaUrls, string[] bundleUrls, string[] vibUrls, HostPatchManagerPatchManagerOperationSpec spec)
    {
        var res = await this.Session.Client.StageHostPatch_Task(this.Reference, metaUrls, bundleUrls, vibUrls, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UninstallHostPatch_Task(string[] bulletinIds, HostPatchManagerPatchManagerOperationSpec spec)
    {
        var res = await this.Session.Client.UninstallHostPatch_Task(this.Reference, bulletinIds, spec);
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
        return await this.GetProperty<HostPciPassthruInfo[]>("pciPassthruInfo");
    }

    public async System.Threading.Tasks.Task<HostSriovDevicePoolInfo[]> GetPropertySriovDevicePoolInfo()
    {
        return await this.GetProperty<HostSriovDevicePoolInfo[]>("sriovDevicePoolInfo");
    }

    public async System.Threading.Tasks.Task Refresh()
    {
        await this.Session.Client.Refresh(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdatePassthruConfig(HostPciPassthruConfig[] config)
    {
        await this.Session.Client.UpdatePassthruConfig(this.Reference, config);
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
        return await this.GetProperty<PowerSystemCapability>("capability");
    }

    public async System.Threading.Tasks.Task<PowerSystemInfo> GetPropertyInfo()
    {
        return await this.GetProperty<PowerSystemInfo>("info");
    }

    public async System.Threading.Tasks.Task ConfigurePowerPolicy(int key)
    {
        await this.Session.Client.ConfigurePowerPolicy(this.Reference, key);
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

    public async System.Threading.Tasks.Task<HostSystem> GetPropertyReferenceHost()
    {
        var referenceHost = await this.GetProperty<ManagedObjectReference>("referenceHost");
        return ManagedObject.Create<HostSystem>(referenceHost, this.Session);
    }

    public async System.Threading.Tasks.Task<HostProfileValidationFailureInfo> GetPropertyValidationFailureInfo()
    {
        return await this.GetProperty<HostProfileValidationFailureInfo>("validationFailureInfo");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyValidationState()
    {
        return await this.GetProperty<string>("validationState");
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyValidationStateUpdateTime()
    {
        return await this.GetProperty<DateTime>("validationStateUpdateTime");
    }

    public async System.Threading.Tasks.Task<ProfileExecuteResult> ExecuteHostProfile(HostSystem host, ProfileDeferredPolicyOptionParameter[] deferredParam)
    {
        return await this.Session.Client.ExecuteHostProfile(this.Reference, host?.Reference, deferredParam);
    }

    public async System.Threading.Tasks.Task HostProfileResetValidationState()
    {
        await this.Session.Client.HostProfileResetValidationState(this.Reference);
    }

    public async System.Threading.Tasks.Task UpdateHostProfile(HostProfileConfigSpec config)
    {
        await this.Session.Client.UpdateHostProfile(this.Reference, config);
    }

    public async System.Threading.Tasks.Task UpdateReferenceHost(HostSystem host)
    {
        await this.Session.Client.UpdateReferenceHost(this.Reference, host?.Reference);
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

    public async System.Threading.Tasks.Task<Task> ApplyEntitiesConfig_Task(ApplyHostProfileConfigurationSpec[] applyConfigSpecs)
    {
        var res = await this.Session.Client.ApplyEntitiesConfig_Task(this.Reference, applyConfigSpecs);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ApplyHostConfig_Task(HostSystem host, HostConfigSpec configSpec, ProfileDeferredPolicyOptionParameter[] userInput)
    {
        var res = await this.Session.Client.ApplyHostConfig_Task(this.Reference, host?.Reference, configSpec, userInput);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckAnswerFileStatus_Task(HostSystem[] host)
    {
        var res = await this.Session.Client.CheckAnswerFileStatus_Task(this.Reference, host?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CompositeHostProfile_Task(Profile source, Profile[] targets, HostApplyProfile toBeMerged, HostApplyProfile toBeReplacedWith, HostApplyProfile toBeDeleted, HostApplyProfile enableStatusToBeCopied)
    {
        var res = await this.Session.Client.CompositeHostProfile_Task(this.Reference, source?.Reference, targets?.Select(m => m.Reference).ToArray(), toBeMerged, toBeReplacedWith, toBeDeleted, enableStatusToBeCopied);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ApplyProfile> CreateDefaultProfile(string profileType, string profileTypeName, Profile profile)
    {
        return await this.Session.Client.CreateDefaultProfile(this.Reference, profileType, profileTypeName, profile?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ExportAnswerFile_Task(HostSystem host)
    {
        var res = await this.Session.Client.ExportAnswerFile_Task(this.Reference, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostProfileManagerConfigTaskList> GenerateConfigTaskList(HostConfigSpec configSpec, HostSystem host)
    {
        return await this.Session.Client.GenerateConfigTaskList(this.Reference, configSpec, host?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> GenerateHostConfigTaskSpec_Task(StructuredCustomizations[] hostsInfo)
    {
        var res = await this.Session.Client.GenerateHostConfigTaskSpec_Task(this.Reference, hostsInfo);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> GenerateHostProfileTaskList_Task(HostConfigSpec configSpec, HostSystem host)
    {
        var res = await this.Session.Client.GenerateHostProfileTaskList_Task(this.Reference, configSpec, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult[]> QueryAnswerFileStatus(HostSystem[] host)
    {
        return await this.Session.Client.QueryAnswerFileStatus(this.Reference, host?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<ProfileMetadata[]> QueryHostProfileMetadata(string[] profileName, Profile profile)
    {
        return await this.Session.Client.QueryHostProfileMetadata(this.Reference, profileName, profile?.Reference);
    }

    public async System.Threading.Tasks.Task<ProfileProfileStructure> QueryProfileStructure(Profile profile)
    {
        return await this.Session.Client.QueryProfileStructure(this.Reference, profile?.Reference);
    }

    public async System.Threading.Tasks.Task<AnswerFile> RetrieveAnswerFile(HostSystem host)
    {
        return await this.Session.Client.RetrieveAnswerFile(this.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task<AnswerFile> RetrieveAnswerFileForProfile(HostSystem host, HostApplyProfile applyProfile)
    {
        return await this.Session.Client.RetrieveAnswerFileForProfile(this.Reference, host?.Reference, applyProfile);
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]> RetrieveHostCustomizations(HostSystem[] hosts)
    {
        return await this.Session.Client.RetrieveHostCustomizations(this.Reference, hosts?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]> RetrieveHostCustomizationsForProfile(HostSystem[] hosts, HostApplyProfile applyProfile)
    {
        return await this.Session.Client.RetrieveHostCustomizationsForProfile(this.Reference, hosts?.Select(m => m.Reference).ToArray(), applyProfile);
    }

    public async System.Threading.Tasks.Task<Task> UpdateAnswerFile_Task(HostSystem host, AnswerFileCreateSpec configSpec)
    {
        var res = await this.Session.Client.UpdateAnswerFile_Task(this.Reference, host?.Reference, configSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UpdateHostCustomizations_Task(HostProfileManagerHostToConfigSpecMap[] hostToConfigSpecMap)
    {
        var res = await this.Session.Client.UpdateHostCustomizations_Task(this.Reference, hostToConfigSpecMap);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ValidateHostProfileComposition_Task(Profile source, Profile[] targets, HostApplyProfile toBeMerged, HostApplyProfile toReplaceWith, HostApplyProfile toBeDeleted, HostApplyProfile enableStatusToBeCopied, bool? errorOnly)
    {
        var res = await this.Session.Client.ValidateHostProfileComposition_Task(this.Reference, source?.Reference, targets?.Select(m => m.Reference).ToArray(), toBeMerged, toReplaceWith, toBeDeleted, enableStatusToBeCopied, errorOnly ?? default, errorOnly.HasValue);
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
        return await this.GetProperty<HostServiceInfo>("serviceInfo");
    }

    public async System.Threading.Tasks.Task RefreshServices()
    {
        await this.Session.Client.RefreshServices(this.Reference);
    }

    public async System.Threading.Tasks.Task RestartService(string id)
    {
        await this.Session.Client.RestartService(this.Reference, id);
    }

    public async System.Threading.Tasks.Task StartService(string id)
    {
        await this.Session.Client.StartService(this.Reference, id);
    }

    public async System.Threading.Tasks.Task StopService(string id)
    {
        await this.Session.Client.StopService(this.Reference, id);
    }

    public async System.Threading.Tasks.Task UninstallService(string id)
    {
        await this.Session.Client.UninstallService(this.Reference, id);
    }

    public async System.Threading.Tasks.Task UpdateServicePolicy(string id, string policy)
    {
        await this.Session.Client.UpdateServicePolicy(this.Reference, id, policy);
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
        return await this.GetProperty<HostSnmpConfigSpec>("configuration");
    }

    public async System.Threading.Tasks.Task<HostSnmpSystemAgentLimits> GetPropertyLimits()
    {
        return await this.GetProperty<HostSnmpSystemAgentLimits>("limits");
    }

    public async System.Threading.Tasks.Task ReconfigureSnmpAgent(HostSnmpConfigSpec spec)
    {
        await this.Session.Client.ReconfigureSnmpAgent(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task SendTestNotification()
    {
        await this.Session.Client.SendTestNotification(this.Reference);
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
        await this.Session.Client.DeleteHostSpecification(this.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task DeleteHostSubSpecification(HostSystem host, string subSpecName)
    {
        await this.Session.Client.DeleteHostSubSpecification(this.Reference, host?.Reference, subSpecName);
    }

    public async System.Threading.Tasks.Task<HostSystem[]> HostSpecGetUpdatedHosts(string startChangeID, string endChangeID)
    {
        var res = await this.Session.Client.HostSpecGetUpdatedHosts(this.Reference, startChangeID, endChangeID);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<HostSpecification> RetrieveHostSpecification(HostSystem host, bool fromHost)
    {
        return await this.Session.Client.RetrieveHostSpecification(this.Reference, host?.Reference, fromHost);
    }

    public async System.Threading.Tasks.Task UpdateHostSpecification(HostSystem host, HostSpecification hostSpec)
    {
        await this.Session.Client.UpdateHostSpecification(this.Reference, host?.Reference, hostSpec);
    }

    public async System.Threading.Tasks.Task UpdateHostSubSpecification(HostSystem host, HostSubSpecification hostSubSpec)
    {
        await this.Session.Client.UpdateHostSubSpecification(this.Reference, host?.Reference, hostSubSpec);
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
        return await this.GetProperty<HostFileSystemVolumeInfo>("fileSystemVolumeInfo");
    }

    public async System.Threading.Tasks.Task<HostMultipathStateInfo> GetPropertyMultipathStateInfo()
    {
        return await this.GetProperty<HostMultipathStateInfo>("multipathStateInfo");
    }

    public async System.Threading.Tasks.Task<HostStorageDeviceInfo> GetPropertyStorageDeviceInfo()
    {
        return await this.GetProperty<HostStorageDeviceInfo>("storageDeviceInfo");
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertySystemFile()
    {
        return await this.GetProperty<string[]>("systemFile");
    }

    public async System.Threading.Tasks.Task AddInternetScsiSendTargets(string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets)
    {
        await this.Session.Client.AddInternetScsiSendTargets(this.Reference, iScsiHbaDevice, targets);
    }

    public async System.Threading.Tasks.Task AddInternetScsiStaticTargets(string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        await this.Session.Client.AddInternetScsiStaticTargets(this.Reference, iScsiHbaDevice, targets);
    }

    public async System.Threading.Tasks.Task AttachScsiLun(string lunUuid)
    {
        await this.Session.Client.AttachScsiLun(this.Reference, lunUuid);
    }

    public async System.Threading.Tasks.Task<Task> AttachScsiLunEx_Task(string[] lunUuid)
    {
        var res = await this.Session.Client.AttachScsiLunEx_Task(this.Reference, lunUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task AttachVmfsExtent(string vmfsPath, HostScsiDiskPartition extent)
    {
        await this.Session.Client.AttachVmfsExtent(this.Reference, vmfsPath, extent);
    }

    public async System.Threading.Tasks.Task ChangeNFSUserPassword(string password)
    {
        await this.Session.Client.ChangeNFSUserPassword(this.Reference, password);
    }

    public async System.Threading.Tasks.Task ClearNFSUser()
    {
        await this.Session.Client.ClearNFSUser(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo> ComputeDiskPartitionInfo(string devicePath, HostDiskPartitionLayout layout, string partitionFormat)
    {
        return await this.Session.Client.ComputeDiskPartitionInfo(this.Reference, devicePath, layout, partitionFormat);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo> ComputeDiskPartitionInfoForResize(HostScsiDiskPartition partition, HostDiskPartitionBlockRange blockRange, string partitionFormat)
    {
        return await this.Session.Client.ComputeDiskPartitionInfoForResize(this.Reference, partition, blockRange, partitionFormat);
    }

    public async System.Threading.Tasks.Task ConnectNvmeController(HostNvmeConnectSpec connectSpec)
    {
        await this.Session.Client.ConnectNvmeController(this.Reference, connectSpec);
    }

    public async System.Threading.Tasks.Task<Task> ConnectNvmeControllerEx_Task(HostNvmeConnectSpec[] connectSpec)
    {
        var res = await this.Session.Client.ConnectNvmeControllerEx_Task(this.Reference, connectSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CreateNvmeOverRdmaAdapter(string rdmaDeviceName)
    {
        await this.Session.Client.CreateNvmeOverRdmaAdapter(this.Reference, rdmaDeviceName);
    }

    public async System.Threading.Tasks.Task CreateSoftwareAdapter(HostHbaCreateSpec spec)
    {
        await this.Session.Client.CreateSoftwareAdapter(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task DeleteScsiLunState(string lunCanonicalName)
    {
        await this.Session.Client.DeleteScsiLunState(this.Reference, lunCanonicalName);
    }

    public async System.Threading.Tasks.Task DeleteVffsVolumeState(string vffsUuid)
    {
        await this.Session.Client.DeleteVffsVolumeState(this.Reference, vffsUuid);
    }

    public async System.Threading.Tasks.Task DeleteVmfsVolumeState(string vmfsUuid)
    {
        await this.Session.Client.DeleteVmfsVolumeState(this.Reference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task DestroyVffs(string vffsPath)
    {
        await this.Session.Client.DestroyVffs(this.Reference, vffsPath);
    }

    public async System.Threading.Tasks.Task DetachScsiLun(string lunUuid)
    {
        await this.Session.Client.DetachScsiLun(this.Reference, lunUuid);
    }

    public async System.Threading.Tasks.Task<Task> DetachScsiLunEx_Task(string[] lunUuid)
    {
        var res = await this.Session.Client.DetachScsiLunEx_Task(this.Reference, lunUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DisableMultipathPath(string pathName)
    {
        await this.Session.Client.DisableMultipathPath(this.Reference, pathName);
    }

    public async System.Threading.Tasks.Task DisconnectNvmeController(HostNvmeDisconnectSpec disconnectSpec)
    {
        await this.Session.Client.DisconnectNvmeController(this.Reference, disconnectSpec);
    }

    public async System.Threading.Tasks.Task<Task> DisconnectNvmeControllerEx_Task(HostNvmeDisconnectSpec[] disconnectSpec)
    {
        var res = await this.Session.Client.DisconnectNvmeControllerEx_Task(this.Reference, disconnectSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DiscoverFcoeHbas(FcoeConfigFcoeSpecification fcoeSpec)
    {
        await this.Session.Client.DiscoverFcoeHbas(this.Reference, fcoeSpec);
    }

    public async System.Threading.Tasks.Task<HostNvmeDiscoveryLog> DiscoverNvmeControllers(HostNvmeDiscoverSpec discoverSpec)
    {
        return await this.Session.Client.DiscoverNvmeControllers(this.Reference, discoverSpec);
    }

    public async System.Threading.Tasks.Task EnableMultipathPath(string pathName)
    {
        await this.Session.Client.EnableMultipathPath(this.Reference, pathName);
    }

    public async System.Threading.Tasks.Task ExpandVmfsExtent(string vmfsPath, HostScsiDiskPartition extent)
    {
        await this.Session.Client.ExpandVmfsExtent(this.Reference, vmfsPath, extent);
    }

    public async System.Threading.Tasks.Task ExtendVffs(string vffsPath, string devicePath, HostDiskPartitionSpec spec)
    {
        await this.Session.Client.ExtendVffs(this.Reference, vffsPath, devicePath, spec);
    }

    public async System.Threading.Tasks.Task<HostVffsVolume> FormatVffs(HostVffsSpec createSpec)
    {
        return await this.Session.Client.FormatVffs(this.Reference, createSpec);
    }

    public async System.Threading.Tasks.Task<HostVmfsVolume> FormatVmfs(HostVmfsSpec createSpec)
    {
        return await this.Session.Client.FormatVmfs(this.Reference, createSpec);
    }

    public async System.Threading.Tasks.Task<Task> MarkAsLocal_Task(string scsiDiskUuid)
    {
        var res = await this.Session.Client.MarkAsLocal_Task(this.Reference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MarkAsNonLocal_Task(string scsiDiskUuid)
    {
        var res = await this.Session.Client.MarkAsNonLocal_Task(this.Reference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MarkAsNonSsd_Task(string scsiDiskUuid)
    {
        var res = await this.Session.Client.MarkAsNonSsd_Task(this.Reference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MarkAsSsd_Task(string scsiDiskUuid)
    {
        var res = await this.Session.Client.MarkAsSsd_Task(this.Reference, scsiDiskUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MarkForRemoval(string hbaName, bool remove)
    {
        await this.Session.Client.MarkForRemoval(this.Reference, hbaName, remove);
    }

    public async System.Threading.Tasks.Task MarkPerenniallyReserved(string lunUuid, bool state)
    {
        await this.Session.Client.MarkPerenniallyReserved(this.Reference, lunUuid, state);
    }

    public async System.Threading.Tasks.Task<Task> MarkPerenniallyReservedEx_Task(string[] lunUuid, bool state)
    {
        var res = await this.Session.Client.MarkPerenniallyReservedEx_Task(this.Reference, lunUuid, state);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MountVffsVolume(string vffsUuid)
    {
        await this.Session.Client.MountVffsVolume(this.Reference, vffsUuid);
    }

    public async System.Threading.Tasks.Task MountVmfsVolume(string vmfsUuid)
    {
        await this.Session.Client.MountVmfsVolume(this.Reference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task<Task> MountVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.Client.MountVmfsVolumeEx_Task(this.Reference, vmfsUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]> QueryAvailableSsds(string vffsPath)
    {
        return await this.Session.Client.QueryAvailableSsds(this.Reference, vffsPath);
    }

    public async System.Threading.Tasks.Task<HostNasVolumeUserInfo> QueryNFSUser()
    {
        return await this.Session.Client.QueryNFSUser(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostPathSelectionPolicyOption[]> QueryPathSelectionPolicyOptions()
    {
        return await this.Session.Client.QueryPathSelectionPolicyOptions(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostStorageArrayTypePolicyOption[]> QueryStorageArrayTypePolicyOptions()
    {
        return await this.Session.Client.QueryStorageArrayTypePolicyOptions(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]> QueryUnresolvedVmfsVolume()
    {
        return await this.Session.Client.QueryUnresolvedVmfsVolume(this.Reference);
    }

    public async System.Threading.Tasks.Task<VmfsConfigOption[]> QueryVmfsConfigOption()
    {
        return await this.Session.Client.QueryVmfsConfigOption(this.Reference);
    }

    public async System.Threading.Tasks.Task RefreshStorageSystem()
    {
        await this.Session.Client.RefreshStorageSystem(this.Reference);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiSendTargets(string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets, bool? force)
    {
        await this.Session.Client.RemoveInternetScsiSendTargets(this.Reference, iScsiHbaDevice, targets, force ?? default, force.HasValue);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiStaticTargets(string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        await this.Session.Client.RemoveInternetScsiStaticTargets(this.Reference, iScsiHbaDevice, targets);
    }

    public async System.Threading.Tasks.Task RemoveNvmeOverRdmaAdapter(string hbaDeviceName)
    {
        await this.Session.Client.RemoveNvmeOverRdmaAdapter(this.Reference, hbaDeviceName);
    }

    public async System.Threading.Tasks.Task RemoveSoftwareAdapter(string hbaDeviceName)
    {
        await this.Session.Client.RemoveSoftwareAdapter(this.Reference, hbaDeviceName);
    }

    public async System.Threading.Tasks.Task RescanAllHba()
    {
        await this.Session.Client.RescanAllHba(this.Reference);
    }

    public async System.Threading.Tasks.Task RescanHba(string hbaDevice)
    {
        await this.Session.Client.RescanHba(this.Reference, hbaDevice);
    }

    public async System.Threading.Tasks.Task RescanVffs()
    {
        await this.Session.Client.RescanVffs(this.Reference);
    }

    public async System.Threading.Tasks.Task RescanVmfs()
    {
        await this.Session.Client.RescanVmfs(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsResolutionResult[]> ResolveMultipleUnresolvedVmfsVolumes(HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        return await this.Session.Client.ResolveMultipleUnresolvedVmfsVolumes(this.Reference, resolutionSpec);
    }

    public async System.Threading.Tasks.Task<Task> ResolveMultipleUnresolvedVmfsVolumesEx_Task(HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        var res = await this.Session.Client.ResolveMultipleUnresolvedVmfsVolumesEx_Task(this.Reference, resolutionSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo[]> RetrieveDiskPartitionInfo(string[] devicePath)
    {
        return await this.Session.Client.RetrieveDiskPartitionInfo(this.Reference, devicePath);
    }

    public async System.Threading.Tasks.Task SetMultipathLunPolicy(string lunId, HostMultipathInfoLogicalUnitPolicy policy)
    {
        await this.Session.Client.SetMultipathLunPolicy(this.Reference, lunId, policy);
    }

    public async System.Threading.Tasks.Task SetNFSUser(string user, string password)
    {
        await this.Session.Client.SetNFSUser(this.Reference, user, password);
    }

    public async System.Threading.Tasks.Task<Task> TurnDiskLocatorLedOff_Task(string[] scsiDiskUuids)
    {
        var res = await this.Session.Client.TurnDiskLocatorLedOff_Task(this.Reference, scsiDiskUuids);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> TurnDiskLocatorLedOn_Task(string[] scsiDiskUuids)
    {
        var res = await this.Session.Client.TurnDiskLocatorLedOn_Task(this.Reference, scsiDiskUuids);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UnmapVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.Client.UnmapVmfsVolumeEx_Task(this.Reference, vmfsUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UnmountForceMountedVmfsVolume(string vmfsUuid)
    {
        await this.Session.Client.UnmountForceMountedVmfsVolume(this.Reference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task UnmountVffsVolume(string vffsUuid)
    {
        await this.Session.Client.UnmountVffsVolume(this.Reference, vffsUuid);
    }

    public async System.Threading.Tasks.Task UnmountVmfsVolume(string vmfsUuid)
    {
        await this.Session.Client.UnmountVmfsVolume(this.Reference, vmfsUuid);
    }

    public async System.Threading.Tasks.Task<Task> UnmountVmfsVolumeEx_Task(string[] vmfsUuid)
    {
        var res = await this.Session.Client.UnmountVmfsVolumeEx_Task(this.Reference, vmfsUuid);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateDiskPartitions(string devicePath, HostDiskPartitionSpec spec)
    {
        await this.Session.Client.UpdateDiskPartitions(this.Reference, devicePath, spec);
    }

    public async System.Threading.Tasks.Task UpdateHppMultipathLunPolicy(string lunId, HostMultipathInfoHppLogicalUnitPolicy policy)
    {
        await this.Session.Client.UpdateHppMultipathLunPolicy(this.Reference, lunId, policy);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAdvancedOptions(string iScsiHbaDevice, HostInternetScsiHbaTargetSet targetSet, HostInternetScsiHbaParamValue[] options)
    {
        await this.Session.Client.UpdateInternetScsiAdvancedOptions(this.Reference, iScsiHbaDevice, targetSet, options);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAlias(string iScsiHbaDevice, string iScsiAlias)
    {
        await this.Session.Client.UpdateInternetScsiAlias(this.Reference, iScsiHbaDevice, iScsiAlias);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAuthenticationProperties(string iScsiHbaDevice, HostInternetScsiHbaAuthenticationProperties authenticationProperties, HostInternetScsiHbaTargetSet targetSet)
    {
        await this.Session.Client.UpdateInternetScsiAuthenticationProperties(this.Reference, iScsiHbaDevice, authenticationProperties, targetSet);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDigestProperties(string iScsiHbaDevice, HostInternetScsiHbaTargetSet targetSet, HostInternetScsiHbaDigestProperties digestProperties)
    {
        await this.Session.Client.UpdateInternetScsiDigestProperties(this.Reference, iScsiHbaDevice, targetSet, digestProperties);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDiscoveryProperties(string iScsiHbaDevice, HostInternetScsiHbaDiscoveryProperties discoveryProperties)
    {
        await this.Session.Client.UpdateInternetScsiDiscoveryProperties(this.Reference, iScsiHbaDevice, discoveryProperties);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiIPProperties(string iScsiHbaDevice, HostInternetScsiHbaIPProperties ipProperties)
    {
        await this.Session.Client.UpdateInternetScsiIPProperties(this.Reference, iScsiHbaDevice, ipProperties);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiName(string iScsiHbaDevice, string iScsiName)
    {
        await this.Session.Client.UpdateInternetScsiName(this.Reference, iScsiHbaDevice, iScsiName);
    }

    public async System.Threading.Tasks.Task UpdateScsiLunDisplayName(string lunUuid, string displayName)
    {
        await this.Session.Client.UpdateScsiLunDisplayName(this.Reference, lunUuid, displayName);
    }

    public async System.Threading.Tasks.Task UpdateSoftwareInternetScsiEnabled(bool enabled)
    {
        await this.Session.Client.UpdateSoftwareInternetScsiEnabled(this.Reference, enabled);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapBandwidth(string vmfsUuid, VmfsUnmapBandwidthSpec unmapBandwidthSpec)
    {
        await this.Session.Client.UpdateVmfsUnmapBandwidth(this.Reference, vmfsUuid, unmapBandwidthSpec);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapPriority(string vmfsUuid, string unmapPriority)
    {
        await this.Session.Client.UpdateVmfsUnmapPriority(this.Reference, vmfsUuid, unmapPriority);
    }

    public async System.Threading.Tasks.Task UpgradeVmfs(string vmfsPath)
    {
        await this.Session.Client.UpgradeVmfs(this.Reference, vmfsPath);
    }

    public async System.Threading.Tasks.Task UpgradeVmLayout()
    {
        await this.Session.Client.UpgradeVmLayout(this.Reference);
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

    public async System.Threading.Tasks.Task<AnswerFileStatusResult> GetPropertyAnswerFileValidationResult()
    {
        return await this.GetProperty<AnswerFileStatusResult>("answerFileValidationResult");
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult> GetPropertyAnswerFileValidationState()
    {
        return await this.GetProperty<AnswerFileStatusResult>("answerFileValidationState");
    }

    public async System.Threading.Tasks.Task<HostCapability> GetPropertyCapability()
    {
        return await this.GetProperty<HostCapability>("capability");
    }

    public async System.Threading.Tasks.Task<ComplianceResult> GetPropertyComplianceCheckResult()
    {
        return await this.GetProperty<ComplianceResult>("complianceCheckResult");
    }

    public async System.Threading.Tasks.Task<HostSystemComplianceCheckState> GetPropertyComplianceCheckState()
    {
        return await this.GetProperty<HostSystemComplianceCheckState>("complianceCheckState");
    }

    public async System.Threading.Tasks.Task<HostConfigInfo> GetPropertyConfig()
    {
        return await this.GetProperty<HostConfigInfo>("config");
    }

    public async System.Threading.Tasks.Task<HostConfigManager> GetPropertyConfigManager()
    {
        return await this.GetProperty<HostConfigManager>("configManager");
    }

    public async System.Threading.Tasks.Task<Datastore[]> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<HostDatastoreBrowser> GetPropertyDatastoreBrowser()
    {
        var datastoreBrowser = await this.GetProperty<ManagedObjectReference>("datastoreBrowser");
        return ManagedObject.Create<HostDatastoreBrowser>(datastoreBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<HostHardwareInfo> GetPropertyHardware()
    {
        return await this.GetProperty<HostHardwareInfo>("hardware");
    }

    public async System.Threading.Tasks.Task<HostLicensableResourceInfo> GetPropertyLicensableResource()
    {
        return await this.GetProperty<HostLicensableResourceInfo>("licensableResource");
    }

    public async System.Threading.Tasks.Task<Network[]> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network
            .Select(r => ManagedObject.Create<Network>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ApplyHostProfileConfigurationSpec> GetPropertyPrecheckRemediationResult()
    {
        return await this.GetProperty<ApplyHostProfileConfigurationSpec>("precheckRemediationResult");
    }

    public async System.Threading.Tasks.Task<ApplyHostProfileConfigurationResult> GetPropertyRemediationResult()
    {
        return await this.GetProperty<ApplyHostProfileConfigurationResult>("remediationResult");
    }

    public async System.Threading.Tasks.Task<HostSystemRemediationState> GetPropertyRemediationState()
    {
        return await this.GetProperty<HostSystemRemediationState>("remediationState");
    }

    public async System.Threading.Tasks.Task<HostRuntimeInfo> GetPropertyRuntime()
    {
        return await this.GetProperty<HostRuntimeInfo>("runtime");
    }

    public async System.Threading.Tasks.Task<HostListSummary> GetPropertySummary()
    {
        return await this.GetProperty<HostListSummary>("summary");
    }

    public async System.Threading.Tasks.Task<HostSystemResourceInfo> GetPropertySystemResources()
    {
        return await this.GetProperty<HostSystemResourceInfo>("systemResources");
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<HostServiceTicket> AcquireCimServicesTicket()
    {
        return await this.Session.Client.AcquireCimServicesTicket(this.Reference);
    }

    public async System.Threading.Tasks.Task ConfigureCryptoKey(CryptoKeyId keyId)
    {
        await this.Session.Client.ConfigureCryptoKey(this.Reference, keyId);
    }

    public async System.Threading.Tasks.Task<Task> DisconnectHost_Task()
    {
        var res = await this.Session.Client.DisconnectHost_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task EnableCrypto(CryptoKeyPlain keyPlain)
    {
        await this.Session.Client.EnableCrypto(this.Reference, keyPlain);
    }

    public async System.Threading.Tasks.Task EnterLockdownMode()
    {
        await this.Session.Client.EnterLockdownMode(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> EnterMaintenanceMode_Task(int timeout, bool? evacuatePoweredOffVms, HostMaintenanceSpec maintenanceSpec)
    {
        var res = await this.Session.Client.EnterMaintenanceMode_Task(this.Reference, timeout, evacuatePoweredOffVms ?? default, evacuatePoweredOffVms.HasValue, maintenanceSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ExitLockdownMode()
    {
        await this.Session.Client.ExitLockdownMode(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ExitMaintenanceMode_Task(int timeout)
    {
        var res = await this.Session.Client.ExitMaintenanceMode_Task(this.Reference, timeout);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> PowerDownHostToStandBy_Task(int timeoutSec, bool? evacuatePoweredOffVms)
    {
        var res = await this.Session.Client.PowerDownHostToStandBy_Task(this.Reference, timeoutSec, evacuatePoweredOffVms ?? default, evacuatePoweredOffVms.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> PowerUpHostFromStandBy_Task(int timeoutSec)
    {
        var res = await this.Session.Client.PowerUpHostFromStandBy_Task(this.Reference, timeoutSec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task PrepareCrypto()
    {
        await this.Session.Client.PrepareCrypto(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostConnectInfo> QueryHostConnectionInfo()
    {
        return await this.Session.Client.QueryHostConnectionInfo(this.Reference);
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverhead(long memorySize, int? videoRamSize, int numVcpus)
    {
        return await this.Session.Client.QueryMemoryOverhead(this.Reference, memorySize, videoRamSize ?? default, videoRamSize.HasValue, numVcpus);
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverheadEx(VirtualMachineConfigInfo vmConfigInfo)
    {
        return await this.Session.Client.QueryMemoryOverheadEx(this.Reference, vmConfigInfo);
    }

    public async System.Threading.Tasks.Task<string> QueryProductLockerLocation()
    {
        return await this.Session.Client.QueryProductLockerLocation(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostTpmAttestationReport> QueryTpmAttestationReport()
    {
        return await this.Session.Client.QueryTpmAttestationReport(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> RebootHost_Task(bool force)
    {
        var res = await this.Session.Client.RebootHost_Task(this.Reference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ReconfigureHostForDAS_Task()
    {
        var res = await this.Session.Client.ReconfigureHostForDAS_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ReconnectHost_Task(HostConnectSpec cnxSpec, HostSystemReconnectSpec reconnectSpec)
    {
        var res = await this.Session.Client.ReconnectHost_Task(this.Reference, cnxSpec, reconnectSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<long> RetrieveFreeEpcMemory()
    {
        return await this.Session.Client.RetrieveFreeEpcMemory(this.Reference);
    }

    public async System.Threading.Tasks.Task<long> RetrieveHardwareUptime()
    {
        return await this.Session.Client.RetrieveHardwareUptime(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ShutdownHost_Task(bool force)
    {
        var res = await this.Session.Client.ShutdownHost_Task(this.Reference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateFlags(HostFlagInfo flagInfo)
    {
        await this.Session.Client.UpdateFlags(this.Reference, flagInfo);
    }

    public async System.Threading.Tasks.Task UpdateIpmi(HostIpmiInfo ipmiInfo)
    {
        await this.Session.Client.UpdateIpmi(this.Reference, ipmiInfo);
    }

    public async System.Threading.Tasks.Task<Task> UpdateProductLockerLocation_Task(string path)
    {
        var res = await this.Session.Client.UpdateProductLockerLocation_Task(this.Reference, path);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateSystemResources(HostSystemResourceInfo resourceInfo)
    {
        await this.Session.Client.UpdateSystemResources(this.Reference, resourceInfo);
    }

    public async System.Threading.Tasks.Task UpdateSystemSwapConfiguration(HostSystemSwapConfiguration sysSwapConfig)
    {
        await this.Session.Client.UpdateSystemSwapConfiguration(this.Reference, sysSwapConfig);
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

    public async System.Threading.Tasks.Task<HostVFlashManagerVFlashConfigInfo> GetPropertyVFlashConfigInfo()
    {
        return await this.GetProperty<HostVFlashManagerVFlashConfigInfo>("vFlashConfigInfo");
    }

    public async System.Threading.Tasks.Task<Task> ConfigureVFlashResourceEx_Task(string[] devicePath)
    {
        var res = await this.Session.Client.ConfigureVFlashResourceEx_Task(this.Reference, devicePath);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HostConfigureVFlashResource(HostVFlashManagerVFlashResourceConfigSpec spec)
    {
        await this.Session.Client.HostConfigureVFlashResource(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task HostConfigVFlashCache(HostVFlashManagerVFlashCacheConfigSpec spec)
    {
        await this.Session.Client.HostConfigVFlashCache(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task<VirtualDiskVFlashCacheConfigInfo> HostGetVFlashModuleDefaultConfig(string vFlashModule)
    {
        return await this.Session.Client.HostGetVFlashModuleDefaultConfig(this.Reference, vFlashModule);
    }

    public async System.Threading.Tasks.Task HostRemoveVFlashResource()
    {
        await this.Session.Client.HostRemoveVFlashResource(this.Reference);
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
        return await this.GetProperty<HostVirtualNicManagerInfo>("info");
    }

    public async System.Threading.Tasks.Task DeselectVnicForNicType(string nicType, string device)
    {
        await this.Session.Client.DeselectVnicForNicType(this.Reference, nicType, device);
    }

    public async System.Threading.Tasks.Task<VirtualNicManagerNetConfig> QueryNetConfig(string nicType)
    {
        return await this.Session.Client.QueryNetConfig(this.Reference, nicType);
    }

    public async System.Threading.Tasks.Task SelectVnicForNicType(string nicType, string device)
    {
        await this.Session.Client.SelectVnicForNicType(this.Reference, nicType, device);
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

    public async System.Threading.Tasks.Task<HostIpConfig> GetPropertyIpConfig()
    {
        return await this.GetProperty<HostIpConfig>("ipConfig");
    }

    public async System.Threading.Tasks.Task<HostVMotionNetConfig> GetPropertyNetConfig()
    {
        return await this.GetProperty<HostVMotionNetConfig>("netConfig");
    }

    public async System.Threading.Tasks.Task DeselectVnic()
    {
        await this.Session.Client.DeselectVnic(this.Reference);
    }

    public async System.Threading.Tasks.Task SelectVnic(string device)
    {
        await this.Session.Client.SelectVnic(this.Reference, device);
    }

    public async System.Threading.Tasks.Task UpdateIpConfig(HostIpConfig ipConfig)
    {
        await this.Session.Client.UpdateIpConfig(this.Reference, ipConfig);
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

    public async System.Threading.Tasks.Task<string[]> AbdicateDomOwnership(string[] uuids)
    {
        return await this.Session.Client.AbdicateDomOwnership(this.Reference, uuids);
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]> CanProvisionObjects(VsanNewPolicyBatch[] npbs, bool? ignoreSatisfiability)
    {
        return await this.Session.Client.CanProvisionObjects(this.Reference, npbs, ignoreSatisfiability ?? default, ignoreSatisfiability.HasValue);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemDeleteVsanObjectsResult[]> DeleteVsanObjects(string[] uuids, bool? force)
    {
        return await this.Session.Client.DeleteVsanObjects(this.Reference, uuids, force ?? default, force.HasValue);
    }

    public async System.Threading.Tasks.Task<string> GetVsanObjExtAttrs(string[] uuids)
    {
        return await this.Session.Client.GetVsanObjExtAttrs(this.Reference, uuids);
    }

    public async System.Threading.Tasks.Task<string> QueryCmmds(HostVsanInternalSystemCmmdsQuery[] queries)
    {
        return await this.Session.Client.QueryCmmds(this.Reference, queries);
    }

    public async System.Threading.Tasks.Task<string> QueryObjectsOnPhysicalVsanDisk(string[] disks)
    {
        return await this.Session.Client.QueryObjectsOnPhysicalVsanDisk(this.Reference, disks);
    }

    public async System.Threading.Tasks.Task<string> QueryPhysicalVsanDisks(string[] props)
    {
        return await this.Session.Client.QueryPhysicalVsanDisks(this.Reference, props);
    }

    public async System.Threading.Tasks.Task<string> QuerySyncingVsanObjects(string[] uuids)
    {
        return await this.Session.Client.QuerySyncingVsanObjects(this.Reference, uuids);
    }

    public async System.Threading.Tasks.Task<string> QueryVsanObjects(string[] uuids)
    {
        return await this.Session.Client.QueryVsanObjects(this.Reference, uuids);
    }

    public async System.Threading.Tasks.Task<string[]> QueryVsanObjectUuidsByFilter(string[] uuids, int? limit, int? version)
    {
        return await this.Session.Client.QueryVsanObjectUuidsByFilter(this.Reference, uuids, limit ?? default, limit.HasValue, version ?? default, version.HasValue);
    }

    public async System.Threading.Tasks.Task<string> QueryVsanStatistics(string[] labels)
    {
        return await this.Session.Client.QueryVsanStatistics(this.Reference, labels);
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]> ReconfigurationSatisfiable(VsanPolicyChangeBatch[] pcbs, bool? ignoreSatisfiability)
    {
        return await this.Session.Client.ReconfigurationSatisfiable(this.Reference, pcbs, ignoreSatisfiability ?? default, ignoreSatisfiability.HasValue);
    }

    public async System.Threading.Tasks.Task ReconfigureDomObject(string uuid, string policy)
    {
        await this.Session.Client.ReconfigureDomObject(this.Reference, uuid, policy);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanPhysicalDiskDiagnosticsResult[]> RunVsanPhysicalDiskDiagnostics(string[] disks)
    {
        return await this.Session.Client.RunVsanPhysicalDiskDiagnostics(this.Reference, disks);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanObjectOperationResult[]> UpgradeVsanObjects(string[] uuids, int newVersion)
    {
        return await this.Session.Client.UpgradeVsanObjects(this.Reference, uuids, newVersion);
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
        return await this.GetProperty<VsanHostConfigInfo>("config");
    }

    public async System.Threading.Tasks.Task<Task> AddDisks_Task(HostScsiDisk[] disk)
    {
        var res = await this.Session.Client.AddDisks_Task(this.Reference, disk);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> EvacuateVsanNode_Task(HostMaintenanceSpec maintenanceSpec, int timeout)
    {
        var res = await this.Session.Client.EvacuateVsanNode_Task(this.Reference, maintenanceSpec, timeout);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> InitializeDisks_Task(VsanHostDiskMapping[] mapping)
    {
        var res = await this.Session.Client.InitializeDisks_Task(this.Reference, mapping);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VsanHostDiskResult[]> QueryDisksForVsan(string[] canonicalName)
    {
        return await this.Session.Client.QueryDisksForVsan(this.Reference, canonicalName);
    }

    public async System.Threading.Tasks.Task<VsanHostClusterStatus> QueryHostStatus()
    {
        return await this.Session.Client.QueryHostStatus(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> RecommissionVsanNode_Task()
    {
        var res = await this.Session.Client.RecommissionVsanNode_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RemoveDisk_Task(HostScsiDisk[] disk, HostMaintenanceSpec maintenanceSpec, int? timeout)
    {
        var res = await this.Session.Client.RemoveDisk_Task(this.Reference, disk, maintenanceSpec, timeout ?? default, timeout.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RemoveDiskMapping_Task(VsanHostDiskMapping[] mapping, HostMaintenanceSpec maintenanceSpec, int? timeout)
    {
        var res = await this.Session.Client.RemoveDiskMapping_Task(this.Reference, mapping, maintenanceSpec, timeout ?? default, timeout.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UnmountDiskMapping_Task(VsanHostDiskMapping[] mapping)
    {
        var res = await this.Session.Client.UnmountDiskMapping_Task(this.Reference, mapping);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UpdateVsan_Task(VsanHostConfigInfo config)
    {
        var res = await this.Session.Client.UpdateVsan_Task(this.Reference, config);
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

    public async System.Threading.Tasks.Task HostClearVStorageObjectControlFlags(ID id, Datastore datastore, string[] controlFlags)
    {
        await this.Session.Client.HostClearVStorageObjectControlFlags(this.Reference, id, datastore?.Reference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task> HostCloneVStorageObject_Task(ID id, Datastore datastore, VslmCloneSpec spec)
    {
        var res = await this.Session.Client.HostCloneVStorageObject_Task(this.Reference, id, datastore?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostCreateDisk_Task(VslmCreateSpec spec)
    {
        var res = await this.Session.Client.HostCreateDisk_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostDeleteVStorageObject_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.Client.HostDeleteVStorageObject_Task(this.Reference, id, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostDeleteVStorageObjectEx_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.Client.HostDeleteVStorageObjectEx_Task(this.Reference, id, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostExtendDisk_Task(ID id, Datastore datastore, long newCapacityInMB)
    {
        var res = await this.Session.Client.HostExtendDisk_Task(this.Reference, id, datastore?.Reference, newCapacityInMB);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostInflateDisk_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.Client.HostInflateDisk_Task(this.Reference, id, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ID[]> HostListVStorageObject(Datastore datastore)
    {
        return await this.Session.Client.HostListVStorageObject(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> HostReconcileDatastoreInventory_Task(Datastore datastore)
    {
        var res = await this.Session.Client.HostReconcileDatastoreInventory_Task(this.Reference, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObject> HostRegisterDisk(string path, string name)
    {
        return await this.Session.Client.HostRegisterDisk(this.Reference, path, name);
    }

    public async System.Threading.Tasks.Task<Task> HostRelocateVStorageObject_Task(ID id, Datastore datastore, VslmRelocateSpec spec)
    {
        var res = await this.Session.Client.HostRelocateVStorageObject_Task(this.Reference, id, datastore?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HostRenameVStorageObject(ID id, Datastore datastore, string name)
    {
        await this.Session.Client.HostRenameVStorageObject(this.Reference, id, datastore?.Reference, name);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]> HostRetrieveVStorageInfrastructureObjectPolicy(Datastore datastore)
    {
        return await this.Session.Client.HostRetrieveVStorageInfrastructureObjectPolicy(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<VStorageObject> HostRetrieveVStorageObject(ID id, Datastore datastore)
    {
        return await this.Session.Client.HostRetrieveVStorageObject(this.Reference, id, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<KeyValue[]> HostRetrieveVStorageObjectMetadata(ID id, Datastore datastore, ID snapshotId, string prefix)
    {
        return await this.Session.Client.HostRetrieveVStorageObjectMetadata(this.Reference, id, datastore?.Reference, snapshotId, prefix);
    }

    public async System.Threading.Tasks.Task<string> HostRetrieveVStorageObjectMetadataValue(ID id, Datastore datastore, ID snapshotId, string key)
    {
        return await this.Session.Client.HostRetrieveVStorageObjectMetadataValue(this.Reference, id, datastore?.Reference, snapshotId, key);
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo> HostRetrieveVStorageObjectState(ID id, Datastore datastore)
    {
        return await this.Session.Client.HostRetrieveVStorageObjectState(this.Reference, id, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task HostScheduleReconcileDatastoreInventory(Datastore datastore)
    {
        await this.Session.Client.HostScheduleReconcileDatastoreInventory(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task HostSetVStorageObjectControlFlags(ID id, Datastore datastore, string[] controlFlags)
    {
        await this.Session.Client.HostSetVStorageObjectControlFlags(this.Reference, id, datastore?.Reference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task> HostUpdateVStorageObjectMetadata_Task(ID id, Datastore datastore, KeyValue[] metadata, string[] deleteKeys)
    {
        var res = await this.Session.Client.HostUpdateVStorageObjectMetadata_Task(this.Reference, id, datastore?.Reference, metadata, deleteKeys);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostUpdateVStorageObjectMetadataEx_Task(ID id, Datastore datastore, KeyValue[] metadata, string[] deleteKeys)
    {
        var res = await this.Session.Client.HostUpdateVStorageObjectMetadataEx_Task(this.Reference, id, datastore?.Reference, metadata, deleteKeys);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostVStorageObjectCreateDiskFromSnapshot_Task(ID id, Datastore datastore, ID snapshotId, string name, VirtualMachineProfileSpec[] profile, CryptoSpec crypto, string path)
    {
        var res = await this.Session.Client.HostVStorageObjectCreateDiskFromSnapshot_Task(this.Reference, id, datastore?.Reference, snapshotId, name, profile, crypto, path);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostVStorageObjectCreateSnapshot_Task(ID id, Datastore datastore, string description)
    {
        var res = await this.Session.Client.HostVStorageObjectCreateSnapshot_Task(this.Reference, id, datastore?.Reference, description);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> HostVStorageObjectDeleteSnapshot_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.Client.HostVStorageObjectDeleteSnapshot_Task(this.Reference, id, datastore?.Reference, snapshotId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo> HostVStorageObjectRetrieveSnapshotInfo(ID id, Datastore datastore)
    {
        return await this.Session.Client.HostVStorageObjectRetrieveSnapshotInfo(this.Reference, id, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> HostVStorageObjectRevert_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.Client.HostVStorageObjectRevert_Task(this.Reference, id, datastore?.Reference, snapshotId);
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
        return await this.GetProperty<HttpNfcLeaseCapabilities>("capabilities");
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault> GetPropertyError()
    {
        return await this.GetProperty<LocalizedMethodFault>("error");
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseInfo> GetPropertyInfo()
    {
        return await this.GetProperty<HttpNfcLeaseInfo>("info");
    }

    public async System.Threading.Tasks.Task<int> GetPropertyInitializeProgress()
    {
        return await this.GetProperty<int>("initializeProgress");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyMode()
    {
        return await this.GetProperty<string>("mode");
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseState> GetPropertyState()
    {
        return await this.GetProperty<HttpNfcLeaseState>("state");
    }

    public async System.Threading.Tasks.Task<int> GetPropertyTransferProgress()
    {
        return await this.GetProperty<int>("transferProgress");
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseAbort(LocalizedMethodFault fault)
    {
        await this.Session.Client.HttpNfcLeaseAbort(this.Reference, fault);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseComplete()
    {
        await this.Session.Client.HttpNfcLeaseComplete(this.Reference);
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseManifestEntry[]> HttpNfcLeaseGetManifest()
    {
        return await this.Session.Client.HttpNfcLeaseGetManifest(this.Reference);
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseProbeResult[]> HttpNfcLeaseProbeUrls(HttpNfcLeaseSourceFile[] files, int? timeout)
    {
        return await this.Session.Client.HttpNfcLeaseProbeUrls(this.Reference, files, timeout ?? default, timeout.HasValue);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseProgress(int percent)
    {
        await this.Session.Client.HttpNfcLeaseProgress(this.Reference, percent);
    }

    public async System.Threading.Tasks.Task<Task> HttpNfcLeasePullFromUrls_Task(HttpNfcLeaseSourceFile[] files)
    {
        var res = await this.Session.Client.HttpNfcLeasePullFromUrls_Task(this.Reference, files);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseSetManifestChecksumType(KeyValue[] deviceUrlsToChecksumTypes)
    {
        await this.Session.Client.HttpNfcLeaseSetManifestChecksumType(this.Reference, deviceUrlsToChecksumTypes);
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

    public async System.Threading.Tasks.Task<ManagedEntity[]> CloseInventoryViewFolder(ManagedEntity[] entity)
    {
        var res = await this.Session.Client.CloseInventoryViewFolder(this.Reference, entity?.Select(m => m.Reference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> OpenInventoryViewFolder(ManagedEntity[] entity)
    {
        var res = await this.Session.Client.OpenInventoryViewFolder(this.Reference, entity?.Select(m => m.Reference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
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

    public async System.Threading.Tasks.Task<Task> InstallIoFilter_Task(string vibUrl, ComputeResource compRes)
    {
        var res = await this.Session.Client.InstallIoFilter_Task(this.Reference, vibUrl, compRes?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualDiskId[]> QueryDisksUsingFilter(string filterId, ComputeResource compRes)
    {
        return await this.Session.Client.QueryDisksUsingFilter(this.Reference, filterId, compRes?.Reference);
    }

    public async System.Threading.Tasks.Task<ClusterIoFilterInfo[]> QueryIoFilterInfo(ComputeResource compRes)
    {
        return await this.Session.Client.QueryIoFilterInfo(this.Reference, compRes?.Reference);
    }

    public async System.Threading.Tasks.Task<IoFilterQueryIssueResult> QueryIoFilterIssues(string filterId, ComputeResource compRes)
    {
        return await this.Session.Client.QueryIoFilterIssues(this.Reference, filterId, compRes?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ResolveInstallationErrorsOnCluster_Task(string filterId, ClusterComputeResource cluster)
    {
        var res = await this.Session.Client.ResolveInstallationErrorsOnCluster_Task(this.Reference, filterId, cluster?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ResolveInstallationErrorsOnHost_Task(string filterId, HostSystem host)
    {
        var res = await this.Session.Client.ResolveInstallationErrorsOnHost_Task(this.Reference, filterId, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UninstallIoFilter_Task(string filterId, ComputeResource compRes)
    {
        var res = await this.Session.Client.UninstallIoFilter_Task(this.Reference, filterId, compRes?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UpgradeIoFilter_Task(string filterId, ComputeResource compRes, string vibUrl)
    {
        var res = await this.Session.Client.UpgradeIoFilter_Task(this.Reference, filterId, compRes?.Reference, vibUrl);
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

    public async System.Threading.Tasks.Task<string> AllocateIpv4Address(Datacenter dc, int poolId, string allocationId)
    {
        return await this.Session.Client.AllocateIpv4Address(this.Reference, dc?.Reference, poolId, allocationId);
    }

    public async System.Threading.Tasks.Task<string> AllocateIpv6Address(Datacenter dc, int poolId, string allocationId)
    {
        return await this.Session.Client.AllocateIpv6Address(this.Reference, dc?.Reference, poolId, allocationId);
    }

    public async System.Threading.Tasks.Task<int> CreateIpPool(Datacenter dc, IpPool pool)
    {
        return await this.Session.Client.CreateIpPool(this.Reference, dc?.Reference, pool);
    }

    public async System.Threading.Tasks.Task DestroyIpPool(Datacenter dc, int id, bool force)
    {
        await this.Session.Client.DestroyIpPool(this.Reference, dc?.Reference, id, force);
    }

    public async System.Threading.Tasks.Task<IpPoolManagerIpAllocation[]> QueryIPAllocations(Datacenter dc, int poolId, string extensionKey)
    {
        return await this.Session.Client.QueryIPAllocations(this.Reference, dc?.Reference, poolId, extensionKey);
    }

    public async System.Threading.Tasks.Task<IpPool[]> QueryIpPools(Datacenter dc)
    {
        return await this.Session.Client.QueryIpPools(this.Reference, dc?.Reference);
    }

    public async System.Threading.Tasks.Task ReleaseIpAllocation(Datacenter dc, int poolId, string allocationId)
    {
        await this.Session.Client.ReleaseIpAllocation(this.Reference, dc?.Reference, poolId, allocationId);
    }

    public async System.Threading.Tasks.Task UpdateIpPool(Datacenter dc, IpPool pool)
    {
        await this.Session.Client.UpdateIpPool(this.Reference, dc?.Reference, pool);
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
        await this.Session.Client.BindVnic(this.Reference, iScsiHbaName, vnicDevice);
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]> QueryBoundVnics(string iScsiHbaName)
    {
        return await this.Session.Client.QueryBoundVnics(this.Reference, iScsiHbaName);
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]> QueryCandidateNics(string iScsiHbaName)
    {
        return await this.Session.Client.QueryCandidateNics(this.Reference, iScsiHbaName);
    }

    public async System.Threading.Tasks.Task<IscsiMigrationDependency> QueryMigrationDependencies(string[] pnicDevice)
    {
        return await this.Session.Client.QueryMigrationDependencies(this.Reference, pnicDevice);
    }

    public async System.Threading.Tasks.Task<IscsiStatus> QueryPnicStatus(string pnicDevice)
    {
        return await this.Session.Client.QueryPnicStatus(this.Reference, pnicDevice);
    }

    public async System.Threading.Tasks.Task<IscsiStatus> QueryVnicStatus(string vnicDevice)
    {
        return await this.Session.Client.QueryVnicStatus(this.Reference, vnicDevice);
    }

    public async System.Threading.Tasks.Task UnbindVnic(string iScsiHbaName, string vnicDevice, bool force)
    {
        await this.Session.Client.UnbindVnic(this.Reference, iScsiHbaName, vnicDevice, force);
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

    public async System.Threading.Tasks.Task<LicenseAssignmentManagerLicenseAssignment[]> QueryAssignedLicenses(string entityId)
    {
        return await this.Session.Client.QueryAssignedLicenses(this.Reference, entityId);
    }

    public async System.Threading.Tasks.Task RemoveAssignedLicense(string entityId)
    {
        await this.Session.Client.RemoveAssignedLicense(this.Reference, entityId);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo> UpdateAssignedLicense(string entity, string licenseKey, string entityDisplayName)
    {
        return await this.Session.Client.UpdateAssignedLicense(this.Reference, entity, licenseKey, entityDisplayName);
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

    public async System.Threading.Tasks.Task<LicenseDiagnostics> GetPropertyDiagnostics()
    {
        return await this.GetProperty<LicenseDiagnostics>("diagnostics");
    }

    public async System.Threading.Tasks.Task<LicenseManagerEvaluationInfo> GetPropertyEvaluation()
    {
        return await this.GetProperty<LicenseManagerEvaluationInfo>("evaluation");
    }

    public async System.Threading.Tasks.Task<LicenseFeatureInfo[]> GetPropertyFeatureInfo()
    {
        return await this.GetProperty<LicenseFeatureInfo[]>("featureInfo");
    }

    public async System.Threading.Tasks.Task<LicenseAssignmentManager> GetPropertyLicenseAssignmentManager()
    {
        var licenseAssignmentManager = await this.GetProperty<ManagedObjectReference>("licenseAssignmentManager");
        return ManagedObject.Create<LicenseAssignmentManager>(licenseAssignmentManager, this.Session);
    }

    public async System.Threading.Tasks.Task<string> GetPropertyLicensedEdition()
    {
        return await this.GetProperty<string>("licensedEdition");
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo[]> GetPropertyLicenses()
    {
        return await this.GetProperty<LicenseManagerLicenseInfo[]>("licenses");
    }

    public async System.Threading.Tasks.Task<LicenseSource> GetPropertySource()
    {
        return await this.GetProperty<LicenseSource>("source");
    }

    public async System.Threading.Tasks.Task<bool> GetPropertySourceAvailable()
    {
        return await this.GetProperty<bool>("sourceAvailable");
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo> AddLicense(string licenseKey, KeyValue[] labels)
    {
        return await this.Session.Client.AddLicense(this.Reference, licenseKey, labels);
    }

    public async System.Threading.Tasks.Task<bool> CheckLicenseFeature(HostSystem host, string featureKey)
    {
        return await this.Session.Client.CheckLicenseFeature(this.Reference, host?.Reference, featureKey);
    }

    public async System.Threading.Tasks.Task ConfigureLicenseSource(HostSystem host, LicenseSource licenseSource)
    {
        await this.Session.Client.ConfigureLicenseSource(this.Reference, host?.Reference, licenseSource);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo> DecodeLicense(string licenseKey)
    {
        return await this.Session.Client.DecodeLicense(this.Reference, licenseKey);
    }

    public async System.Threading.Tasks.Task<bool> DisableFeature(HostSystem host, string featureKey)
    {
        return await this.Session.Client.DisableFeature(this.Reference, host?.Reference, featureKey);
    }

    public async System.Threading.Tasks.Task<bool> EnableFeature(HostSystem host, string featureKey)
    {
        return await this.Session.Client.EnableFeature(this.Reference, host?.Reference, featureKey);
    }

    public async System.Threading.Tasks.Task<LicenseAvailabilityInfo[]> QueryLicenseSourceAvailability(HostSystem host)
    {
        return await this.Session.Client.QueryLicenseSourceAvailability(this.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task<LicenseUsageInfo> QueryLicenseUsage(HostSystem host)
    {
        return await this.Session.Client.QueryLicenseUsage(this.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task<LicenseFeatureInfo[]> QuerySupportedFeatures(HostSystem host)
    {
        return await this.Session.Client.QuerySupportedFeatures(this.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task RemoveLicense(string licenseKey)
    {
        await this.Session.Client.RemoveLicense(this.Reference, licenseKey);
    }

    public async System.Threading.Tasks.Task RemoveLicenseLabel(string licenseKey, string labelKey)
    {
        await this.Session.Client.RemoveLicenseLabel(this.Reference, licenseKey, labelKey);
    }

    public async System.Threading.Tasks.Task SetLicenseEdition(HostSystem host, string featureKey)
    {
        await this.Session.Client.SetLicenseEdition(this.Reference, host?.Reference, featureKey);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo> UpdateLicense(string licenseKey, KeyValue[] labels)
    {
        return await this.Session.Client.UpdateLicense(this.Reference, licenseKey, labels);
    }

    public async System.Threading.Tasks.Task UpdateLicenseLabel(string licenseKey, string labelKey, string labelValue)
    {
        await this.Session.Client.UpdateLicenseLabel(this.Reference, licenseKey, labelKey, labelValue);
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

    public async System.Threading.Tasks.Task<ManagedObject[]> ModifyListView(ManagedObject[] add, ManagedObject[] remove)
    {
        var res = await this.Session.Client.ModifyListView(this.Reference, add?.Select(m => m.Reference).ToArray(), remove?.Select(m => m.Reference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedObject[]> ResetListView(ManagedObject[] obj)
    {
        var res = await this.Session.Client.ResetListView(this.Reference, obj?.Select(m => m.Reference).ToArray());
        return res?.Select(r => ManagedObject.Create<ManagedObject>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task ResetListViewFromView(View view)
    {
        await this.Session.Client.ResetListViewFromView(this.Reference, view?.Reference);
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

    public async System.Threading.Tasks.Task<LocalizationManagerMessageCatalog[]> GetPropertyCatalog()
    {
        return await this.GetProperty<LocalizationManagerMessageCatalog[]>("catalog");
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
        return await this.GetProperty<bool>("alarmActionsEnabled");
    }

    public async System.Threading.Tasks.Task<Event[]> GetPropertyConfigIssue()
    {
        return await this.GetProperty<Event[]>("configIssue");
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyConfigStatus()
    {
        return await this.GetProperty<ManagedEntityStatus>("configStatus");
    }

    public async System.Threading.Tasks.Task<CustomFieldValue[]> GetPropertyCustomValue()
    {
        return await this.GetProperty<CustomFieldValue[]>("customValue");
    }

    public async System.Threading.Tasks.Task<AlarmState[]> GetPropertyDeclaredAlarmState()
    {
        return await this.GetProperty<AlarmState[]>("declaredAlarmState");
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertyDisabledMethod()
    {
        return await this.GetProperty<string[]>("disabledMethod");
    }

    public async System.Threading.Tasks.Task<int[]> GetPropertyEffectiveRole()
    {
        return await this.GetProperty<int[]>("effectiveRole");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        return await this.GetProperty<string>("name");
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyOverallStatus()
    {
        return await this.GetProperty<ManagedEntityStatus>("overallStatus");
    }

    public async System.Threading.Tasks.Task<ManagedEntity> GetPropertyParent()
    {
        var parent = await this.GetProperty<ManagedObjectReference>("parent");
        return ManagedObject.Create<ManagedEntity>(parent, this.Session);
    }

    public async System.Threading.Tasks.Task<Permission[]> GetPropertyPermission()
    {
        return await this.GetProperty<Permission[]>("permission");
    }

    public async System.Threading.Tasks.Task<Task[]> GetPropertyRecentTask()
    {
        var recentTask = await this.GetProperty<ManagedObjectReference[]>("recentTask");
        return recentTask
            .Select(r => ManagedObject.Create<Task>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Tag[]> GetPropertyTag()
    {
        return await this.GetProperty<Tag[]>("tag");
    }

    public async System.Threading.Tasks.Task<AlarmState[]> GetPropertyTriggeredAlarmState()
    {
        return await this.GetProperty<AlarmState[]>("triggeredAlarmState");
    }

    public async System.Threading.Tasks.Task<Task> Destroy_Task()
    {
        var res = await this.Session.Client.Destroy_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task Reload()
    {
        await this.Session.Client.Reload(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> Rename_Task(string newName)
    {
        var res = await this.Session.Client.Rename_Task(this.Reference, newName);
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

    public async System.Threading.Tasks.Task<ManagedObject[]> GetPropertyView()
    {
        var view = await this.GetProperty<ManagedObjectReference[]>("view");
        return view
            .Select(r => ManagedObject.Create<ManagedObject>(r, this.Session))
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

    public async System.Threading.Tasks.Task<HostSystem[]> GetPropertyHost()
    {
        var host = await this.GetProperty<ManagedObjectReference[]>("host");
        return host
            .Select(r => ManagedObject.Create<HostSystem>(r, this.Session))
            .ToArray();
    }

    public new async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        return await this.GetProperty<string>("name");
    }

    public async System.Threading.Tasks.Task<NetworkSummary> GetPropertySummary()
    {
        return await this.GetProperty<NetworkSummary>("summary");
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task DestroyNetwork()
    {
        await this.Session.Client.DestroyNetwork(this.Reference);
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

    public async System.Threading.Tasks.Task<OpaqueNetworkCapability> GetPropertyCapability()
    {
        return await this.GetProperty<OpaqueNetworkCapability>("capability");
    }

    public async System.Threading.Tasks.Task<OptionValue[]> GetPropertyExtraConfig()
    {
        return await this.GetProperty<OptionValue[]>("extraConfig");
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

    public async System.Threading.Tasks.Task<OptionValue[]> GetPropertySetting()
    {
        return await this.GetProperty<OptionValue[]>("setting");
    }

    public async System.Threading.Tasks.Task<OptionDef[]> GetPropertySupportedOption()
    {
        return await this.GetProperty<OptionDef[]>("supportedOption");
    }

    public async System.Threading.Tasks.Task<OptionValue[]> QueryOptions(string name)
    {
        return await this.Session.Client.QueryOptions(this.Reference, name);
    }

    public async System.Threading.Tasks.Task UpdateOptions(OptionValue[] changedValue)
    {
        await this.Session.Client.UpdateOptions(this.Reference, changedValue);
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
        return await this.Session.Client.LookupVmOverheadMemory(this.Reference, vm?.Reference, host?.Reference);
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

    public async System.Threading.Tasks.Task<OvfOptionInfo[]> GetPropertyOvfExportOption()
    {
        return await this.GetProperty<OvfOptionInfo[]>("ovfExportOption");
    }

    public async System.Threading.Tasks.Task<OvfOptionInfo[]> GetPropertyOvfImportOption()
    {
        return await this.GetProperty<OvfOptionInfo[]>("ovfImportOption");
    }

    public async System.Threading.Tasks.Task<OvfCreateDescriptorResult> CreateDescriptor(ManagedEntity obj, OvfCreateDescriptorParams cdp)
    {
        return await this.Session.Client.CreateDescriptor(this.Reference, obj?.Reference, cdp);
    }

    public async System.Threading.Tasks.Task<OvfCreateImportSpecResult> CreateImportSpec(string ovfDescriptor, ResourcePool resourcePool, Datastore datastore, OvfCreateImportSpecParams cisp)
    {
        return await this.Session.Client.CreateImportSpec(this.Reference, ovfDescriptor, resourcePool?.Reference, datastore?.Reference, cisp);
    }

    public async System.Threading.Tasks.Task<OvfParseDescriptorResult> ParseDescriptor(string ovfDescriptor, OvfParseDescriptorParams pdp)
    {
        return await this.Session.Client.ParseDescriptor(this.Reference, ovfDescriptor, pdp);
    }

    public async System.Threading.Tasks.Task<OvfValidateHostResult> ValidateHost(string ovfDescriptor, HostSystem host, OvfValidateHostParams vhp)
    {
        return await this.Session.Client.ValidateHost(this.Reference, ovfDescriptor, host?.Reference, vhp);
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
        return await this.GetProperty<PerformanceDescription>("description");
    }

    public async System.Threading.Tasks.Task<PerfInterval[]> GetPropertyHistoricalInterval()
    {
        return await this.GetProperty<PerfInterval[]>("historicalInterval");
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]> GetPropertyPerfCounter()
    {
        return await this.GetProperty<PerfCounterInfo[]>("perfCounter");
    }

    public async System.Threading.Tasks.Task CreatePerfInterval(PerfInterval intervalId)
    {
        await this.Session.Client.CreatePerfInterval(this.Reference, intervalId);
    }

    public async System.Threading.Tasks.Task<PerfMetricId[]> QueryAvailablePerfMetric(ManagedObject entity, DateTime? beginTime, DateTime? endTime, int? intervalId)
    {
        return await this.Session.Client.QueryAvailablePerfMetric(this.Reference, entity?.Reference, beginTime ?? default, beginTime.HasValue, endTime ?? default, endTime.HasValue, intervalId ?? default, intervalId.HasValue);
    }

    public async System.Threading.Tasks.Task<PerfEntityMetricBase[]> QueryPerf(PerfQuerySpec[] querySpec)
    {
        return await this.Session.Client.QueryPerf(this.Reference, querySpec);
    }

    public async System.Threading.Tasks.Task<PerfCompositeMetric> QueryPerfComposite(PerfQuerySpec querySpec)
    {
        return await this.Session.Client.QueryPerfComposite(this.Reference, querySpec);
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]> QueryPerfCounter(int[] counterId)
    {
        return await this.Session.Client.QueryPerfCounter(this.Reference, counterId);
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]> QueryPerfCounterByLevel(int level)
    {
        return await this.Session.Client.QueryPerfCounterByLevel(this.Reference, level);
    }

    public async System.Threading.Tasks.Task<PerfProviderSummary> QueryPerfProviderSummary(ManagedObject entity)
    {
        return await this.Session.Client.QueryPerfProviderSummary(this.Reference, entity?.Reference);
    }

    public async System.Threading.Tasks.Task RemovePerfInterval(int samplePeriod)
    {
        await this.Session.Client.RemovePerfInterval(this.Reference, samplePeriod);
    }

    public async System.Threading.Tasks.Task ResetCounterLevelMapping(int[] counters)
    {
        await this.Session.Client.ResetCounterLevelMapping(this.Reference, counters);
    }

    public async System.Threading.Tasks.Task UpdateCounterLevelMapping(PerformanceManagerCounterLevelMapping[] counterLevelMap)
    {
        await this.Session.Client.UpdateCounterLevelMapping(this.Reference, counterLevelMap);
    }

    public async System.Threading.Tasks.Task UpdatePerfInterval(PerfInterval interval)
    {
        await this.Session.Client.UpdatePerfInterval(this.Reference, interval);
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
        return await this.GetProperty<string>("complianceStatus");
    }

    public async System.Threading.Tasks.Task<ProfileConfigInfo> GetPropertyConfig()
    {
        return await this.GetProperty<ProfileConfigInfo>("config");
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyCreatedTime()
    {
        return await this.GetProperty<DateTime>("createdTime");
    }

    public async System.Threading.Tasks.Task<ProfileDescription> GetPropertyDescription()
    {
        return await this.GetProperty<ProfileDescription>("description");
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> GetPropertyEntity()
    {
        var entity = await this.GetProperty<ManagedObjectReference[]>("entity");
        return entity
            .Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyModifiedTime()
    {
        return await this.GetProperty<DateTime>("modifiedTime");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyName()
    {
        return await this.GetProperty<string>("name");
    }

    public async System.Threading.Tasks.Task AssociateProfile(ManagedEntity[] entity)
    {
        await this.Session.Client.AssociateProfile(this.Reference, entity?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<Task> CheckProfileCompliance_Task(ManagedEntity[] entity)
    {
        var res = await this.Session.Client.CheckProfileCompliance_Task(this.Reference, entity?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyProfile()
    {
        await this.Session.Client.DestroyProfile(this.Reference);
    }

    public async System.Threading.Tasks.Task DissociateProfile(ManagedEntity[] entity)
    {
        await this.Session.Client.DissociateProfile(this.Reference, entity?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<string> ExportProfile()
    {
        return await this.Session.Client.ExportProfile(this.Reference);
    }

    public async System.Threading.Tasks.Task<ProfileDescription> RetrieveDescription()
    {
        return await this.Session.Client.RetrieveDescription(this.Reference);
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

    public async System.Threading.Tasks.Task<Task> CheckCompliance_Task(Profile[] profile, ManagedEntity[] entity)
    {
        var res = await this.Session.Client.CheckCompliance_Task(this.Reference, profile?.Select(m => m.Reference).ToArray(), entity?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ClearComplianceStatus(Profile[] profile, ManagedEntity[] entity)
    {
        await this.Session.Client.ClearComplianceStatus(this.Reference, profile?.Select(m => m.Reference).ToArray(), entity?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<ComplianceResult[]> QueryComplianceStatus(Profile[] profile, ManagedEntity[] entity)
    {
        return await this.Session.Client.QueryComplianceStatus(this.Reference, profile?.Select(m => m.Reference).ToArray(), entity?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<ProfileExpressionMetadata[]> QueryExpressionMetadata(string[] expressionName, Profile profile)
    {
        return await this.Session.Client.QueryExpressionMetadata(this.Reference, expressionName, profile?.Reference);
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

    public async System.Threading.Tasks.Task<Profile[]> GetPropertyProfile()
    {
        var profile = await this.GetProperty<ManagedObjectReference[]>("profile");
        return profile
            .Select(r => ManagedObject.Create<Profile>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Profile> CreateProfile(ProfileCreateSpec createSpec)
    {
        var res = await this.Session.Client.CreateProfile(this.Reference, createSpec);
        return ManagedObject.Create<Profile>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Profile[]> FindAssociatedProfile(ManagedEntity entity)
    {
        var res = await this.Session.Client.FindAssociatedProfile(this.Reference, entity?.Reference);
        return res?.Select(r => ManagedObject.Create<Profile>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<ProfilePolicyMetadata[]> QueryPolicyMetadata(string[] policyName, Profile profile)
    {
        return await this.Session.Client.QueryPolicyMetadata(this.Reference, policyName, profile?.Reference);
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

    public async System.Threading.Tasks.Task<PropertyFilter[]> GetPropertyFilter()
    {
        var filter = await this.GetProperty<ManagedObjectReference[]>("filter");
        return filter
            .Select(r => ManagedObject.Create<PropertyFilter>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task CancelRetrievePropertiesEx(string token)
    {
        await this.Session.Client.CancelRetrievePropertiesEx(this.Reference, token);
    }

    public async System.Threading.Tasks.Task CancelWaitForUpdates()
    {
        await this.Session.Client.CancelWaitForUpdates(this.Reference);
    }

    public async System.Threading.Tasks.Task<UpdateSet> CheckForUpdates(string version)
    {
        return await this.Session.Client.CheckForUpdates(this.Reference, version);
    }

    public async System.Threading.Tasks.Task<RetrieveResult> ContinueRetrievePropertiesEx(string token)
    {
        return await this.Session.Client.ContinueRetrievePropertiesEx(this.Reference, token);
    }

    public async System.Threading.Tasks.Task<PropertyFilter> CreateFilter(PropertyFilterSpec spec, bool partialUpdates)
    {
        var res = await this.Session.Client.CreateFilter(this.Reference, spec, partialUpdates);
        return ManagedObject.Create<PropertyFilter>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<PropertyCollector> CreatePropertyCollector()
    {
        var res = await this.Session.Client.CreatePropertyCollector(this.Reference);
        return ManagedObject.Create<PropertyCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyPropertyCollector()
    {
        await this.Session.Client.DestroyPropertyCollector(this.Reference);
    }

    public async System.Threading.Tasks.Task<ObjectContent[]> RetrieveProperties(PropertyFilterSpec[] specSet)
    {
        return await this.Session.Client.RetrieveProperties(this.Reference, specSet);
    }

    public async System.Threading.Tasks.Task<RetrieveResult> RetrievePropertiesEx(PropertyFilterSpec[] specSet, RetrieveOptions options)
    {
        return await this.Session.Client.RetrievePropertiesEx(this.Reference, specSet, options);
    }

    public async System.Threading.Tasks.Task<UpdateSet> WaitForUpdates(string version)
    {
        return await this.Session.Client.WaitForUpdates(this.Reference, version);
    }

    public async System.Threading.Tasks.Task<UpdateSet> WaitForUpdatesEx(string version, WaitOptions options)
    {
        return await this.Session.Client.WaitForUpdatesEx(this.Reference, version, options);
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
        return await this.GetProperty<bool>("partialUpdates");
    }

    public async System.Threading.Tasks.Task<PropertyFilterSpec> GetPropertySpec()
    {
        return await this.GetProperty<PropertyFilterSpec>("spec");
    }

    public async System.Threading.Tasks.Task DestroyPropertyFilter()
    {
        await this.Session.Client.DestroyPropertyFilter(this.Reference);
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

    public async System.Threading.Tasks.Task<DatabaseSizeEstimate> EstimateDatabaseSize(DatabaseSizeParam dbSizeParam)
    {
        return await this.Session.Client.EstimateDatabaseSize(this.Reference, dbSizeParam);
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

    public async System.Threading.Tasks.Task<ResourceConfigSpec[]> GetPropertyChildConfiguration()
    {
        return await this.GetProperty<ResourceConfigSpec[]>("childConfiguration");
    }

    public async System.Threading.Tasks.Task<ResourceConfigSpec> GetPropertyConfig()
    {
        return await this.GetProperty<ResourceConfigSpec>("config");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyNamespace()
    {
        return await this.GetProperty<string>("namespace");
    }

    public async System.Threading.Tasks.Task<ComputeResource> GetPropertyOwner()
    {
        var owner = await this.GetProperty<ManagedObjectReference>("owner");
        return ManagedObject.Create<ComputeResource>(owner, this.Session);
    }

    public async System.Threading.Tasks.Task<ResourcePool[]> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference[]>("resourcePool");
        return resourcePool
            .Select(r => ManagedObject.Create<ResourcePool>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ResourcePoolRuntimeInfo> GetPropertyRuntime()
    {
        return await this.GetProperty<ResourcePoolRuntimeInfo>("runtime");
    }

    public async System.Threading.Tasks.Task<ResourcePoolSummary> GetPropertySummary()
    {
        return await this.GetProperty<ResourcePoolSummary>("summary");
    }

    public async System.Threading.Tasks.Task<VirtualMachine[]> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference[]>("vm");
        return vm
            .Select(r => ManagedObject.Create<VirtualMachine>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Task> CreateChildVM_Task(VirtualMachineConfigSpec config, HostSystem host)
    {
        var res = await this.Session.Client.CreateChildVM_Task(this.Reference, config, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ResourcePool> CreateResourcePool(string name, ResourceConfigSpec spec)
    {
        var res = await this.Session.Client.CreateResourcePool(this.Reference, name, spec);
        return ManagedObject.Create<ResourcePool>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualApp> CreateVApp(string name, ResourceConfigSpec resSpec, VAppConfigSpec configSpec, Folder vmFolder)
    {
        var res = await this.Session.Client.CreateVApp(this.Reference, name, resSpec, configSpec, vmFolder?.Reference);
        return ManagedObject.Create<VirtualApp>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DestroyChildren()
    {
        await this.Session.Client.DestroyChildren(this.Reference);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease> ImportVApp(ImportSpec spec, Folder folder, HostSystem host)
    {
        var res = await this.Session.Client.ImportVApp(this.Reference, spec, folder?.Reference, host?.Reference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MoveIntoResourcePool(ManagedEntity[] list)
    {
        await this.Session.Client.MoveIntoResourcePool(this.Reference, list?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<ResourceConfigOption> QueryResourceConfigOption()
    {
        return await this.Session.Client.QueryResourceConfigOption(this.Reference);
    }

    public async System.Threading.Tasks.Task RefreshRuntime()
    {
        await this.Session.Client.RefreshRuntime(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> RegisterChildVM_Task(string path, string name, HostSystem host)
    {
        var res = await this.Session.Client.RegisterChildVM_Task(this.Reference, path, name, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateChildResourceConfiguration(ResourceConfigSpec[] spec)
    {
        await this.Session.Client.UpdateChildResourceConfiguration(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task UpdateConfig(string name, ResourceConfigSpec config)
    {
        await this.Session.Client.UpdateConfig(this.Reference, name, config);
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
        return await this.GetProperty<ScheduledTaskInfo>("info");
    }

    public async System.Threading.Tasks.Task ReconfigureScheduledTask(ScheduledTaskSpec spec)
    {
        await this.Session.Client.ReconfigureScheduledTask(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task RemoveScheduledTask()
    {
        await this.Session.Client.RemoveScheduledTask(this.Reference);
    }

    public async System.Threading.Tasks.Task RunScheduledTask()
    {
        await this.Session.Client.RunScheduledTask(this.Reference);
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
        return await this.GetProperty<ScheduledTaskDescription>("description");
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]> GetPropertyScheduledTask()
    {
        var scheduledTask = await this.GetProperty<ManagedObjectReference[]>("scheduledTask");
        return scheduledTask
            .Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ScheduledTask> CreateObjectScheduledTask(ManagedObject obj, ScheduledTaskSpec spec)
    {
        var res = await this.Session.Client.CreateObjectScheduledTask(this.Reference, obj?.Reference, spec);
        return ManagedObject.Create<ScheduledTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ScheduledTask> CreateScheduledTask(ManagedEntity entity, ScheduledTaskSpec spec)
    {
        var res = await this.Session.Client.CreateScheduledTask(this.Reference, entity?.Reference, spec);
        return ManagedObject.Create<ScheduledTask>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]> RetrieveEntityScheduledTask(ManagedEntity entity)
    {
        var res = await this.Session.Client.RetrieveEntityScheduledTask(this.Reference, entity?.Reference);
        return res?.Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<ScheduledTask[]> RetrieveObjectScheduledTask(ManagedObject obj)
    {
        var res = await this.Session.Client.RetrieveObjectScheduledTask(this.Reference, obj?.Reference);
        return res?.Select(r => ManagedObject.Create<ScheduledTask>(r, this.Session)).ToArray();
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

    public async System.Threading.Tasks.Task<ManagedEntity[]> FindAllByDnsName(Datacenter datacenter, string dnsName, bool vmSearch)
    {
        var res = await this.Session.Client.FindAllByDnsName(this.Reference, datacenter?.Reference, dnsName, vmSearch);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> FindAllByIp(Datacenter datacenter, string ip, bool vmSearch)
    {
        var res = await this.Session.Client.FindAllByIp(this.Reference, datacenter?.Reference, ip, vmSearch);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> FindAllByUuid(Datacenter datacenter, string uuid, bool vmSearch, bool? instanceUuid)
    {
        var res = await this.Session.Client.FindAllByUuid(this.Reference, datacenter?.Reference, uuid, vmSearch, instanceUuid ?? default, instanceUuid.HasValue);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachine> FindByDatastorePath(Datacenter datacenter, string path)
    {
        var res = await this.Session.Client.FindByDatastorePath(this.Reference, datacenter?.Reference, path);
        return ManagedObject.Create<VirtualMachine>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity> FindByDnsName(Datacenter datacenter, string dnsName, bool vmSearch)
    {
        var res = await this.Session.Client.FindByDnsName(this.Reference, datacenter?.Reference, dnsName, vmSearch);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity> FindByInventoryPath(string inventoryPath)
    {
        var res = await this.Session.Client.FindByInventoryPath(this.Reference, inventoryPath);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity> FindByIp(Datacenter datacenter, string ip, bool vmSearch)
    {
        var res = await this.Session.Client.FindByIp(this.Reference, datacenter?.Reference, ip, vmSearch);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity> FindByUuid(Datacenter datacenter, string uuid, bool vmSearch, bool? instanceUuid)
    {
        var res = await this.Session.Client.FindByUuid(this.Reference, datacenter?.Reference, uuid, vmSearch, instanceUuid ?? default, instanceUuid.HasValue);
        return ManagedObject.Create<ManagedEntity>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity> FindChild(ManagedEntity entity, string name)
    {
        var res = await this.Session.Client.FindChild(this.Reference, entity?.Reference, name);
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
        return await this.GetProperty<Capability>("capability");
    }

    public async System.Threading.Tasks.Task<ServiceContent> GetPropertyContent()
    {
        return await this.GetProperty<ServiceContent>("content");
    }

    public async System.Threading.Tasks.Task<DateTime> GetPropertyServerClock()
    {
        return await this.GetProperty<DateTime>("serverClock");
    }

    public async System.Threading.Tasks.Task<DateTime> CurrentTime()
    {
        return await this.Session.Client.CurrentTime(this.Reference);
    }

    public async System.Threading.Tasks.Task<HostVMotionCompatibility[]> QueryVMotionCompatibility(VirtualMachine vm, HostSystem[] host, string[] compatibility)
    {
        return await this.Session.Client.QueryVMotionCompatibility(this.Reference, vm?.Reference, host?.Select(m => m.Reference).ToArray(), compatibility);
    }

    public async System.Threading.Tasks.Task<ProductComponentInfo[]> RetrieveProductComponents()
    {
        return await this.Session.Client.RetrieveProductComponents(this.Reference);
    }

    public async System.Threading.Tasks.Task<ServiceContent> RetrieveServiceContent()
    {
        return await this.Session.Client.RetrieveServiceContent(this.Reference);
    }

    public async System.Threading.Tasks.Task<Event[]> ValidateMigration(VirtualMachine[] vm, VirtualMachinePowerState? state, string[] testType, ResourcePool pool, HostSystem host)
    {
        return await this.Session.Client.ValidateMigration(this.Reference, vm?.Select(m => m.Reference).ToArray(), state ?? default, state.HasValue, testType, pool?.Reference, host?.Reference);
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

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo[]> GetPropertyService()
    {
        return await this.GetProperty<ServiceManagerServiceInfo[]>("service");
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo[]> QueryServiceList(string serviceName, string[] location)
    {
        return await this.Session.Client.QueryServiceList(this.Reference, serviceName, location);
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

    public async System.Threading.Tasks.Task<UserSession> GetPropertyCurrentSession()
    {
        return await this.GetProperty<UserSession>("currentSession");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyDefaultLocale()
    {
        return await this.GetProperty<string>("defaultLocale");
    }

    public async System.Threading.Tasks.Task<string> GetPropertyMessage()
    {
        return await this.GetProperty<string>("message");
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertyMessageLocaleList()
    {
        return await this.GetProperty<string[]>("messageLocaleList");
    }

    public async System.Threading.Tasks.Task<UserSession[]> GetPropertySessionList()
    {
        return await this.GetProperty<UserSession[]>("sessionList");
    }

    public async System.Threading.Tasks.Task<string[]> GetPropertySupportedLocaleList()
    {
        return await this.GetProperty<string[]>("supportedLocaleList");
    }

    public async System.Threading.Tasks.Task<string> AcquireCloneTicket()
    {
        return await this.Session.Client.AcquireCloneTicket(this.Reference);
    }

    public async System.Threading.Tasks.Task<SessionManagerGenericServiceTicket> AcquireGenericServiceTicket(SessionManagerServiceRequestSpec spec)
    {
        return await this.Session.Client.AcquireGenericServiceTicket(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task<SessionManagerLocalTicket> AcquireLocalTicket(string userName)
    {
        return await this.Session.Client.AcquireLocalTicket(this.Reference, userName);
    }

    public async System.Threading.Tasks.Task<UserSession> CloneSession(string cloneTicket)
    {
        return await this.Session.Client.CloneSession(this.Reference, cloneTicket);
    }

    public async System.Threading.Tasks.Task<UserSession> ImpersonateUser(string userName, string locale)
    {
        return await this.Session.Client.ImpersonateUser(this.Reference, userName, locale);
    }

    public async System.Threading.Tasks.Task<UserSession> Login(string userName, string password, string locale)
    {
        return await this.Session.Client.Login(this.Reference, userName, password, locale);
    }

    public async System.Threading.Tasks.Task<UserSession> LoginBySSPI(string base64Token, string locale)
    {
        return await this.Session.Client.LoginBySSPI(this.Reference, base64Token, locale);
    }

    public async System.Threading.Tasks.Task<UserSession> LoginByToken(string locale)
    {
        return await this.Session.Client.LoginByToken(this.Reference, locale);
    }

    public async System.Threading.Tasks.Task<UserSession> LoginExtensionByCertificate(string extensionKey, string locale)
    {
        return await this.Session.Client.LoginExtensionByCertificate(this.Reference, extensionKey, locale);
    }

    public async System.Threading.Tasks.Task<UserSession> LoginExtensionBySubjectName(string extensionKey, string locale)
    {
        return await this.Session.Client.LoginExtensionBySubjectName(this.Reference, extensionKey, locale);
    }

    public async System.Threading.Tasks.Task Logout()
    {
        await this.Session.Client.Logout(this.Reference);
    }

    public async System.Threading.Tasks.Task<bool> SessionIsActive(string sessionID, string userName)
    {
        return await this.Session.Client.SessionIsActive(this.Reference, sessionID, userName);
    }

    public async System.Threading.Tasks.Task SetLocale(string locale)
    {
        await this.Session.Client.SetLocale(this.Reference, locale);
    }

    public async System.Threading.Tasks.Task TerminateSession(string[] sessionId)
    {
        await this.Session.Client.TerminateSession(this.Reference, sessionId);
    }

    public async System.Threading.Tasks.Task UpdateServiceMessage(string message)
    {
        await this.Session.Client.UpdateServiceMessage(this.Reference, message);
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
        return await this.GetProperty<string>("encodingType");
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo> GetPropertyEntity()
    {
        return await this.GetProperty<ServiceManagerServiceInfo>("entity");
    }

    public async System.Threading.Tasks.Task<string> ExecuteSimpleCommand(string[] arguments)
    {
        return await this.Session.Client.ExecuteSimpleCommand(this.Reference, arguments);
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

    public async System.Threading.Tasks.Task<SiteInfo> GetSiteInfo()
    {
        return await this.Session.Client.GetSiteInfo(this.Reference);
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

    public async System.Threading.Tasks.Task<PodStorageDrsEntry> GetPropertyPodStorageDrsEntry()
    {
        return await this.GetProperty<PodStorageDrsEntry>("podStorageDrsEntry");
    }

    public async System.Threading.Tasks.Task<StoragePodSummary> GetPropertySummary()
    {
        return await this.GetProperty<StoragePodSummary>("summary");
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

    public async System.Threading.Tasks.Task<HostSystem[]> QueryHostsWithAttachedLun(string lunUuid)
    {
        var res = await this.Session.Client.QueryHostsWithAttachedLun(this.Reference, lunUuid);
        return res?.Select(r => ManagedObject.Create<HostSystem>(r, this.Session)).ToArray();
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

    public async System.Threading.Tasks.Task<Task> ApplyStorageDrsRecommendation_Task(string[] key)
    {
        var res = await this.Session.Client.ApplyStorageDrsRecommendation_Task(this.Reference, key);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ApplyStorageDrsRecommendationToPod_Task(StoragePod pod, string key)
    {
        var res = await this.Session.Client.ApplyStorageDrsRecommendationToPod_Task(this.Reference, pod?.Reference, key);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CancelStorageDrsRecommendation(string[] key)
    {
        await this.Session.Client.CancelStorageDrsRecommendation(this.Reference, key);
    }

    public async System.Threading.Tasks.Task<Task> ConfigureDatastoreIORM_Task(Datastore datastore, StorageIORMConfigSpec spec)
    {
        var res = await this.Session.Client.ConfigureDatastoreIORM_Task(this.Reference, datastore?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ConfigureStorageDrsForPod_Task(StoragePod pod, StorageDrsConfigSpec spec, bool modify)
    {
        var res = await this.Session.Client.ConfigureStorageDrsForPod_Task(this.Reference, pod?.Reference, spec, modify);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<StoragePerformanceSummary[]> QueryDatastorePerformanceSummary(Datastore datastore)
    {
        return await this.Session.Client.QueryDatastorePerformanceSummary(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<StorageIORMConfigOption> QueryIORMConfigOption(HostSystem host)
    {
        return await this.Session.Client.QueryIORMConfigOption(this.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult> RecommendDatastores(StoragePlacementSpec storageSpec)
    {
        return await this.Session.Client.RecommendDatastores(this.Reference, storageSpec);
    }

    public async System.Threading.Tasks.Task RefreshStorageDrsRecommendation(StoragePod pod)
    {
        await this.Session.Client.RefreshStorageDrsRecommendation(this.Reference, pod?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> RefreshStorageDrsRecommendationsForPod_Task(StoragePod pod)
    {
        var res = await this.Session.Client.RefreshStorageDrsRecommendationsForPod_Task(this.Reference, pod?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault> ValidateStoragePodConfig(StoragePod pod, StorageDrsConfigSpec spec)
    {
        return await this.Session.Client.ValidateStoragePodConfig(this.Reference, pod?.Reference, spec);
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
        return await this.GetProperty<TaskInfo>("info");
    }

    public async System.Threading.Tasks.Task CancelTask()
    {
        await this.Session.Client.CancelTask(this.Reference);
    }

    public async System.Threading.Tasks.Task SetTaskDescription(LocalizableMessage description)
    {
        await this.Session.Client.SetTaskDescription(this.Reference, description);
    }

    public async System.Threading.Tasks.Task SetTaskState(TaskInfoState state, object result, LocalizedMethodFault fault)
    {
        await this.Session.Client.SetTaskState(this.Reference, state, result, fault);
    }

    public async System.Threading.Tasks.Task UpdateProgress(int percentDone)
    {
        await this.Session.Client.UpdateProgress(this.Reference, percentDone);
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

    public async System.Threading.Tasks.Task<TaskInfo[]> GetPropertyLatestPage()
    {
        return await this.GetProperty<TaskInfo[]>("latestPage");
    }

    public async System.Threading.Tasks.Task<TaskInfo[]> ReadNextTasks(int maxCount)
    {
        return await this.Session.Client.ReadNextTasks(this.Reference, maxCount);
    }

    public async System.Threading.Tasks.Task<TaskInfo[]> ReadPreviousTasks(int maxCount)
    {
        return await this.Session.Client.ReadPreviousTasks(this.Reference, maxCount);
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
        return await this.GetProperty<TaskDescription>("description");
    }

    public async System.Threading.Tasks.Task<int> GetPropertyMaxCollector()
    {
        return await this.GetProperty<int>("maxCollector");
    }

    public async System.Threading.Tasks.Task<Task[]> GetPropertyRecentTask()
    {
        var recentTask = await this.GetProperty<ManagedObjectReference[]>("recentTask");
        return recentTask
            .Select(r => ManagedObject.Create<Task>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<TaskHistoryCollector> CreateCollectorForTasks(TaskFilterSpec filter)
    {
        var res = await this.Session.Client.CreateCollectorForTasks(this.Reference, filter);
        return ManagedObject.Create<TaskHistoryCollector>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<TaskInfo> CreateTask(ManagedObject obj, string taskTypeId, string initiatedBy, bool cancelable, string parentTaskKey, string activationId)
    {
        return await this.Session.Client.CreateTask(this.Reference, obj?.Reference, taskTypeId, initiatedBy, cancelable, parentTaskKey, activationId);
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

    public async System.Threading.Tasks.Task MarkServiceProviderEntities(ManagedEntity[] entity)
    {
        await this.Session.Client.MarkServiceProviderEntities(this.Reference, entity?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task<ManagedEntity[]> RetrieveServiceProviderEntities()
    {
        var res = await this.Session.Client.RetrieveServiceProviderEntities(this.Reference);
        return res?.Select(r => ManagedObject.Create<ManagedEntity>(r, this.Session)).ToArray();
    }

    public async System.Threading.Tasks.Task UnmarkServiceProviderEntities(ManagedEntity[] entity)
    {
        await this.Session.Client.UnmarkServiceProviderEntities(this.Reference, entity?.Select(m => m.Reference).ToArray());
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

    public async System.Threading.Tasks.Task<string[]> GetPropertyDomainList()
    {
        return await this.GetProperty<string[]>("domainList");
    }

    public async System.Threading.Tasks.Task<UserSearchResult[]> RetrieveUserGroups(string domain, string searchStr, string belongsToGroup, string belongsToUser, bool exactMatch, bool findUsers, bool findGroups)
    {
        return await this.Session.Client.RetrieveUserGroups(this.Reference, domain, searchStr, belongsToGroup, belongsToUser, exactMatch, findUsers, findGroups);
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
        await this.Session.Client.AttachTagToVStorageObject(this.Reference, id, category, tag);
    }

    public async System.Threading.Tasks.Task ClearVStorageObjectControlFlags(ID id, Datastore datastore, string[] controlFlags)
    {
        await this.Session.Client.ClearVStorageObjectControlFlags(this.Reference, id, datastore?.Reference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task> CloneVStorageObject_Task(ID id, Datastore datastore, VslmCloneSpec spec)
    {
        var res = await this.Session.Client.CloneVStorageObject_Task(this.Reference, id, datastore?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateDisk_Task(VslmCreateSpec spec)
    {
        var res = await this.Session.Client.CreateDisk_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateDiskFromSnapshot_Task(ID id, Datastore datastore, ID snapshotId, string name, VirtualMachineProfileSpec[] profile, CryptoSpec crypto, string path)
    {
        var res = await this.Session.Client.CreateDiskFromSnapshot_Task(this.Reference, id, datastore?.Reference, snapshotId, name, profile, crypto, path);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeleteSnapshot_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.Client.DeleteSnapshot_Task(this.Reference, id, datastore?.Reference, snapshotId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeleteVStorageObject_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.Client.DeleteVStorageObject_Task(this.Reference, id, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeleteVStorageObjectEx_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.Client.DeleteVStorageObjectEx_Task(this.Reference, id, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DetachTagFromVStorageObject(ID id, string category, string tag)
    {
        await this.Session.Client.DetachTagFromVStorageObject(this.Reference, id, category, tag);
    }

    public async System.Threading.Tasks.Task<Task> ExtendDisk_Task(ID id, Datastore datastore, long newCapacityInMB)
    {
        var res = await this.Session.Client.ExtendDisk_Task(this.Reference, id, datastore?.Reference, newCapacityInMB);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> InflateDisk_Task(ID id, Datastore datastore)
    {
        var res = await this.Session.Client.InflateDisk_Task(this.Reference, id, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VslmTagEntry[]> ListTagsAttachedToVStorageObject(ID id)
    {
        return await this.Session.Client.ListTagsAttachedToVStorageObject(this.Reference, id);
    }

    public async System.Threading.Tasks.Task<ID[]> ListVStorageObject(Datastore datastore)
    {
        return await this.Session.Client.ListVStorageObject(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<ID[]> ListVStorageObjectsAttachedToTag(string category, string tag)
    {
        return await this.Session.Client.ListVStorageObjectsAttachedToTag(this.Reference, category, tag);
    }

    public async System.Threading.Tasks.Task<Task> ReconcileDatastoreInventory_Task(Datastore datastore)
    {
        var res = await this.Session.Client.ReconcileDatastoreInventory_Task(this.Reference, datastore?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VStorageObject> RegisterDisk(string path, string name)
    {
        return await this.Session.Client.RegisterDisk(this.Reference, path, name);
    }

    public async System.Threading.Tasks.Task<Task> RelocateVStorageObject_Task(ID id, Datastore datastore, VslmRelocateSpec spec)
    {
        var res = await this.Session.Client.RelocateVStorageObject_Task(this.Reference, id, datastore?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RenameVStorageObject(ID id, Datastore datastore, string name)
    {
        await this.Session.Client.RenameVStorageObject(this.Reference, id, datastore?.Reference, name);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotDetails> RetrieveSnapshotDetails(ID id, Datastore datastore, ID snapshotId)
    {
        return await this.Session.Client.RetrieveSnapshotDetails(this.Reference, id, datastore?.Reference, snapshotId);
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo> RetrieveSnapshotInfo(ID id, Datastore datastore)
    {
        return await this.Session.Client.RetrieveSnapshotInfo(this.Reference, id, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]> RetrieveVStorageInfrastructureObjectPolicy(Datastore datastore)
    {
        return await this.Session.Client.RetrieveVStorageInfrastructureObjectPolicy(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<VStorageObject> RetrieveVStorageObject(ID id, Datastore datastore)
    {
        return await this.Session.Client.RetrieveVStorageObject(this.Reference, id, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<VStorageObjectAssociations[]> RetrieveVStorageObjectAssociations(RetrieveVStorageObjSpec[] ids)
    {
        return await this.Session.Client.RetrieveVStorageObjectAssociations(this.Reference, ids);
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo> RetrieveVStorageObjectState(ID id, Datastore datastore)
    {
        return await this.Session.Client.RetrieveVStorageObjectState(this.Reference, id, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> RevertVStorageObject_Task(ID id, Datastore datastore, ID snapshotId)
    {
        var res = await this.Session.Client.RevertVStorageObject_Task(this.Reference, id, datastore?.Reference, snapshotId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ScheduleReconcileDatastoreInventory(Datastore datastore)
    {
        await this.Session.Client.ScheduleReconcileDatastoreInventory(this.Reference, datastore?.Reference);
    }

    public async System.Threading.Tasks.Task SetVStorageObjectControlFlags(ID id, Datastore datastore, string[] controlFlags)
    {
        await this.Session.Client.SetVStorageObjectControlFlags(this.Reference, id, datastore?.Reference, controlFlags);
    }

    public async System.Threading.Tasks.Task<Task> UpdateVStorageInfrastructureObjectPolicy_Task(vslmInfrastructureObjectPolicySpec spec)
    {
        var res = await this.Session.Client.UpdateVStorageInfrastructureObjectPolicy_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UpdateVStorageObjectCrypto_Task(ID id, Datastore datastore, VirtualMachineProfileSpec[] profile, DiskCryptoSpec disksCrypto)
    {
        var res = await this.Session.Client.UpdateVStorageObjectCrypto_Task(this.Reference, id, datastore?.Reference, profile, disksCrypto);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UpdateVStorageObjectPolicy_Task(ID id, Datastore datastore, VirtualMachineProfileSpec[] profile)
    {
        var res = await this.Session.Client.UpdateVStorageObjectPolicy_Task(this.Reference, id, datastore?.Reference, profile);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> VCenterUpdateVStorageObjectMetadataEx_Task(ID id, Datastore datastore, KeyValue[] metadata, string[] deleteKeys)
    {
        var res = await this.Session.Client.VCenterUpdateVStorageObjectMetadataEx_Task(this.Reference, id, datastore?.Reference, metadata, deleteKeys);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> VStorageObjectCreateSnapshot_Task(ID id, Datastore datastore, string description)
    {
        var res = await this.Session.Client.VStorageObjectCreateSnapshot_Task(this.Reference, id, datastore?.Reference, description);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo> VstorageObjectVCenterQueryChangedDiskAreas(ID id, Datastore datastore, ID snapshotId, long startOffset, string changeId)
    {
        return await this.Session.Client.VstorageObjectVCenterQueryChangedDiskAreas(this.Reference, id, datastore?.Reference, snapshotId, startOffset, changeId);
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
        await this.Session.Client.DestroyView(this.Reference);
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

    public async System.Threading.Tasks.Task<View[]> GetPropertyViewList()
    {
        var viewList = await this.GetProperty<ManagedObjectReference[]>("viewList");
        return viewList
            .Select(r => ManagedObject.Create<View>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ContainerView> CreateContainerView(ManagedEntity container, string[] type, bool recursive)
    {
        var res = await this.Session.Client.CreateContainerView(this.Reference, container?.Reference, type, recursive);
        return ManagedObject.Create<ContainerView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<InventoryView> CreateInventoryView()
    {
        var res = await this.Session.Client.CreateInventoryView(this.Reference);
        return ManagedObject.Create<InventoryView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ListView> CreateListView(ManagedObject[] obj)
    {
        var res = await this.Session.Client.CreateListView(this.Reference, obj?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<ListView>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<ListView> CreateListViewFromView(View view)
    {
        var res = await this.Session.Client.CreateListViewFromView(this.Reference, view?.Reference);
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

    public async System.Threading.Tasks.Task<VirtualAppLinkInfo[]> GetPropertyChildLink()
    {
        return await this.GetProperty<VirtualAppLinkInfo[]>("childLink");
    }

    public async System.Threading.Tasks.Task<Datastore[]> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Network[]> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network
            .Select(r => ManagedObject.Create<Network>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<Folder> GetPropertyParentFolder()
    {
        var parentFolder = await this.GetProperty<ManagedObjectReference>("parentFolder");
        return ManagedObject.Create<Folder>(parentFolder, this.Session);
    }

    public async System.Threading.Tasks.Task<ManagedEntity> GetPropertyParentVApp()
    {
        var parentVApp = await this.GetProperty<ManagedObjectReference>("parentVApp");
        return ManagedObject.Create<ManagedEntity>(parentVApp, this.Session);
    }

    public async System.Threading.Tasks.Task<VAppConfigInfo> GetPropertyVAppConfig()
    {
        return await this.GetProperty<VAppConfigInfo>("vAppConfig");
    }

    public async System.Threading.Tasks.Task<Task> CloneVApp_Task(string name, ResourcePool target, VAppCloneSpec spec)
    {
        var res = await this.Session.Client.CloneVApp_Task(this.Reference, name, target?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease> ExportVApp()
    {
        var res = await this.Session.Client.ExportVApp(this.Reference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> PowerOffVApp_Task(bool force)
    {
        var res = await this.Session.Client.PowerOffVApp_Task(this.Reference, force);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> PowerOnVApp_Task()
    {
        var res = await this.Session.Client.PowerOnVApp_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> SuspendVApp_Task()
    {
        var res = await this.Session.Client.SuspendVApp_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UnregisterVApp_Task()
    {
        var res = await this.Session.Client.UnregisterVApp_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UpdateLinkedChildren(VirtualAppLinkInfo[] addChangeSet, ManagedEntity[] removeSet)
    {
        await this.Session.Client.UpdateLinkedChildren(this.Reference, addChangeSet, removeSet?.Select(m => m.Reference).ToArray());
    }

    public async System.Threading.Tasks.Task UpdateVAppConfig(VAppConfigSpec spec)
    {
        await this.Session.Client.UpdateVAppConfig(this.Reference, spec);
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

    public async System.Threading.Tasks.Task<Task> CopyVirtualDisk_Task(string sourceName, Datacenter sourceDatacenter, string destName, Datacenter destDatacenter, VirtualDiskSpec destSpec, bool? force)
    {
        var res = await this.Session.Client.CopyVirtualDisk_Task(this.Reference, sourceName, sourceDatacenter?.Reference, destName, destDatacenter?.Reference, destSpec, force ?? default, force.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateVirtualDisk_Task(string name, Datacenter datacenter, VirtualDiskSpec spec)
    {
        var res = await this.Session.Client.CreateVirtualDisk_Task(this.Reference, name, datacenter?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DefragmentVirtualDisk_Task(string name, Datacenter datacenter)
    {
        var res = await this.Session.Client.DefragmentVirtualDisk_Task(this.Reference, name, datacenter?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DeleteVirtualDisk_Task(string name, Datacenter datacenter)
    {
        var res = await this.Session.Client.DeleteVirtualDisk_Task(this.Reference, name, datacenter?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> EagerZeroVirtualDisk_Task(string name, Datacenter datacenter)
    {
        var res = await this.Session.Client.EagerZeroVirtualDisk_Task(this.Reference, name, datacenter?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ExtendVirtualDisk_Task(string name, Datacenter datacenter, long newCapacityKb, bool? eagerZero)
    {
        var res = await this.Session.Client.ExtendVirtualDisk_Task(this.Reference, name, datacenter?.Reference, newCapacityKb, eagerZero ?? default, eagerZero.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ImportUnmanagedSnapshot(string vdisk, Datacenter datacenter, string vvolId)
    {
        await this.Session.Client.ImportUnmanagedSnapshot(this.Reference, vdisk, datacenter?.Reference, vvolId);
    }

    public async System.Threading.Tasks.Task<Task> InflateVirtualDisk_Task(string name, Datacenter datacenter)
    {
        var res = await this.Session.Client.InflateVirtualDisk_Task(this.Reference, name, datacenter?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MoveVirtualDisk_Task(string sourceName, Datacenter sourceDatacenter, string destName, Datacenter destDatacenter, bool? force, VirtualMachineProfileSpec[] profile)
    {
        var res = await this.Session.Client.MoveVirtualDisk_Task(this.Reference, sourceName, sourceDatacenter?.Reference, destName, destDatacenter?.Reference, force ?? default, force.HasValue, profile);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int> QueryVirtualDiskFragmentation(string name, Datacenter datacenter)
    {
        return await this.Session.Client.QueryVirtualDiskFragmentation(this.Reference, name, datacenter?.Reference);
    }

    public async System.Threading.Tasks.Task<HostDiskDimensionsChs> QueryVirtualDiskGeometry(string name, Datacenter datacenter)
    {
        return await this.Session.Client.QueryVirtualDiskGeometry(this.Reference, name, datacenter?.Reference);
    }

    public async System.Threading.Tasks.Task<string> QueryVirtualDiskUuid(string name, Datacenter datacenter)
    {
        return await this.Session.Client.QueryVirtualDiskUuid(this.Reference, name, datacenter?.Reference);
    }

    public async System.Threading.Tasks.Task ReleaseManagedSnapshot(string vdisk, Datacenter datacenter)
    {
        await this.Session.Client.ReleaseManagedSnapshot(this.Reference, vdisk, datacenter?.Reference);
    }

    public async System.Threading.Tasks.Task SetVirtualDiskUuid(string name, Datacenter datacenter, string uuid)
    {
        await this.Session.Client.SetVirtualDiskUuid(this.Reference, name, datacenter?.Reference, uuid);
    }

    public async System.Threading.Tasks.Task<Task> ShrinkVirtualDisk_Task(string name, Datacenter datacenter, bool? copy)
    {
        var res = await this.Session.Client.ShrinkVirtualDisk_Task(this.Reference, name, datacenter?.Reference, copy ?? default, copy.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ZeroFillVirtualDisk_Task(string name, Datacenter datacenter)
    {
        var res = await this.Session.Client.ZeroFillVirtualDisk_Task(this.Reference, name, datacenter?.Reference);
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
        return await this.GetProperty<VirtualMachineCapability>("capability");
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigInfo> GetPropertyConfig()
    {
        return await this.GetProperty<VirtualMachineConfigInfo>("config");
    }

    public async System.Threading.Tasks.Task<Datastore[]> GetPropertyDatastore()
    {
        var datastore = await this.GetProperty<ManagedObjectReference[]>("datastore");
        return datastore
            .Select(r => ManagedObject.Create<Datastore>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<EnvironmentBrowser> GetPropertyEnvironmentBrowser()
    {
        var environmentBrowser = await this.GetProperty<ManagedObjectReference>("environmentBrowser");
        return ManagedObject.Create<EnvironmentBrowser>(environmentBrowser, this.Session);
    }

    public async System.Threading.Tasks.Task<GuestInfo> GetPropertyGuest()
    {
        return await this.GetProperty<GuestInfo>("guest");
    }

    public async System.Threading.Tasks.Task<ManagedEntityStatus> GetPropertyGuestHeartbeatStatus()
    {
        return await this.GetProperty<ManagedEntityStatus>("guestHeartbeatStatus");
    }

    public async System.Threading.Tasks.Task<VirtualMachineFileLayout> GetPropertyLayout()
    {
        return await this.GetProperty<VirtualMachineFileLayout>("layout");
    }

    public async System.Threading.Tasks.Task<VirtualMachineFileLayoutEx> GetPropertyLayoutEx()
    {
        return await this.GetProperty<VirtualMachineFileLayoutEx>("layoutEx");
    }

    public async System.Threading.Tasks.Task<Network[]> GetPropertyNetwork()
    {
        var network = await this.GetProperty<ManagedObjectReference[]>("network");
        return network
            .Select(r => ManagedObject.Create<Network>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<ManagedEntity> GetPropertyParentVApp()
    {
        var parentVApp = await this.GetProperty<ManagedObjectReference>("parentVApp");
        return ManagedObject.Create<ManagedEntity>(parentVApp, this.Session);
    }

    public async System.Threading.Tasks.Task<ResourceConfigSpec> GetPropertyResourceConfig()
    {
        return await this.GetProperty<ResourceConfigSpec>("resourceConfig");
    }

    public async System.Threading.Tasks.Task<ResourcePool> GetPropertyResourcePool()
    {
        var resourcePool = await this.GetProperty<ManagedObjectReference>("resourcePool");
        return ManagedObject.Create<ResourcePool>(resourcePool, this.Session);
    }

    public async System.Threading.Tasks.Task<VirtualMachineSnapshot[]> GetPropertyRootSnapshot()
    {
        var rootSnapshot = await this.GetProperty<ManagedObjectReference[]>("rootSnapshot");
        return rootSnapshot
            .Select(r => ManagedObject.Create<VirtualMachineSnapshot>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachineRuntimeInfo> GetPropertyRuntime()
    {
        return await this.GetProperty<VirtualMachineRuntimeInfo>("runtime");
    }

    public async System.Threading.Tasks.Task<VirtualMachineSnapshotInfo> GetPropertySnapshot()
    {
        return await this.GetProperty<VirtualMachineSnapshotInfo>("snapshot");
    }

    public async System.Threading.Tasks.Task<VirtualMachineStorageInfo> GetPropertyStorage()
    {
        return await this.GetProperty<VirtualMachineStorageInfo>("storage");
    }

    public async System.Threading.Tasks.Task<VirtualMachineSummary> GetPropertySummary()
    {
        return await this.GetProperty<VirtualMachineSummary>("summary");
    }

    public async System.Threading.Tasks.Task<VirtualMachineMksTicket> AcquireMksTicket()
    {
        return await this.Session.Client.AcquireMksTicket(this.Reference);
    }

    public async System.Threading.Tasks.Task<VirtualMachineTicket> AcquireTicket(string ticketType)
    {
        return await this.Session.Client.AcquireTicket(this.Reference, ticketType);
    }

    public async System.Threading.Tasks.Task AnswerVM(string questionId, string answerChoice)
    {
        await this.Session.Client.AnswerVM(this.Reference, questionId, answerChoice);
    }

    public async System.Threading.Tasks.Task<Task> ApplyEvcModeVM_Task(HostFeatureMask[] mask, bool? completeMasks)
    {
        var res = await this.Session.Client.ApplyEvcModeVM_Task(this.Reference, mask, completeMasks ?? default, completeMasks.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> AttachDisk_Task(ID diskId, Datastore datastore, int? controllerKey, int? unitNumber)
    {
        var res = await this.Session.Client.AttachDisk_Task(this.Reference, diskId, datastore?.Reference, controllerKey ?? default, controllerKey.HasValue, unitNumber ?? default, unitNumber.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task CheckCustomizationSpec(CustomizationSpec spec)
    {
        await this.Session.Client.CheckCustomizationSpec(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task<Task> CloneVM_Task(Folder folder, string name, VirtualMachineCloneSpec spec)
    {
        var res = await this.Session.Client.CloneVM_Task(this.Reference, folder?.Reference, name, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> ConsolidateVMDisks_Task()
    {
        var res = await this.Session.Client.ConsolidateVMDisks_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateScreenshot_Task()
    {
        var res = await this.Session.Client.CreateScreenshot_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateSecondaryVM_Task(HostSystem host)
    {
        var res = await this.Session.Client.CreateSecondaryVM_Task(this.Reference, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateSecondaryVMEx_Task(HostSystem host, FaultToleranceConfigSpec spec)
    {
        var res = await this.Session.Client.CreateSecondaryVMEx_Task(this.Reference, host?.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateSnapshot_Task(string name, string description, bool memory, bool quiesce)
    {
        var res = await this.Session.Client.CreateSnapshot_Task(this.Reference, name, description, memory, quiesce);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CreateSnapshotEx_Task(string name, string description, bool memory, VirtualMachineGuestQuiesceSpec quiesceSpec)
    {
        var res = await this.Session.Client.CreateSnapshotEx_Task(this.Reference, name, description, memory, quiesceSpec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CryptoUnlock_Task()
    {
        var res = await this.Session.Client.CryptoUnlock_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CustomizeVM_Task(CustomizationSpec spec)
    {
        var res = await this.Session.Client.CustomizeVM_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task DefragmentAllDisks()
    {
        await this.Session.Client.DefragmentAllDisks(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> DetachDisk_Task(ID diskId)
    {
        var res = await this.Session.Client.DetachDisk_Task(this.Reference, diskId);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> DisableSecondaryVM_Task(VirtualMachine vm)
    {
        var res = await this.Session.Client.DisableSecondaryVM_Task(this.Reference, vm?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<bool> DropConnections(VirtualMachineConnection[] listOfConnections)
    {
        return await this.Session.Client.DropConnections(this.Reference, listOfConnections);
    }

    public async System.Threading.Tasks.Task<Task> EnableSecondaryVM_Task(VirtualMachine vm, HostSystem host)
    {
        var res = await this.Session.Client.EnableSecondaryVM_Task(this.Reference, vm?.Reference, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> EstimateStorageForConsolidateSnapshots_Task()
    {
        var res = await this.Session.Client.EstimateStorageForConsolidateSnapshots_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease> ExportVm()
    {
        var res = await this.Session.Client.ExportVm(this.Reference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<string> ExtractOvfEnvironment()
    {
        return await this.Session.Client.ExtractOvfEnvironment(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> InstantClone_Task(VirtualMachineInstantCloneSpec spec)
    {
        var res = await this.Session.Client.InstantClone_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> MakePrimaryVM_Task(VirtualMachine vm)
    {
        var res = await this.Session.Client.MakePrimaryVM_Task(this.Reference, vm?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MarkAsTemplate()
    {
        await this.Session.Client.MarkAsTemplate(this.Reference);
    }

    public async System.Threading.Tasks.Task MarkAsVirtualMachine(ResourcePool pool, HostSystem host)
    {
        await this.Session.Client.MarkAsVirtualMachine(this.Reference, pool?.Reference, host?.Reference);
    }

    public async System.Threading.Tasks.Task<Task> MigrateVM_Task(ResourcePool pool, HostSystem host, VirtualMachineMovePriority priority, VirtualMachinePowerState? state)
    {
        var res = await this.Session.Client.MigrateVM_Task(this.Reference, pool?.Reference, host?.Reference, priority, state ?? default, state.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task MountToolsInstaller()
    {
        await this.Session.Client.MountToolsInstaller(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> PowerOffVM_Task()
    {
        var res = await this.Session.Client.PowerOffVM_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> PowerOnVM_Task(HostSystem host)
    {
        var res = await this.Session.Client.PowerOnVM_Task(this.Reference, host?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> PromoteDisks_Task(bool unlink, VirtualDisk[] disks)
    {
        var res = await this.Session.Client.PromoteDisks_Task(this.Reference, unlink, disks);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<int> PutUsbScanCodes(UsbScanCodeSpec spec)
    {
        return await this.Session.Client.PutUsbScanCodes(this.Reference, spec);
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo> QueryChangedDiskAreas(VirtualMachineSnapshot snapshot, int deviceKey, long startOffset, string changeId)
    {
        return await this.Session.Client.QueryChangedDiskAreas(this.Reference, snapshot?.Reference, deviceKey, startOffset, changeId);
    }

    public async System.Threading.Tasks.Task<VirtualMachineConnection[]> QueryConnections()
    {
        return await this.Session.Client.QueryConnections(this.Reference);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]> QueryFaultToleranceCompatibility()
    {
        return await this.Session.Client.QueryFaultToleranceCompatibility(this.Reference);
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]> QueryFaultToleranceCompatibilityEx(bool? forLegacyFt)
    {
        return await this.Session.Client.QueryFaultToleranceCompatibilityEx(this.Reference, forLegacyFt ?? default, forLegacyFt.HasValue);
    }

    public async System.Threading.Tasks.Task<string[]> QueryUnownedFiles()
    {
        return await this.Session.Client.QueryUnownedFiles(this.Reference);
    }

    public async System.Threading.Tasks.Task RebootGuest()
    {
        await this.Session.Client.RebootGuest(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ReconfigVM_Task(VirtualMachineConfigSpec spec)
    {
        var res = await this.Session.Client.ReconfigVM_Task(this.Reference, spec);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RefreshStorageInfo()
    {
        await this.Session.Client.RefreshStorageInfo(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ReloadVirtualMachineFromPath_Task(string configurationPath)
    {
        var res = await this.Session.Client.ReloadVirtualMachineFromPath_Task(this.Reference, configurationPath);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RelocateVM_Task(VirtualMachineRelocateSpec spec, VirtualMachineMovePriority? priority)
    {
        var res = await this.Session.Client.RelocateVM_Task(this.Reference, spec, priority ?? default, priority.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RemoveAllSnapshots_Task(bool? consolidate)
    {
        var res = await this.Session.Client.RemoveAllSnapshots_Task(this.Reference, consolidate ?? default, consolidate.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task ResetGuestInformation()
    {
        await this.Session.Client.ResetGuestInformation(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> ResetVM_Task()
    {
        var res = await this.Session.Client.ResetVM_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RevertToCurrentSnapshot_Task(HostSystem host, bool? suppressPowerOn)
    {
        var res = await this.Session.Client.RevertToCurrentSnapshot_Task(this.Reference, host?.Reference, suppressPowerOn ?? default, suppressPowerOn.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task SendNMI()
    {
        await this.Session.Client.SendNMI(this.Reference);
    }

    public async System.Threading.Tasks.Task SetDisplayTopology(VirtualMachineDisplayTopology[] displays)
    {
        await this.Session.Client.SetDisplayTopology(this.Reference, displays);
    }

    public async System.Threading.Tasks.Task SetScreenResolution(int width, int height)
    {
        await this.Session.Client.SetScreenResolution(this.Reference, width, height);
    }

    public async System.Threading.Tasks.Task ShutdownGuest()
    {
        await this.Session.Client.ShutdownGuest(this.Reference);
    }

    public async System.Threading.Tasks.Task StandbyGuest()
    {
        await this.Session.Client.StandbyGuest(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> StartRecording_Task(string name, string description)
    {
        var res = await this.Session.Client.StartRecording_Task(this.Reference, name, description);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> StartReplaying_Task(VirtualMachineSnapshot replaySnapshot)
    {
        var res = await this.Session.Client.StartReplaying_Task(this.Reference, replaySnapshot?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> StopRecording_Task()
    {
        var res = await this.Session.Client.StopRecording_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> StopReplaying_Task()
    {
        var res = await this.Session.Client.StopReplaying_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> SuspendVM_Task()
    {
        var res = await this.Session.Client.SuspendVM_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> TerminateFaultTolerantVM_Task(VirtualMachine vm)
    {
        var res = await this.Session.Client.TerminateFaultTolerantVM_Task(this.Reference, vm?.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task TerminateVM()
    {
        await this.Session.Client.TerminateVM(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> TurnOffFaultToleranceForVM_Task()
    {
        var res = await this.Session.Client.TurnOffFaultToleranceForVM_Task(this.Reference);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task UnmountToolsInstaller()
    {
        await this.Session.Client.UnmountToolsInstaller(this.Reference);
    }

    public async System.Threading.Tasks.Task UnregisterVM()
    {
        await this.Session.Client.UnregisterVM(this.Reference);
    }

    public async System.Threading.Tasks.Task<Task> UpgradeTools_Task(string installerOptions)
    {
        var res = await this.Session.Client.UpgradeTools_Task(this.Reference, installerOptions);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> UpgradeVM_Task(string version)
    {
        var res = await this.Session.Client.UpgradeVM_Task(this.Reference, version);
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

    public async System.Threading.Tasks.Task<Task> CheckCompatibility_Task(VirtualMachine vm, HostSystem host, ResourcePool pool, string[] testType)
    {
        var res = await this.Session.Client.CheckCompatibility_Task(this.Reference, vm?.Reference, host?.Reference, pool?.Reference, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckPowerOn_Task(VirtualMachine vm, HostSystem host, ResourcePool pool, string[] testType)
    {
        var res = await this.Session.Client.CheckPowerOn_Task(this.Reference, vm?.Reference, host?.Reference, pool?.Reference, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckVmConfig_Task(VirtualMachineConfigSpec spec, VirtualMachine vm, HostSystem host, ResourcePool pool, string[] testType)
    {
        var res = await this.Session.Client.CheckVmConfig_Task(this.Reference, spec, vm?.Reference, host?.Reference, pool?.Reference, testType);
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

    public async System.Threading.Tasks.Task<Task> AbortCustomization_Task(VirtualMachine vm, GuestAuthentication auth)
    {
        var res = await this.Session.Client.AbortCustomization_Task(this.Reference, vm?.Reference, auth);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CustomizeGuest_Task(VirtualMachine vm, GuestAuthentication auth, CustomizationSpec spec, OptionValue[] configParams)
    {
        var res = await this.Session.Client.CustomizeGuest_Task(this.Reference, vm?.Reference, auth, spec, configParams);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> StartGuestNetwork_Task(VirtualMachine vm, GuestAuthentication auth)
    {
        var res = await this.Session.Client.StartGuestNetwork_Task(this.Reference, vm?.Reference, auth);
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

    public async System.Threading.Tasks.Task<Task> CheckClone_Task(VirtualMachine vm, Folder folder, string name, VirtualMachineCloneSpec spec, string[] testType)
    {
        var res = await this.Session.Client.CheckClone_Task(this.Reference, vm?.Reference, folder?.Reference, name, spec, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckInstantClone_Task(VirtualMachine vm, VirtualMachineInstantCloneSpec spec, string[] testType)
    {
        var res = await this.Session.Client.CheckInstantClone_Task(this.Reference, vm?.Reference, spec, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckMigrate_Task(VirtualMachine vm, HostSystem host, ResourcePool pool, VirtualMachinePowerState? state, string[] testType)
    {
        var res = await this.Session.Client.CheckMigrate_Task(this.Reference, vm?.Reference, host?.Reference, pool?.Reference, state ?? default, state.HasValue, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> CheckRelocate_Task(VirtualMachine vm, VirtualMachineRelocateSpec spec, string[] testType)
    {
        var res = await this.Session.Client.CheckRelocate_Task(this.Reference, vm?.Reference, spec, testType);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> QueryVMotionCompatibilityEx_Task(VirtualMachine[] vm, HostSystem[] host)
    {
        var res = await this.Session.Client.QueryVMotionCompatibilityEx_Task(this.Reference, vm?.Select(m => m.Reference).ToArray(), host?.Select(m => m.Reference).ToArray());
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

    public async System.Threading.Tasks.Task<VirtualMachineSnapshot[]> GetPropertyChildSnapshot()
    {
        var childSnapshot = await this.GetProperty<ManagedObjectReference[]>("childSnapshot");
        return childSnapshot
            .Select(r => ManagedObject.Create<VirtualMachineSnapshot>(r, this.Session))
            .ToArray();
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigInfo> GetPropertyConfig()
    {
        return await this.GetProperty<VirtualMachineConfigInfo>("config");
    }

    public async System.Threading.Tasks.Task<VirtualMachine> GetPropertyVm()
    {
        var vm = await this.GetProperty<ManagedObjectReference>("vm");
        return ManagedObject.Create<VirtualMachine>(vm, this.Session);
    }

    public async System.Threading.Tasks.Task<HttpNfcLease> ExportSnapshot()
    {
        var res = await this.Session.Client.ExportSnapshot(this.Reference);
        return ManagedObject.Create<HttpNfcLease>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<Task> RemoveSnapshot_Task(bool removeChildren, bool? consolidate)
    {
        var res = await this.Session.Client.RemoveSnapshot_Task(this.Reference, removeChildren, consolidate ?? default, consolidate.HasValue);
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task RenameSnapshot(string name, string description)
    {
        await this.Session.Client.RenameSnapshot(this.Reference, name, description);
    }

    public async System.Threading.Tasks.Task<Task> RevertToSnapshot_Task(HostSystem host, bool? suppressPowerOn)
    {
        var res = await this.Session.Client.RevertToSnapshot_Task(this.Reference, host?.Reference, suppressPowerOn ?? default, suppressPowerOn.HasValue);
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

    public async System.Threading.Tasks.Task<Task> UpdateDVSLacpGroupConfig_Task(VMwareDvsLacpGroupSpec[] lacpGroupSpec)
    {
        var res = await this.Session.Client.UpdateDVSLacpGroupConfig_Task(this.Reference, lacpGroupSpec);
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

    public async System.Threading.Tasks.Task<Task> PerformVsanUpgrade_Task(ClusterComputeResource cluster, bool? performObjectUpgrade, bool? downgradeFormat, bool? allowReducedRedundancy, HostSystem[] excludeHosts)
    {
        var res = await this.Session.Client.PerformVsanUpgrade_Task(this.Reference, cluster?.Reference, performObjectUpgrade ?? default, performObjectUpgrade.HasValue, downgradeFormat ?? default, downgradeFormat.HasValue, allowReducedRedundancy ?? default, allowReducedRedundancy.HasValue, excludeHosts?.Select(m => m.Reference).ToArray());
        return ManagedObject.Create<Task>(res, this.Session);
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemPreflightCheckResult> PerformVsanUpgradePreflightCheck(ClusterComputeResource cluster, bool? downgradeFormat)
    {
        return await this.Session.Client.PerformVsanUpgradePreflightCheck(this.Reference, cluster?.Reference, downgradeFormat ?? default, downgradeFormat.HasValue);
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemUpgradeStatus> QueryVsanUpgradeStatus(ClusterComputeResource cluster)
    {
        return await this.Session.Client.QueryVsanUpgradeStatus(this.Reference, cluster?.Reference);
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

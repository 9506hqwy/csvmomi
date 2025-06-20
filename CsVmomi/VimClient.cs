namespace CsVmomi;

using System.ServiceModel.Channels;

#pragma warning disable IDE0058 // Expression value is never used

public class VimClient : IVimClient
{
    private readonly VimPortTypeClient inner;

    internal VimClient(VimPortTypeClient inner)
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

    public async System.Threading.Tasks.Task AbandonHciWorkflow(ManagedObjectReference self)
    {
        var req = new AbandonHciWorkflowRequestType
        {
            _this = self,
        };

        await this.inner.AbandonHciWorkflowAsync(req);
    }

    public async System.Threading.Tasks.Task<string[]?> AbdicateDomOwnership(ManagedObjectReference self, string[] uuids)
    {
        var req = new AbdicateDomOwnershipRequestType
        {
            _this = self,
            uuids = uuids,
        };

        var res = await this.inner.AbdicateDomOwnershipAsync(req);

        return res.AbdicateDomOwnershipResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> AbortCustomization_Task(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth)
    {
        var req = new AbortCustomizationRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
        };

        var res = await this.inner.AbortCustomization_TaskAsync(req);

        return res.AbortCustomization_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task AcknowledgeAlarm(ManagedObjectReference self, ManagedObjectReference alarm, ManagedObjectReference entity)
    {
        var req = new AcknowledgeAlarmRequestType
        {
            _this = self,
            alarm = alarm,
            entity = entity,
        };

        await this.inner.AcknowledgeAlarmAsync(req);
    }

    public async System.Threading.Tasks.Task<HostServiceTicket?> AcquireCimServicesTicket(ManagedObjectReference self)
    {
        var req = new AcquireCimServicesTicketRequestType
        {
            _this = self,
        };

        var res = await this.inner.AcquireCimServicesTicketAsync(req);

        return res.AcquireCimServicesTicketResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> AcquireCloneTicket(ManagedObjectReference self)
    {
        var req = new AcquireCloneTicketRequestType
        {
            _this = self,
        };

        var res = await this.inner.AcquireCloneTicketAsync(req);

        return res.AcquireCloneTicketResponse.returnval;
    }

    public async System.Threading.Tasks.Task<GuestAuthentication?> AcquireCredentialsInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication requestedAuth, long sessionID, bool sessionIDSpecified)
    {
        var req = new AcquireCredentialsInGuestRequestType
        {
            _this = self,
            vm = vm,
            requestedAuth = requestedAuth,
            sessionID = sessionID,
            sessionIDSpecified = sessionIDSpecified,
        };

        var res = await this.inner.AcquireCredentialsInGuestAsync(req);

        return res.AcquireCredentialsInGuestResponse.returnval;
    }

    public async System.Threading.Tasks.Task<SessionManagerGenericServiceTicket?> AcquireGenericServiceTicket(ManagedObjectReference self, SessionManagerServiceRequestSpec spec)
    {
        var req = new AcquireGenericServiceTicketRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.AcquireGenericServiceTicketAsync(req);

        return res.AcquireGenericServiceTicketResponse.returnval;
    }

    public async System.Threading.Tasks.Task<SessionManagerLocalTicket?> AcquireLocalTicket(ManagedObjectReference self, string userName)
    {
        var req = new AcquireLocalTicketRequestType
        {
            _this = self,
            userName = userName,
        };

        var res = await this.inner.AcquireLocalTicketAsync(req);

        return res.AcquireLocalTicketResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VirtualMachineMksTicket?> AcquireMksTicket(ManagedObjectReference self)
    {
        var req = new AcquireMksTicketRequestType
        {
            _this = self,
        };

        var res = await this.inner.AcquireMksTicketAsync(req);

        return res.AcquireMksTicketResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VirtualMachineTicket?> AcquireTicket(ManagedObjectReference self, string ticketType)
    {
        var req = new AcquireTicketRequestType
        {
            _this = self,
            ticketType = ticketType,
        };

        var res = await this.inner.AcquireTicketAsync(req);

        return res.AcquireTicketResponse.returnval;
    }

    public async System.Threading.Tasks.Task<int> AddAuthorizationRole(ManagedObjectReference self, string name, string[]? privIds)
    {
        var req = new AddAuthorizationRoleRequestType
        {
            _this = self,
            name = name,
            privIds = privIds,
        };

        var res = await this.inner.AddAuthorizationRoleAsync(req);

        return res.AddAuthorizationRoleResponse.returnval;
    }

    public async System.Threading.Tasks.Task<CustomFieldDef?> AddCustomFieldDef(ManagedObjectReference self, string name, string? moType, PrivilegePolicyDef? fieldDefPolicy, PrivilegePolicyDef? fieldPolicy)
    {
        var req = new AddCustomFieldDefRequestType
        {
            _this = self,
            name = name,
            moType = moType,
            fieldDefPolicy = fieldDefPolicy,
            fieldPolicy = fieldPolicy,
        };

        var res = await this.inner.AddCustomFieldDefAsync(req);

        return res.AddCustomFieldDefResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> AddDisks_Task(ManagedObjectReference self, HostScsiDisk[] disk)
    {
        var req = new AddDisksRequestType
        {
            _this = self,
            disk = disk,
        };

        var res = await this.inner.AddDisks_TaskAsync(req);

        return res.AddDisks_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> AddDVPortgroup_Task(ManagedObjectReference self, DVPortgroupConfigSpec[] spec)
    {
        var req = new AddDVPortgroupRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.AddDVPortgroup_TaskAsync(req);

        return res.AddDVPortgroup_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> AddFilter(ManagedObjectReference self, string providerId, string filterName, string[]? infoIds)
    {
        var req = new AddFilterRequestType
        {
            _this = self,
            providerId = providerId,
            filterName = filterName,
            infoIds = infoIds,
        };

        var res = await this.inner.AddFilterAsync(req);

        return res.AddFilterResponse.returnval;
    }

    public async System.Threading.Tasks.Task AddFilterEntities(ManagedObjectReference self, string filterId, ManagedObjectReference[]? entities)
    {
        var req = new AddFilterEntitiesRequestType
        {
            _this = self,
            filterId = filterId,
            entities = entities,
        };

        await this.inner.AddFilterEntitiesAsync(req);
    }

    public async System.Threading.Tasks.Task AddGuestAlias(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username, bool mapCert, string base64Cert, GuestAuthAliasInfo aliasInfo)
    {
        var req = new AddGuestAliasRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            username = username,
            mapCert = mapCert,
            base64Cert = base64Cert,
            aliasInfo = aliasInfo,
        };

        await this.inner.AddGuestAliasAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> AddHost_Task(ManagedObjectReference self, HostConnectSpec spec, bool asConnected, ManagedObjectReference? resourcePool, string? license)
    {
        var req = new AddHostRequestType
        {
            _this = self,
            spec = spec,
            asConnected = asConnected,
            resourcePool = resourcePool,
            license = license,
        };

        var res = await this.inner.AddHost_TaskAsync(req);

        return res.AddHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task AddInternetScsiSendTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets)
    {
        var req = new AddInternetScsiSendTargetsRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            targets = targets,
        };

        await this.inner.AddInternetScsiSendTargetsAsync(req);
    }

    public async System.Threading.Tasks.Task AddInternetScsiStaticTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        var req = new AddInternetScsiStaticTargetsRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            targets = targets,
        };

        await this.inner.AddInternetScsiStaticTargetsAsync(req);
    }

    public async System.Threading.Tasks.Task AddKey(ManagedObjectReference self, CryptoKeyPlain key)
    {
        var req = new AddKeyRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.AddKeyAsync(req);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]?> AddKeys(ManagedObjectReference self, CryptoKeyPlain[]? keys)
    {
        var req = new AddKeysRequestType
        {
            _this = self,
            keys = keys,
        };

        var res = await this.inner.AddKeysAsync(req);

        return res.AddKeysResponse1;
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> AddLicense(ManagedObjectReference self, string licenseKey, KeyValue[]? labels)
    {
        var req = new AddLicenseRequestType
        {
            _this = self,
            licenseKey = licenseKey,
            labels = labels,
        };

        var res = await this.inner.AddLicenseAsync(req);

        return res.AddLicenseResponse.returnval;
    }

    public async System.Threading.Tasks.Task AddMonitoredEntities(ManagedObjectReference self, string providerId, ManagedObjectReference[]? entities)
    {
        var req = new AddMonitoredEntitiesRequestType
        {
            _this = self,
            providerId = providerId,
            entities = entities,
        };

        await this.inner.AddMonitoredEntitiesAsync(req);
    }

    public async System.Threading.Tasks.Task AddNetworkResourcePool(ManagedObjectReference self, DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        var req = new AddNetworkResourcePoolRequestType
        {
            _this = self,
            configSpec = configSpec,
        };

        await this.inner.AddNetworkResourcePoolAsync(req);
    }

    public async System.Threading.Tasks.Task AddPortGroup(ManagedObjectReference self, HostPortGroupSpec portgrp)
    {
        var req = new AddPortGroupRequestType
        {
            _this = self,
            portgrp = portgrp,
        };

        await this.inner.AddPortGroupAsync(req);
    }

    public async System.Threading.Tasks.Task<string?> AddServiceConsoleVirtualNic(ManagedObjectReference self, string portgroup, HostVirtualNicSpec nic)
    {
        var req = new AddServiceConsoleVirtualNicRequestType
        {
            _this = self,
            portgroup = portgroup,
            nic = nic,
        };

        var res = await this.inner.AddServiceConsoleVirtualNicAsync(req);

        return res.AddServiceConsoleVirtualNicResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> AddStandaloneHost_Task(ManagedObjectReference self, HostConnectSpec spec, ComputeResourceConfigSpec? compResSpec, bool addConnected, string? license)
    {
        var req = new AddStandaloneHostRequestType
        {
            _this = self,
            spec = spec,
            compResSpec = compResSpec,
            addConnected = addConnected,
            license = license,
        };

        var res = await this.inner.AddStandaloneHost_TaskAsync(req);

        return res.AddStandaloneHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> AddVirtualNic(ManagedObjectReference self, string portgroup, HostVirtualNicSpec nic)
    {
        var req = new AddVirtualNicRequestType
        {
            _this = self,
            portgroup = portgroup,
            nic = nic,
        };

        var res = await this.inner.AddVirtualNicAsync(req);

        return res.AddVirtualNicResponse.returnval;
    }

    public async System.Threading.Tasks.Task AddVirtualSwitch(ManagedObjectReference self, string vswitchName, HostVirtualSwitchSpec? spec)
    {
        var req = new AddVirtualSwitchRequestType
        {
            _this = self,
            vswitchName = vswitchName,
            spec = spec,
        };

        await this.inner.AddVirtualSwitchAsync(req);
    }

    public async System.Threading.Tasks.Task<string?> AllocateIpv4Address(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string allocationId)
    {
        var req = new AllocateIpv4AddressRequestType
        {
            _this = self,
            dc = dc,
            poolId = poolId,
            allocationId = allocationId,
        };

        var res = await this.inner.AllocateIpv4AddressAsync(req);

        return res.AllocateIpv4AddressResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> AllocateIpv6Address(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string allocationId)
    {
        var req = new AllocateIpv6AddressRequestType
        {
            _this = self,
            dc = dc,
            poolId = poolId,
            allocationId = allocationId,
        };

        var res = await this.inner.AllocateIpv6AddressAsync(req);

        return res.AllocateIpv6AddressResponse.returnval;
    }

    public async System.Threading.Tasks.Task AnswerVM(ManagedObjectReference self, string questionId, string answerChoice)
    {
        var req = new AnswerVMRequestType
        {
            _this = self,
            questionId = questionId,
            answerChoice = answerChoice,
        };

        await this.inner.AnswerVMAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ApplyEntitiesConfig_Task(ManagedObjectReference self, ApplyHostProfileConfigurationSpec[]? applyConfigSpecs)
    {
        var req = new ApplyEntitiesConfigRequestType
        {
            _this = self,
            applyConfigSpecs = applyConfigSpecs,
        };

        var res = await this.inner.ApplyEntitiesConfig_TaskAsync(req);

        return res.ApplyEntitiesConfig_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ApplyEvcModeVM_Task(ManagedObjectReference self, HostFeatureMask[]? mask, bool completeMasks, bool completeMasksSpecified)
    {
        var req = new ApplyEvcModeVMRequestType
        {
            _this = self,
            mask = mask,
            completeMasks = completeMasks,
            completeMasksSpecified = completeMasksSpecified,
        };

        var res = await this.inner.ApplyEvcModeVM_TaskAsync(req);

        return res.ApplyEvcModeVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ApplyHostConfig_Task(ManagedObjectReference self, ManagedObjectReference host, HostConfigSpec configSpec, ProfileDeferredPolicyOptionParameter[]? userInput)
    {
        var req = new ApplyHostConfigRequestType
        {
            _this = self,
            host = host,
            configSpec = configSpec,
            userInput = userInput,
        };

        var res = await this.inner.ApplyHostConfig_TaskAsync(req);

        return res.ApplyHostConfig_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ApplyRecommendation(ManagedObjectReference self, string key)
    {
        var req = new ApplyRecommendationRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.ApplyRecommendationAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ApplyStorageDrsRecommendation_Task(ManagedObjectReference self, string[] key)
    {
        var req = new ApplyStorageDrsRecommendationRequestType
        {
            _this = self,
            key = key,
        };

        var res = await this.inner.ApplyStorageDrsRecommendation_TaskAsync(req);

        return res.ApplyStorageDrsRecommendation_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ApplyStorageDrsRecommendationToPod_Task(ManagedObjectReference self, ManagedObjectReference pod, string key)
    {
        var req = new ApplyStorageDrsRecommendationToPodRequestType
        {
            _this = self,
            pod = pod,
            key = key,
        };

        var res = await this.inner.ApplyStorageDrsRecommendationToPod_TaskAsync(req);

        return res.ApplyStorageDrsRecommendationToPod_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> AreAlarmActionsEnabled(ManagedObjectReference self, ManagedObjectReference entity)
    {
        var req = new AreAlarmActionsEnabledRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.AreAlarmActionsEnabledAsync(req);

        return res.AreAlarmActionsEnabledResponse.returnval;
    }

    public async System.Threading.Tasks.Task AssignUserToGroup(ManagedObjectReference self, string user, string group)
    {
        var req = new AssignUserToGroupRequestType
        {
            _this = self,
            user = user,
            group = group,
        };

        await this.inner.AssignUserToGroupAsync(req);
    }

    public async System.Threading.Tasks.Task AssociateProfile(ManagedObjectReference self, ManagedObjectReference[] entity)
    {
        var req = new AssociateProfileRequestType
        {
            _this = self,
            entity = entity,
        };

        await this.inner.AssociateProfileAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> AttachDisk_Task(ManagedObjectReference self, ID diskId, ManagedObjectReference datastore, int controllerKey, bool controllerKeySpecified, int unitNumber, bool unitNumberSpecified)
    {
        var req = new AttachDiskRequestType
        {
            _this = self,
            diskId = diskId,
            datastore = datastore,
            controllerKey = controllerKey,
            controllerKeySpecified = controllerKeySpecified,
            unitNumber = unitNumber,
            unitNumberSpecified = unitNumberSpecified,
        };

        var res = await this.inner.AttachDisk_TaskAsync(req);

        return res.AttachDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task AttachScsiLun(ManagedObjectReference self, string lunUuid)
    {
        var req = new AttachScsiLunRequestType
        {
            _this = self,
            lunUuid = lunUuid,
        };

        await this.inner.AttachScsiLunAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> AttachScsiLunEx_Task(ManagedObjectReference self, string[] lunUuid)
    {
        var req = new AttachScsiLunExRequestType
        {
            _this = self,
            lunUuid = lunUuid,
        };

        var res = await this.inner.AttachScsiLunEx_TaskAsync(req);

        return res.AttachScsiLunEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task AttachTagToVStorageObject(ManagedObjectReference self, ID id, string category, string tag)
    {
        var req = new AttachTagToVStorageObjectRequestType
        {
            _this = self,
            id = id,
            category = category,
            tag = tag,
        };

        await this.inner.AttachTagToVStorageObjectAsync(req);
    }

    public async System.Threading.Tasks.Task AttachVmfsExtent(ManagedObjectReference self, string vmfsPath, HostScsiDiskPartition extent)
    {
        var req = new AttachVmfsExtentRequestType
        {
            _this = self,
            vmfsPath = vmfsPath,
            extent = extent,
        };

        await this.inner.AttachVmfsExtentAsync(req);
    }

    public async System.Threading.Tasks.Task AutoStartPowerOff(ManagedObjectReference self)
    {
        var req = new AutoStartPowerOffRequestType
        {
            _this = self,
        };

        await this.inner.AutoStartPowerOffAsync(req);
    }

    public async System.Threading.Tasks.Task AutoStartPowerOn(ManagedObjectReference self)
    {
        var req = new AutoStartPowerOnRequestType
        {
            _this = self,
        };

        await this.inner.AutoStartPowerOnAsync(req);
    }

    public async System.Threading.Tasks.Task<string?> BackupFirmwareConfiguration(ManagedObjectReference self)
    {
        var req = new BackupFirmwareConfigurationRequestType
        {
            _this = self,
        };

        var res = await this.inner.BackupFirmwareConfigurationAsync(req);

        return res.BackupFirmwareConfigurationResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> BatchAddHostsToCluster_Task(ManagedObjectReference self, ManagedObjectReference cluster, FolderNewHostSpec[]? newHosts, ManagedObjectReference[]? existingHosts, ComputeResourceConfigSpec? compResSpec, string? desiredState)
    {
        var req = new BatchAddHostsToClusterRequestType
        {
            _this = self,
            cluster = cluster,
            newHosts = newHosts,
            existingHosts = existingHosts,
            compResSpec = compResSpec,
            desiredState = desiredState,
        };

        var res = await this.inner.BatchAddHostsToCluster_TaskAsync(req);

        return res.BatchAddHostsToCluster_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> BatchAddStandaloneHosts_Task(ManagedObjectReference self, FolderNewHostSpec[]? newHosts, ComputeResourceConfigSpec? compResSpec, bool addConnected)
    {
        var req = new BatchAddStandaloneHostsRequestType
        {
            _this = self,
            newHosts = newHosts,
            compResSpec = compResSpec,
            addConnected = addConnected,
        };

        var res = await this.inner.BatchAddStandaloneHosts_TaskAsync(req);

        return res.BatchAddStandaloneHosts_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DatacenterBasicConnectInfo[]?> BatchQueryConnectInfo(ManagedObjectReference self, HostConnectSpec[]? hostSpecs)
    {
        var req = new BatchQueryConnectInfoRequestType
        {
            _this = self,
            hostSpecs = hostSpecs,
        };

        var res = await this.inner.BatchQueryConnectInfoAsync(req);

        return res.BatchQueryConnectInfoResponse1;
    }

    public async System.Threading.Tasks.Task BindVnic(ManagedObjectReference self, string iScsiHbaName, string vnicDevice)
    {
        var req = new BindVnicRequestType
        {
            _this = self,
            iScsiHbaName = iScsiHbaName,
            vnicDevice = vnicDevice,
        };

        await this.inner.BindVnicAsync(req);
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerLogHeader?> BrowseDiagnosticLog(ManagedObjectReference self, ManagedObjectReference? host, string key, int start, bool startSpecified, int lines, bool linesSpecified)
    {
        var req = new BrowseDiagnosticLogRequestType
        {
            _this = self,
            host = host,
            key = key,
            start = start,
            startSpecified = startSpecified,
            lines = lines,
            linesSpecified = linesSpecified,
        };

        var res = await this.inner.BrowseDiagnosticLogAsync(req);

        return res.BrowseDiagnosticLogResponse.returnval;
    }

    public async System.Threading.Tasks.Task CancelRecommendation(ManagedObjectReference self, string key)
    {
        var req = new CancelRecommendationRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.CancelRecommendationAsync(req);
    }

    public async System.Threading.Tasks.Task CancelRetrievePropertiesEx(ManagedObjectReference self, string token)
    {
        var req = new CancelRetrievePropertiesExRequestType
        {
            _this = self,
            token = token,
        };

        await this.inner.CancelRetrievePropertiesExAsync(req);
    }

    public async System.Threading.Tasks.Task CancelStorageDrsRecommendation(ManagedObjectReference self, string[] key)
    {
        var req = new CancelStorageDrsRecommendationRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.CancelStorageDrsRecommendationAsync(req);
    }

    public async System.Threading.Tasks.Task CancelTask(ManagedObjectReference self)
    {
        var req = new CancelTaskRequestType
        {
            _this = self,
        };

        await this.inner.CancelTaskAsync(req);
    }

    public async System.Threading.Tasks.Task CancelWaitForUpdates(ManagedObjectReference self)
    {
        var req = new CancelWaitForUpdatesRequestType
        {
            _this = self,
        };

        await this.inner.CancelWaitForUpdatesAsync(req);
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> CanProvisionObjects(ManagedObjectReference self, VsanNewPolicyBatch[] npbs, bool ignoreSatisfiability, bool ignoreSatisfiabilitySpecified)
    {
        var req = new CanProvisionObjectsRequestType
        {
            _this = self,
            npbs = npbs,
            ignoreSatisfiability = ignoreSatisfiability,
            ignoreSatisfiabilitySpecified = ignoreSatisfiabilitySpecified,
        };

        var res = await this.inner.CanProvisionObjectsAsync(req);

        return res.CanProvisionObjectsResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CertMgrRefreshCACertificatesAndCRLs_Task(ManagedObjectReference self, ManagedObjectReference[] host)
    {
        var req = new CertMgrRefreshCACertificatesAndCRLsRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.CertMgrRefreshCACertificatesAndCRLs_TaskAsync(req);

        return res.CertMgrRefreshCACertificatesAndCRLs_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CertMgrRefreshCertificates_Task(ManagedObjectReference self, ManagedObjectReference[] host)
    {
        var req = new CertMgrRefreshCertificatesRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.CertMgrRefreshCertificates_TaskAsync(req);

        return res.CertMgrRefreshCertificates_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CertMgrRevokeCertificates_Task(ManagedObjectReference self, ManagedObjectReference[] host)
    {
        var req = new CertMgrRevokeCertificatesRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.CertMgrRevokeCertificates_TaskAsync(req);

        return res.CertMgrRevokeCertificates_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ChangeAccessMode(ManagedObjectReference self, string principal, bool isGroup, HostAccessMode accessMode)
    {
        var req = new ChangeAccessModeRequestType
        {
            _this = self,
            principal = principal,
            isGroup = isGroup,
            accessMode = accessMode,
        };

        await this.inner.ChangeAccessModeAsync(req);
    }

    public async System.Threading.Tasks.Task ChangeFileAttributesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes)
    {
        var req = new ChangeFileAttributesInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            guestFilePath = guestFilePath,
            fileAttributes = fileAttributes,
        };

        await this.inner.ChangeFileAttributesInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ChangeKey_Task(ManagedObjectReference self, CryptoKeyPlain newKey)
    {
        var req = new ChangeKeyRequestType
        {
            _this = self,
            newKey = newKey,
        };

        var res = await this.inner.ChangeKey_TaskAsync(req);

        return res.ChangeKey_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ChangeLockdownMode(ManagedObjectReference self, HostLockdownMode mode)
    {
        var req = new ChangeLockdownModeRequestType
        {
            _this = self,
            mode = mode,
        };

        await this.inner.ChangeLockdownModeAsync(req);
    }

    public async System.Threading.Tasks.Task ChangeNFSUserPassword(ManagedObjectReference self, string password)
    {
        var req = new ChangeNFSUserPasswordRequestType
        {
            _this = self,
            password = password,
        };

        await this.inner.ChangeNFSUserPasswordAsync(req);
    }

    public async System.Threading.Tasks.Task ChangeOwner(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, string owner)
    {
        var req = new ChangeOwnerRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
            owner = owner,
        };

        await this.inner.ChangeOwnerAsync(req);
    }

    public async System.Threading.Tasks.Task ChangePassword(ManagedObjectReference self, string user, string oldPassword, string newPassword)
    {
        var req = new ChangePasswordRequestType
        {
            _this = self,
            user = user,
            oldPassword = oldPassword,
            newPassword = newPassword,
        };

        await this.inner.ChangePasswordAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckAddHostEvc_Task(ManagedObjectReference self, HostConnectSpec cnxSpec)
    {
        var req = new CheckAddHostEvcRequestType
        {
            _this = self,
            cnxSpec = cnxSpec,
        };

        var res = await this.inner.CheckAddHostEvc_TaskAsync(req);

        return res.CheckAddHostEvc_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckAnswerFileStatus_Task(ManagedObjectReference self, ManagedObjectReference[] host)
    {
        var req = new CheckAnswerFileStatusRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.CheckAnswerFileStatus_TaskAsync(req);

        return res.CheckAnswerFileStatus_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckClone_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference folder, string name, VirtualMachineCloneSpec spec, string[]? testType)
    {
        var req = new CheckCloneRequestType
        {
            _this = self,
            vm = vm,
            folder = folder,
            name = name,
            spec = spec,
            testType = testType,
        };

        var res = await this.inner.CheckClone_TaskAsync(req);

        return res.CheckClone_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckCompatibility_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host, ManagedObjectReference? pool, string[]? testType)
    {
        var req = new CheckCompatibilityRequestType
        {
            _this = self,
            vm = vm,
            host = host,
            pool = pool,
            testType = testType,
        };

        var res = await this.inner.CheckCompatibility_TaskAsync(req);

        return res.CheckCompatibility_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckCompliance_Task(ManagedObjectReference self, ManagedObjectReference[]? profile, ManagedObjectReference[]? entity)
    {
        var req = new CheckComplianceRequestType
        {
            _this = self,
            profile = profile,
            entity = entity,
        };

        var res = await this.inner.CheckCompliance_TaskAsync(req);

        return res.CheckCompliance_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckConfigureEvcMode_Task(ManagedObjectReference self, string evcModeKey, string? evcGraphicsModeKey)
    {
        var req = new CheckConfigureEvcModeRequestType
        {
            _this = self,
            evcModeKey = evcModeKey,
            evcGraphicsModeKey = evcGraphicsModeKey,
        };

        var res = await this.inner.CheckConfigureEvcMode_TaskAsync(req);

        return res.CheckConfigureEvcMode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task CheckCustomizationResources(ManagedObjectReference self, string guestOs)
    {
        var req = new CheckCustomizationResourcesRequestType
        {
            _this = self,
            guestOs = guestOs,
        };

        await this.inner.CheckCustomizationResourcesAsync(req);
    }

    public async System.Threading.Tasks.Task CheckCustomizationSpec(ManagedObjectReference self, CustomizationSpec spec)
    {
        var req = new CheckCustomizationSpecRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.CheckCustomizationSpecAsync(req);
    }

    public async System.Threading.Tasks.Task<UpdateSet?> CheckForUpdates(ManagedObjectReference self, string? version)
    {
        var req = new CheckForUpdatesRequestType
        {
            _this = self,
            version = version,
        };

        var res = await this.inner.CheckForUpdatesAsync(req);

        return res.CheckForUpdatesResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckHostPatch_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var req = new CheckHostPatchRequestType
        {
            _this = self,
            metaUrls = metaUrls,
            bundleUrls = bundleUrls,
            spec = spec,
        };

        var res = await this.inner.CheckHostPatch_TaskAsync(req);

        return res.CheckHostPatch_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckInstantClone_Task(ManagedObjectReference self, ManagedObjectReference vm, VirtualMachineInstantCloneSpec spec, string[]? testType)
    {
        var req = new CheckInstantCloneRequestType
        {
            _this = self,
            vm = vm,
            spec = spec,
            testType = testType,
        };

        var res = await this.inner.CheckInstantClone_TaskAsync(req);

        return res.CheckInstantClone_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> CheckLicenseFeature(ManagedObjectReference self, ManagedObjectReference? host, string featureKey)
    {
        var req = new CheckLicenseFeatureRequestType
        {
            _this = self,
            host = host,
            featureKey = featureKey,
        };

        var res = await this.inner.CheckLicenseFeatureAsync(req);

        return res.CheckLicenseFeatureResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckMigrate_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host, ManagedObjectReference? pool, VirtualMachinePowerState state, bool stateSpecified, string[]? testType)
    {
        var req = new CheckMigrateRequestType
        {
            _this = self,
            vm = vm,
            host = host,
            pool = pool,
            state = state,
            stateSpecified = stateSpecified,
            testType = testType,
        };

        var res = await this.inner.CheckMigrate_TaskAsync(req);

        return res.CheckMigrate_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckPowerOn_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host, ManagedObjectReference? pool, string[]? testType)
    {
        var req = new CheckPowerOnRequestType
        {
            _this = self,
            vm = vm,
            host = host,
            pool = pool,
            testType = testType,
        };

        var res = await this.inner.CheckPowerOn_TaskAsync(req);

        return res.CheckPowerOn_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckProfileCompliance_Task(ManagedObjectReference self, ManagedObjectReference[]? entity)
    {
        var req = new CheckProfileComplianceRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.CheckProfileCompliance_TaskAsync(req);

        return res.CheckProfileCompliance_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckRelocate_Task(ManagedObjectReference self, ManagedObjectReference vm, VirtualMachineRelocateSpec spec, string[]? testType)
    {
        var req = new CheckRelocateRequestType
        {
            _this = self,
            vm = vm,
            spec = spec,
            testType = testType,
        };

        var res = await this.inner.CheckRelocate_TaskAsync(req);

        return res.CheckRelocate_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CheckVmConfig_Task(ManagedObjectReference self, VirtualMachineConfigSpec spec, ManagedObjectReference? vm, ManagedObjectReference? host, ManagedObjectReference? pool, string[]? testType)
    {
        var req = new CheckVmConfigRequestType
        {
            _this = self,
            spec = spec,
            vm = vm,
            host = host,
            pool = pool,
            testType = testType,
        };

        var res = await this.inner.CheckVmConfig_TaskAsync(req);

        return res.CheckVmConfig_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ClearComplianceStatus(ManagedObjectReference self, ManagedObjectReference[]? profile, ManagedObjectReference[]? entity)
    {
        var req = new ClearComplianceStatusRequestType
        {
            _this = self,
            profile = profile,
            entity = entity,
        };

        await this.inner.ClearComplianceStatusAsync(req);
    }

    public async System.Threading.Tasks.Task ClearNFSUser(ManagedObjectReference self)
    {
        var req = new ClearNFSUserRequestType
        {
            _this = self,
        };

        await this.inner.ClearNFSUserAsync(req);
    }

    public async System.Threading.Tasks.Task ClearSystemEventLog(ManagedObjectReference self)
    {
        var req = new ClearSystemEventLogRequestType
        {
            _this = self,
        };

        await this.inner.ClearSystemEventLogAsync(req);
    }

    public async System.Threading.Tasks.Task ClearTriggeredAlarms(ManagedObjectReference self, AlarmFilterSpec filter)
    {
        var req = new ClearTriggeredAlarmsRequestType
        {
            _this = self,
            filter = filter,
        };

        await this.inner.ClearTriggeredAlarmsAsync(req);
    }

    public async System.Threading.Tasks.Task ClearVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags)
    {
        var req = new ClearVStorageObjectControlFlagsRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            controlFlags = controlFlags,
        };

        await this.inner.ClearVStorageObjectControlFlagsAsync(req);
    }

    public async System.Threading.Tasks.Task<UserSession?> CloneSession(ManagedObjectReference self, string cloneTicket)
    {
        var req = new CloneSessionRequestType
        {
            _this = self,
            cloneTicket = cloneTicket,
        };

        var res = await this.inner.CloneSessionAsync(req);

        return res.CloneSessionResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CloneVApp_Task(ManagedObjectReference self, string name, ManagedObjectReference target, VAppCloneSpec spec)
    {
        var req = new CloneVAppRequestType
        {
            _this = self,
            name = name,
            target = target,
            spec = spec,
        };

        var res = await this.inner.CloneVApp_TaskAsync(req);

        return res.CloneVApp_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CloneVM_Task(ManagedObjectReference self, ManagedObjectReference folder, string name, VirtualMachineCloneSpec spec)
    {
        var req = new CloneVMRequestType
        {
            _this = self,
            folder = folder,
            name = name,
            spec = spec,
        };

        var res = await this.inner.CloneVM_TaskAsync(req);

        return res.CloneVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CloneVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmCloneSpec spec)
    {
        var req = new CloneVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            spec = spec,
        };

        var res = await this.inner.CloneVStorageObject_TaskAsync(req);

        return res.CloneVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> CloseInventoryViewFolder(ManagedObjectReference self, ManagedObjectReference[] entity)
    {
        var req = new CloseInventoryViewFolderRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.CloseInventoryViewFolderAsync(req);

        return res.CloseInventoryViewFolderResponse1;
    }

    public async System.Threading.Tasks.Task<ClusterEnterMaintenanceResult?> ClusterEnterMaintenanceMode(ManagedObjectReference self, ManagedObjectReference[] host, OptionValue[]? option, ClusterComputeResourceMaintenanceInfo? info)
    {
        var req = new ClusterEnterMaintenanceModeRequestType
        {
            _this = self,
            host = host,
            option = option,
            info = info,
        };

        var res = await this.inner.ClusterEnterMaintenanceModeAsync(req);

        return res.ClusterEnterMaintenanceModeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CompositeHostProfile_Task(ManagedObjectReference self, ManagedObjectReference source, ManagedObjectReference[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toBeReplacedWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied)
    {
        var req = new CompositeHostProfileRequestType
        {
            _this = self,
            source = source,
            targets = targets,
            toBeMerged = toBeMerged,
            toBeReplacedWith = toBeReplacedWith,
            toBeDeleted = toBeDeleted,
            enableStatusToBeCopied = enableStatusToBeCopied,
        };

        var res = await this.inner.CompositeHostProfile_TaskAsync(req);

        return res.CompositeHostProfile_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfo(ManagedObjectReference self, string devicePath, HostDiskPartitionLayout layout, string? partitionFormat)
    {
        var req = new ComputeDiskPartitionInfoRequestType
        {
            _this = self,
            devicePath = devicePath,
            layout = layout,
            partitionFormat = partitionFormat,
        };

        var res = await this.inner.ComputeDiskPartitionInfoAsync(req);

        return res.ComputeDiskPartitionInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo?> ComputeDiskPartitionInfoForResize(ManagedObjectReference self, HostScsiDiskPartition partition, HostDiskPartitionBlockRange blockRange, string? partitionFormat)
    {
        var req = new ComputeDiskPartitionInfoForResizeRequestType
        {
            _this = self,
            partition = partition,
            blockRange = blockRange,
            partitionFormat = partitionFormat,
        };

        var res = await this.inner.ComputeDiskPartitionInfoForResizeAsync(req);

        return res.ComputeDiskPartitionInfoForResizeResponse.returnval;
    }

    public async System.Threading.Tasks.Task ConfigureCryptoKey(ManagedObjectReference self, CryptoKeyId? keyId)
    {
        var req = new ConfigureCryptoKeyRequestType
        {
            _this = self,
            keyId = keyId,
        };

        await this.inner.ConfigureCryptoKeyAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureDatastoreIORM_Task(ManagedObjectReference self, ManagedObjectReference datastore, StorageIORMConfigSpec spec)
    {
        var req = new ConfigureDatastoreIORMRequestType
        {
            _this = self,
            datastore = datastore,
            spec = spec,
        };

        var res = await this.inner.ConfigureDatastoreIORM_TaskAsync(req);

        return res.ConfigureDatastoreIORM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ConfigureDatastorePrincipal(ManagedObjectReference self, string userName, string? password)
    {
        var req = new ConfigureDatastorePrincipalRequestType
        {
            _this = self,
            userName = userName,
            password = password,
        };

        await this.inner.ConfigureDatastorePrincipalAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureEvcMode_Task(ManagedObjectReference self, string evcModeKey, string? evcGraphicsModeKey)
    {
        var req = new ConfigureEvcModeRequestType
        {
            _this = self,
            evcModeKey = evcModeKey,
            evcGraphicsModeKey = evcGraphicsModeKey,
        };

        var res = await this.inner.ConfigureEvcMode_TaskAsync(req);

        return res.ConfigureEvcMode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureHCI_Task(ManagedObjectReference self, ClusterComputeResourceHCIConfigSpec clusterSpec, ClusterComputeResourceHostConfigurationInput[]? hostInputs)
    {
        var req = new ConfigureHCIRequestType
        {
            _this = self,
            clusterSpec = clusterSpec,
            hostInputs = hostInputs,
        };

        var res = await this.inner.ConfigureHCI_TaskAsync(req);

        return res.ConfigureHCI_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureHostCache_Task(ManagedObjectReference self, HostCacheConfigurationSpec spec)
    {
        var req = new ConfigureHostCacheRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.ConfigureHostCache_TaskAsync(req);

        return res.ConfigureHostCache_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ConfigureLicenseSource(ManagedObjectReference self, ManagedObjectReference? host, LicenseSource licenseSource)
    {
        var req = new ConfigureLicenseSourceRequestType
        {
            _this = self,
            host = host,
            licenseSource = licenseSource,
        };

        await this.inner.ConfigureLicenseSourceAsync(req);
    }

    public async System.Threading.Tasks.Task ConfigurePowerPolicy(ManagedObjectReference self, int key)
    {
        var req = new ConfigurePowerPolicyRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.ConfigurePowerPolicyAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureStorageDrsForPod_Task(ManagedObjectReference self, ManagedObjectReference pod, StorageDrsConfigSpec spec, bool modify)
    {
        var req = new ConfigureStorageDrsForPodRequestType
        {
            _this = self,
            pod = pod,
            spec = spec,
            modify = modify,
        };

        var res = await this.inner.ConfigureStorageDrsForPod_TaskAsync(req);

        return res.ConfigureStorageDrsForPod_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureVcha_Task(ManagedObjectReference self, VchaClusterConfigSpec configSpec)
    {
        var req = new configureVchaRequestType
        {
            _this = self,
            configSpec = configSpec,
        };

        var res = await this.inner.configureVcha_TaskAsync(req);

        return res.configureVcha_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConfigureVFlashResourceEx_Task(ManagedObjectReference self, string[]? devicePath)
    {
        var req = new ConfigureVFlashResourceExRequestType
        {
            _this = self,
            devicePath = devicePath,
        };

        var res = await this.inner.ConfigureVFlashResourceEx_TaskAsync(req);

        return res.ConfigureVFlashResourceEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ConnectNvmeController(ManagedObjectReference self, HostNvmeConnectSpec connectSpec)
    {
        var req = new ConnectNvmeControllerRequestType
        {
            _this = self,
            connectSpec = connectSpec,
        };

        await this.inner.ConnectNvmeControllerAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConnectNvmeControllerEx_Task(ManagedObjectReference self, HostNvmeConnectSpec[]? connectSpec)
    {
        var req = new ConnectNvmeControllerExRequestType
        {
            _this = self,
            connectSpec = connectSpec,
        };

        var res = await this.inner.ConnectNvmeControllerEx_TaskAsync(req);

        return res.ConnectNvmeControllerEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ConsolidateVMDisks_Task(ManagedObjectReference self)
    {
        var req = new ConsolidateVMDisksRequestType
        {
            _this = self,
        };

        var res = await this.inner.ConsolidateVMDisks_TaskAsync(req);

        return res.ConsolidateVMDisks_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<RetrieveResult?> ContinueRetrievePropertiesEx(ManagedObjectReference self, string token)
    {
        var req = new ContinueRetrievePropertiesExRequestType
        {
            _this = self,
            token = token,
        };

        var res = await this.inner.ContinueRetrievePropertiesExAsync(req);

        return res.ContinueRetrievePropertiesExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> ConvertNamespacePathToUuidPath(ManagedObjectReference self, ManagedObjectReference? datacenter, string namespaceUrl)
    {
        var req = new ConvertNamespacePathToUuidPathRequestType
        {
            _this = self,
            datacenter = datacenter,
            namespaceUrl = namespaceUrl,
        };

        var res = await this.inner.ConvertNamespacePathToUuidPathAsync(req);

        return res.ConvertNamespacePathToUuidPathResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CopyDatastoreFile_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destinationName, ManagedObjectReference? destinationDatacenter, bool force, bool forceSpecified)
    {
        var req = new CopyDatastoreFileRequestType
        {
            _this = self,
            sourceName = sourceName,
            sourceDatacenter = sourceDatacenter,
            destinationName = destinationName,
            destinationDatacenter = destinationDatacenter,
            force = force,
            forceSpecified = forceSpecified,
        };

        var res = await this.inner.CopyDatastoreFile_TaskAsync(req);

        return res.CopyDatastoreFile_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CopyVirtualDisk_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destName, ManagedObjectReference? destDatacenter, VirtualDiskSpec? destSpec, bool force, bool forceSpecified)
    {
        var req = new CopyVirtualDiskRequestType
        {
            _this = self,
            sourceName = sourceName,
            sourceDatacenter = sourceDatacenter,
            destName = destName,
            destDatacenter = destDatacenter,
            destSpec = destSpec,
            force = force,
            forceSpecified = forceSpecified,
        };

        var res = await this.inner.CopyVirtualDisk_TaskAsync(req);

        return res.CopyVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateAlarm(ManagedObjectReference self, ManagedObjectReference entity, AlarmSpec spec)
    {
        var req = new CreateAlarmRequestType
        {
            _this = self,
            entity = entity,
            spec = spec,
        };

        var res = await this.inner.CreateAlarmAsync(req);

        return res.CreateAlarmResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateChildVM_Task(ManagedObjectReference self, VirtualMachineConfigSpec config, ManagedObjectReference? host)
    {
        var req = new CreateChildVMRequestType
        {
            _this = self,
            config = config,
            host = host,
        };

        var res = await this.inner.CreateChildVM_TaskAsync(req);

        return res.CreateChildVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateCluster(ManagedObjectReference self, string name, ClusterConfigSpec spec)
    {
        var req = new CreateClusterRequestType
        {
            _this = self,
            name = name,
            spec = spec,
        };

        var res = await this.inner.CreateClusterAsync(req);

        return res.CreateClusterResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateClusterEx(ManagedObjectReference self, string name, ClusterConfigSpecEx spec)
    {
        var req = new CreateClusterExRequestType
        {
            _this = self,
            name = name,
            spec = spec,
        };

        var res = await this.inner.CreateClusterExAsync(req);

        return res.CreateClusterExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateCollectorForEvents(ManagedObjectReference self, EventFilterSpec filter)
    {
        var req = new CreateCollectorForEventsRequestType
        {
            _this = self,
            filter = filter,
        };

        var res = await this.inner.CreateCollectorForEventsAsync(req);

        return res.CreateCollectorForEventsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateCollectorForTasks(ManagedObjectReference self, TaskFilterSpec filter)
    {
        var req = new CreateCollectorForTasksRequestType
        {
            _this = self,
            filter = filter,
        };

        var res = await this.inner.CreateCollectorForTasksAsync(req);

        return res.CreateCollectorForTasksResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateCollectorWithInfoFilterForTasks(ManagedObjectReference self, TaskFilterSpec filter, TaskInfoFilterSpec? infoFilter)
    {
        var req = new CreateCollectorWithInfoFilterForTasksRequestType
        {
            _this = self,
            filter = filter,
            infoFilter = infoFilter,
        };

        var res = await this.inner.CreateCollectorWithInfoFilterForTasksAsync(req);

        return res.CreateCollectorWithInfoFilterForTasksResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateContainerView(ManagedObjectReference self, ManagedObjectReference container, string[]? type, bool recursive)
    {
        var req = new CreateContainerViewRequestType
        {
            _this = self,
            container = container,
            type = type,
            recursive = recursive,
        };

        var res = await this.inner.CreateContainerViewAsync(req);

        return res.CreateContainerViewResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreateCustomizationSpec(ManagedObjectReference self, CustomizationSpecItem item)
    {
        var req = new CreateCustomizationSpecRequestType
        {
            _this = self,
            item = item,
        };

        await this.inner.CreateCustomizationSpecAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateDatacenter(ManagedObjectReference self, string name)
    {
        var req = new CreateDatacenterRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.CreateDatacenterAsync(req);

        return res.CreateDatacenterResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ApplyProfile?> CreateDefaultProfile(ManagedObjectReference self, string profileType, string? profileTypeName, ManagedObjectReference? profile)
    {
        var req = new CreateDefaultProfileRequestType
        {
            _this = self,
            profileType = profileType,
            profileTypeName = profileTypeName,
            profile = profile,
        };

        var res = await this.inner.CreateDefaultProfileAsync(req);

        return res.CreateDefaultProfileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<OvfCreateDescriptorResult?> CreateDescriptor(ManagedObjectReference self, ManagedObjectReference obj, OvfCreateDescriptorParams cdp)
    {
        var req = new CreateDescriptorRequestType
        {
            _this = self,
            obj = obj,
            cdp = cdp,
        };

        var res = await this.inner.CreateDescriptorAsync(req);

        return res.CreateDescriptorResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreateDiagnosticPartition(ManagedObjectReference self, HostDiagnosticPartitionCreateSpec spec)
    {
        var req = new CreateDiagnosticPartitionRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.CreateDiagnosticPartitionAsync(req);
    }

    public async System.Threading.Tasks.Task<string?> CreateDirectory(ManagedObjectReference self, ManagedObjectReference datastore, string? displayName, string? policy, long size, bool sizeSpecified)
    {
        var req = new CreateDirectoryRequestType
        {
            _this = self,
            datastore = datastore,
            displayName = displayName,
            policy = policy,
            size = size,
            sizeSpecified = sizeSpecified,
        };

        var res = await this.inner.CreateDirectoryAsync(req);

        return res.CreateDirectoryResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateDisk_Task(ManagedObjectReference self, VslmCreateSpec spec)
    {
        var req = new CreateDiskRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.CreateDisk_TaskAsync(req);

        return res.CreateDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateDiskFromSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path)
    {
        var req = new CreateDiskFromSnapshotRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
            name = name,
            profile = profile,
            crypto = crypto,
            path = path,
        };

        var res = await this.inner.CreateDiskFromSnapshot_TaskAsync(req);

        return res.CreateDiskFromSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateDVPortgroup_Task(ManagedObjectReference self, DVPortgroupConfigSpec spec)
    {
        var req = new CreateDVPortgroupRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.CreateDVPortgroup_TaskAsync(req);

        return res.CreateDVPortgroup_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateDVS_Task(ManagedObjectReference self, DVSCreateSpec spec)
    {
        var req = new CreateDVSRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.CreateDVS_TaskAsync(req);

        return res.CreateDVS_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateFilter(ManagedObjectReference self, PropertyFilterSpec spec, bool partialUpdates)
    {
        var req = new CreateFilterRequestType
        {
            _this = self,
            spec = spec,
            partialUpdates = partialUpdates,
        };

        var res = await this.inner.CreateFilterAsync(req);

        return res.CreateFilterResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateFolder(ManagedObjectReference self, string name)
    {
        var req = new CreateFolderRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.CreateFolderAsync(req);

        return res.CreateFolderResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreateGroup(ManagedObjectReference self, HostAccountSpec group)
    {
        var req = new CreateGroupRequestType
        {
            _this = self,
            group = group,
        };

        await this.inner.CreateGroupAsync(req);
    }

    public async System.Threading.Tasks.Task<OvfCreateImportSpecResult?> CreateImportSpec(ManagedObjectReference self, string ovfDescriptor, ManagedObjectReference resourcePool, ManagedObjectReference datastore, OvfCreateImportSpecParams cisp)
    {
        var req = new CreateImportSpecRequestType
        {
            _this = self,
            ovfDescriptor = ovfDescriptor,
            resourcePool = resourcePool,
            datastore = datastore,
            cisp = cisp,
        };

        var res = await this.inner.CreateImportSpecAsync(req);

        return res.CreateImportSpecResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateInventoryView(ManagedObjectReference self)
    {
        var req = new CreateInventoryViewRequestType
        {
            _this = self,
        };

        var res = await this.inner.CreateInventoryViewAsync(req);

        return res.CreateInventoryViewResponse.returnval;
    }

    public async System.Threading.Tasks.Task<int> CreateIpPool(ManagedObjectReference self, ManagedObjectReference dc, IpPool pool)
    {
        var req = new CreateIpPoolRequestType
        {
            _this = self,
            dc = dc,
            pool = pool,
        };

        var res = await this.inner.CreateIpPoolAsync(req);

        return res.CreateIpPoolResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateListView(ManagedObjectReference self, ManagedObjectReference[]? obj)
    {
        var req = new CreateListViewRequestType
        {
            _this = self,
            obj = obj,
        };

        var res = await this.inner.CreateListViewAsync(req);

        return res.CreateListViewResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateListViewFromView(ManagedObjectReference self, ManagedObjectReference view)
    {
        var req = new CreateListViewFromViewRequestType
        {
            _this = self,
            view = view,
        };

        var res = await this.inner.CreateListViewFromViewAsync(req);

        return res.CreateListViewFromViewResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateLocalDatastore(ManagedObjectReference self, string name, string path)
    {
        var req = new CreateLocalDatastoreRequestType
        {
            _this = self,
            name = name,
            path = path,
        };

        var res = await this.inner.CreateLocalDatastoreAsync(req);

        return res.CreateLocalDatastoreResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateNasDatastore(ManagedObjectReference self, HostNasVolumeSpec spec)
    {
        var req = new CreateNasDatastoreRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.CreateNasDatastoreAsync(req);

        return res.CreateNasDatastoreResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateNvdimmNamespace_Task(ManagedObjectReference self, NvdimmNamespaceCreateSpec createSpec)
    {
        var req = new CreateNvdimmNamespaceRequestType
        {
            _this = self,
            createSpec = createSpec,
        };

        var res = await this.inner.CreateNvdimmNamespace_TaskAsync(req);

        return res.CreateNvdimmNamespace_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateNvdimmPMemNamespace_Task(ManagedObjectReference self, NvdimmPMemNamespaceCreateSpec createSpec)
    {
        var req = new CreateNvdimmPMemNamespaceRequestType
        {
            _this = self,
            createSpec = createSpec,
        };

        var res = await this.inner.CreateNvdimmPMemNamespace_TaskAsync(req);

        return res.CreateNvdimmPMemNamespace_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreateNvmeOverRdmaAdapter(ManagedObjectReference self, string rdmaDeviceName)
    {
        var req = new CreateNvmeOverRdmaAdapterRequestType
        {
            _this = self,
            rdmaDeviceName = rdmaDeviceName,
        };

        await this.inner.CreateNvmeOverRdmaAdapterAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateObjectScheduledTask(ManagedObjectReference self, ManagedObjectReference obj, ScheduledTaskSpec spec)
    {
        var req = new CreateObjectScheduledTaskRequestType
        {
            _this = self,
            obj = obj,
            spec = spec,
        };

        var res = await this.inner.CreateObjectScheduledTaskAsync(req);

        return res.CreateObjectScheduledTaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreatePassiveNode_Task(ManagedObjectReference self, PassiveNodeDeploymentSpec passiveDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var req = new createPassiveNodeRequestType
        {
            _this = self,
            passiveDeploymentSpec = passiveDeploymentSpec,
            sourceVcSpec = sourceVcSpec,
        };

        var res = await this.inner.createPassiveNode_TaskAsync(req);

        return res.createPassiveNode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreatePerfInterval(ManagedObjectReference self, PerfInterval intervalId)
    {
        var req = new CreatePerfIntervalRequestType
        {
            _this = self,
            intervalId = intervalId,
        };

        await this.inner.CreatePerfIntervalAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateProfile(ManagedObjectReference self, ProfileCreateSpec createSpec)
    {
        var req = new CreateProfileRequestType
        {
            _this = self,
            createSpec = createSpec,
        };

        var res = await this.inner.CreateProfileAsync(req);

        return res.CreateProfileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreatePropertyCollector(ManagedObjectReference self)
    {
        var req = new CreatePropertyCollectorRequestType
        {
            _this = self,
        };

        var res = await this.inner.CreatePropertyCollectorAsync(req);

        return res.CreatePropertyCollectorResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreateRegistryKeyInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool isVolatile, string? classType)
    {
        var req = new CreateRegistryKeyInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            keyName = keyName,
            isVolatile = isVolatile,
            classType = classType,
        };

        await this.inner.CreateRegistryKeyInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateResourcePool(ManagedObjectReference self, string name, ResourceConfigSpec spec)
    {
        var req = new CreateResourcePoolRequestType
        {
            _this = self,
            name = name,
            spec = spec,
        };

        var res = await this.inner.CreateResourcePoolAsync(req);

        return res.CreateResourcePoolResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateScheduledTask(ManagedObjectReference self, ManagedObjectReference entity, ScheduledTaskSpec spec)
    {
        var req = new CreateScheduledTaskRequestType
        {
            _this = self,
            entity = entity,
            spec = spec,
        };

        var res = await this.inner.CreateScheduledTaskAsync(req);

        return res.CreateScheduledTaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateScreenshot_Task(ManagedObjectReference self)
    {
        var req = new CreateScreenshotRequestType
        {
            _this = self,
        };

        var res = await this.inner.CreateScreenshot_TaskAsync(req);

        return res.CreateScreenshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateSecondaryVM_Task(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new CreateSecondaryVMRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.CreateSecondaryVM_TaskAsync(req);

        return res.CreateSecondaryVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateSecondaryVMEx_Task(ManagedObjectReference self, ManagedObjectReference? host, FaultToleranceConfigSpec? spec)
    {
        var req = new CreateSecondaryVMExRequestType
        {
            _this = self,
            host = host,
            spec = spec,
        };

        var res = await this.inner.CreateSecondaryVMEx_TaskAsync(req);

        return res.CreateSecondaryVMEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateSnapshot_Task(ManagedObjectReference self, string name, string? description, bool memory, bool quiesce)
    {
        var req = new CreateSnapshotRequestType
        {
            _this = self,
            name = name,
            description = description,
            memory = memory,
            quiesce = quiesce,
        };

        var res = await this.inner.CreateSnapshot_TaskAsync(req);

        return res.CreateSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateSnapshotEx_Task(ManagedObjectReference self, string name, string? description, bool memory, VirtualMachineGuestQuiesceSpec? quiesceSpec)
    {
        var req = new CreateSnapshotExRequestType
        {
            _this = self,
            name = name,
            description = description,
            memory = memory,
            quiesceSpec = quiesceSpec,
        };

        var res = await this.inner.CreateSnapshotEx_TaskAsync(req);

        return res.CreateSnapshotEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreateSoftwareAdapter(ManagedObjectReference self, HostHbaCreateSpec spec)
    {
        var req = new CreateSoftwareAdapterRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.CreateSoftwareAdapterAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateStoragePod(ManagedObjectReference self, string name)
    {
        var req = new CreateStoragePodRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.CreateStoragePodAsync(req);

        return res.CreateStoragePodResponse.returnval;
    }

    public async System.Threading.Tasks.Task<TaskInfo?> CreateTask(ManagedObjectReference self, ManagedObjectReference obj, string taskTypeId, string? initiatedBy, bool cancelable, string? parentTaskKey, string? activationId)
    {
        var req = new CreateTaskRequestType
        {
            _this = self,
            obj = obj,
            taskTypeId = taskTypeId,
            initiatedBy = initiatedBy,
            cancelable = cancelable,
            parentTaskKey = parentTaskKey,
            activationId = activationId,
        };

        var res = await this.inner.CreateTaskAsync(req);

        return res.CreateTaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> CreateTemporaryDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath)
    {
        var req = new CreateTemporaryDirectoryInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            prefix = prefix,
            suffix = suffix,
            directoryPath = directoryPath,
        };

        var res = await this.inner.CreateTemporaryDirectoryInGuestAsync(req);

        return res.CreateTemporaryDirectoryInGuestResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> CreateTemporaryFileInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string prefix, string suffix, string? directoryPath)
    {
        var req = new CreateTemporaryFileInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            prefix = prefix,
            suffix = suffix,
            directoryPath = directoryPath,
        };

        var res = await this.inner.CreateTemporaryFileInGuestAsync(req);

        return res.CreateTemporaryFileInGuestResponse.returnval;
    }

    public async System.Threading.Tasks.Task CreateUser(ManagedObjectReference self, HostAccountSpec user)
    {
        var req = new CreateUserRequestType
        {
            _this = self,
            user = user,
        };

        await this.inner.CreateUserAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateVApp(ManagedObjectReference self, string name, ResourceConfigSpec resSpec, VAppConfigSpec configSpec, ManagedObjectReference? vmFolder)
    {
        var req = new CreateVAppRequestType
        {
            _this = self,
            name = name,
            resSpec = resSpec,
            configSpec = configSpec,
            vmFolder = vmFolder,
        };

        var res = await this.inner.CreateVAppAsync(req);

        return res.CreateVAppResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, VirtualDiskSpec spec)
    {
        var req = new CreateVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
            spec = spec,
        };

        var res = await this.inner.CreateVirtualDisk_TaskAsync(req);

        return res.CreateVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateVM_Task(ManagedObjectReference self, VirtualMachineConfigSpec config, ManagedObjectReference pool, ManagedObjectReference? host)
    {
        var req = new CreateVMRequestType
        {
            _this = self,
            config = config,
            pool = pool,
            host = host,
        };

        var res = await this.inner.CreateVM_TaskAsync(req);

        return res.CreateVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateVmfsDatastore(ManagedObjectReference self, VmfsDatastoreCreateSpec spec)
    {
        var req = new CreateVmfsDatastoreRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.CreateVmfsDatastoreAsync(req);

        return res.CreateVmfsDatastoreResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateVvolDatastore(ManagedObjectReference self, HostDatastoreSystemVvolDatastoreSpec spec)
    {
        var req = new CreateVvolDatastoreRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.CreateVvolDatastoreAsync(req);

        return res.CreateVvolDatastoreResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CreateWitnessNode_Task(ManagedObjectReference self, NodeDeploymentSpec witnessDeploymentSpec, SourceNodeSpec sourceVcSpec)
    {
        var req = new createWitnessNodeRequestType
        {
            _this = self,
            witnessDeploymentSpec = witnessDeploymentSpec,
            sourceVcSpec = sourceVcSpec,
        };

        var res = await this.inner.createWitnessNode_TaskAsync(req);

        return res.createWitnessNode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task CryptoManagerHostDisable(ManagedObjectReference self)
    {
        var req = new CryptoManagerHostDisableRequestType
        {
            _this = self,
        };

        await this.inner.CryptoManagerHostDisableAsync(req);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostEnable(ManagedObjectReference self, CryptoKeyPlain initialKey)
    {
        var req = new CryptoManagerHostEnableRequestType
        {
            _this = self,
            initialKey = initialKey,
        };

        await this.inner.CryptoManagerHostEnableAsync(req);
    }

    public async System.Threading.Tasks.Task CryptoManagerHostPrepare(ManagedObjectReference self)
    {
        var req = new CryptoManagerHostPrepareRequestType
        {
            _this = self,
        };

        await this.inner.CryptoManagerHostPrepareAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CryptoUnlock_Task(ManagedObjectReference self)
    {
        var req = new CryptoUnlockRequestType
        {
            _this = self,
        };

        var res = await this.inner.CryptoUnlock_TaskAsync(req);

        return res.CryptoUnlock_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DateTime> CurrentTime(ManagedObjectReference self)
    {
        var req = new CurrentTimeRequestType
        {
            _this = self,
        };

        var res = await this.inner.CurrentTimeAsync(req);

        return res.CurrentTimeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> CustomizationSpecItemToXml(ManagedObjectReference self, CustomizationSpecItem item)
    {
        var req = new CustomizationSpecItemToXmlRequestType
        {
            _this = self,
            item = item,
        };

        var res = await this.inner.CustomizationSpecItemToXmlAsync(req);

        return res.CustomizationSpecItemToXmlResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CustomizeGuest_Task(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, CustomizationSpec spec, OptionValue[]? configParams)
    {
        var req = new CustomizeGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            spec = spec,
            configParams = configParams,
        };

        var res = await this.inner.CustomizeGuest_TaskAsync(req);

        return res.CustomizeGuest_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> CustomizeVM_Task(ManagedObjectReference self, CustomizationSpec spec)
    {
        var req = new CustomizeVMRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.CustomizeVM_TaskAsync(req);

        return res.CustomizeVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult?> DatastoreEnterMaintenanceMode(ManagedObjectReference self)
    {
        var req = new DatastoreEnterMaintenanceModeRequestType
        {
            _this = self,
        };

        var res = await this.inner.DatastoreEnterMaintenanceModeAsync(req);

        return res.DatastoreEnterMaintenanceModeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DatastoreExitMaintenanceMode_Task(ManagedObjectReference self)
    {
        var req = new DatastoreExitMaintenanceModeRequestType
        {
            _this = self,
        };

        var res = await this.inner.DatastoreExitMaintenanceMode_TaskAsync(req);

        return res.DatastoreExitMaintenanceMode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> DecodeLicense(ManagedObjectReference self, string licenseKey)
    {
        var req = new DecodeLicenseRequestType
        {
            _this = self,
            licenseKey = licenseKey,
        };

        var res = await this.inner.DecodeLicenseAsync(req);

        return res.DecodeLicenseResponse.returnval;
    }

    public async System.Threading.Tasks.Task DefragmentAllDisks(ManagedObjectReference self)
    {
        var req = new DefragmentAllDisksRequestType
        {
            _this = self,
        };

        await this.inner.DefragmentAllDisksAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DefragmentVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new DefragmentVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.DefragmentVirtualDisk_TaskAsync(req);

        return res.DefragmentVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DeleteCustomizationSpec(ManagedObjectReference self, string name)
    {
        var req = new DeleteCustomizationSpecRequestType
        {
            _this = self,
            name = name,
        };

        await this.inner.DeleteCustomizationSpecAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeleteDatastoreFile_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new DeleteDatastoreFileRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.DeleteDatastoreFile_TaskAsync(req);

        return res.DeleteDatastoreFile_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DeleteDirectory(ManagedObjectReference self, ManagedObjectReference? datacenter, string datastorePath)
    {
        var req = new DeleteDirectoryRequestType
        {
            _this = self,
            datacenter = datacenter,
            datastorePath = datastorePath,
        };

        await this.inner.DeleteDirectoryAsync(req);
    }

    public async System.Threading.Tasks.Task DeleteDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string directoryPath, bool recursive)
    {
        var req = new DeleteDirectoryInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            directoryPath = directoryPath,
            recursive = recursive,
        };

        await this.inner.DeleteDirectoryInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task DeleteFile(ManagedObjectReference self, string datastorePath)
    {
        var req = new DeleteFileRequestType
        {
            _this = self,
            datastorePath = datastorePath,
        };

        await this.inner.DeleteFileAsync(req);
    }

    public async System.Threading.Tasks.Task DeleteFileInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string filePath)
    {
        var req = new DeleteFileInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            filePath = filePath,
        };

        await this.inner.DeleteFileInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task DeleteHostSpecification(ManagedObjectReference self, ManagedObjectReference host)
    {
        var req = new DeleteHostSpecificationRequestType
        {
            _this = self,
            host = host,
        };

        await this.inner.DeleteHostSpecificationAsync(req);
    }

    public async System.Threading.Tasks.Task DeleteHostSubSpecification(ManagedObjectReference self, ManagedObjectReference host, string subSpecName)
    {
        var req = new DeleteHostSubSpecificationRequestType
        {
            _this = self,
            host = host,
            subSpecName = subSpecName,
        };

        await this.inner.DeleteHostSubSpecificationAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeleteNvdimmBlockNamespaces_Task(ManagedObjectReference self)
    {
        var req = new DeleteNvdimmBlockNamespacesRequestType
        {
            _this = self,
        };

        var res = await this.inner.DeleteNvdimmBlockNamespaces_TaskAsync(req);

        return res.DeleteNvdimmBlockNamespaces_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeleteNvdimmNamespace_Task(ManagedObjectReference self, NvdimmNamespaceDeleteSpec deleteSpec)
    {
        var req = new DeleteNvdimmNamespaceRequestType
        {
            _this = self,
            deleteSpec = deleteSpec,
        };

        var res = await this.inner.DeleteNvdimmNamespace_TaskAsync(req);

        return res.DeleteNvdimmNamespace_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DeleteRegistryKeyInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive)
    {
        var req = new DeleteRegistryKeyInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            keyName = keyName,
            recursive = recursive,
        };

        await this.inner.DeleteRegistryKeyInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task DeleteRegistryValueInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegValueNameSpec valueName)
    {
        var req = new DeleteRegistryValueInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            valueName = valueName,
        };

        await this.inner.DeleteRegistryValueInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task DeleteScsiLunState(ManagedObjectReference self, string lunCanonicalName)
    {
        var req = new DeleteScsiLunStateRequestType
        {
            _this = self,
            lunCanonicalName = lunCanonicalName,
        };

        await this.inner.DeleteScsiLunStateAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeleteSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new DeleteSnapshotRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.DeleteSnapshot_TaskAsync(req);

        return res.DeleteSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DeleteVffsVolumeState(ManagedObjectReference self, string vffsUuid)
    {
        var req = new DeleteVffsVolumeStateRequestType
        {
            _this = self,
            vffsUuid = vffsUuid,
        };

        await this.inner.DeleteVffsVolumeStateAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeleteVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new DeleteVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.DeleteVirtualDisk_TaskAsync(req);

        return res.DeleteVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DeleteVmfsVolumeState(ManagedObjectReference self, string vmfsUuid)
    {
        var req = new DeleteVmfsVolumeStateRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
        };

        await this.inner.DeleteVmfsVolumeStateAsync(req);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemDeleteVsanObjectsResult[]?> DeleteVsanObjects(ManagedObjectReference self, string[] uuids, bool force, bool forceSpecified)
    {
        var req = new DeleteVsanObjectsRequestType
        {
            _this = self,
            uuids = uuids,
            force = force,
            forceSpecified = forceSpecified,
        };

        var res = await this.inner.DeleteVsanObjectsAsync(req);

        return res.DeleteVsanObjectsResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeleteVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new DeleteVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.DeleteVStorageObject_TaskAsync(req);

        return res.DeleteVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeleteVStorageObjectEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new DeleteVStorageObjectExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.DeleteVStorageObjectEx_TaskAsync(req);

        return res.DeleteVStorageObjectEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DeployVcha_Task(ManagedObjectReference self, VchaClusterDeploymentSpec deploymentSpec)
    {
        var req = new deployVchaRequestType
        {
            _this = self,
            deploymentSpec = deploymentSpec,
        };

        var res = await this.inner.deployVcha_TaskAsync(req);

        return res.deployVcha_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DeselectVnic(ManagedObjectReference self)
    {
        var req = new DeselectVnicRequestType
        {
            _this = self,
        };

        await this.inner.DeselectVnicAsync(req);
    }

    public async System.Threading.Tasks.Task DeselectVnicForNicType(ManagedObjectReference self, string nicType, string device)
    {
        var req = new DeselectVnicForNicTypeRequestType
        {
            _this = self,
            nicType = nicType,
            device = device,
        };

        await this.inner.DeselectVnicForNicTypeAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> Destroy_Task(ManagedObjectReference self)
    {
        var req = new DestroyRequestType
        {
            _this = self,
        };

        var res = await this.inner.Destroy_TaskAsync(req);

        return res.Destroy_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DestroyChildren(ManagedObjectReference self)
    {
        var req = new DestroyChildrenRequestType
        {
            _this = self,
        };

        await this.inner.DestroyChildrenAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyCollector(ManagedObjectReference self)
    {
        var req = new DestroyCollectorRequestType
        {
            _this = self,
        };

        await this.inner.DestroyCollectorAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyDatastore(ManagedObjectReference self)
    {
        var req = new DestroyDatastoreRequestType
        {
            _this = self,
        };

        await this.inner.DestroyDatastoreAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyIpPool(ManagedObjectReference self, ManagedObjectReference dc, int id, bool force)
    {
        var req = new DestroyIpPoolRequestType
        {
            _this = self,
            dc = dc,
            id = id,
            force = force,
        };

        await this.inner.DestroyIpPoolAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyNetwork(ManagedObjectReference self)
    {
        var req = new DestroyNetworkRequestType
        {
            _this = self,
        };

        await this.inner.DestroyNetworkAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyProfile(ManagedObjectReference self)
    {
        var req = new DestroyProfileRequestType
        {
            _this = self,
        };

        await this.inner.DestroyProfileAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyPropertyCollector(ManagedObjectReference self)
    {
        var req = new DestroyPropertyCollectorRequestType
        {
            _this = self,
        };

        await this.inner.DestroyPropertyCollectorAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyPropertyFilter(ManagedObjectReference self)
    {
        var req = new DestroyPropertyFilterRequestType
        {
            _this = self,
        };

        await this.inner.DestroyPropertyFilterAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DestroyVcha_Task(ManagedObjectReference self)
    {
        var req = new destroyVchaRequestType
        {
            _this = self,
        };

        var res = await this.inner.destroyVcha_TaskAsync(req);

        return res.destroyVcha_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DestroyVffs(ManagedObjectReference self, string vffsPath)
    {
        var req = new DestroyVffsRequestType
        {
            _this = self,
            vffsPath = vffsPath,
        };

        await this.inner.DestroyVffsAsync(req);
    }

    public async System.Threading.Tasks.Task DestroyView(ManagedObjectReference self)
    {
        var req = new DestroyViewRequestType
        {
            _this = self,
        };

        await this.inner.DestroyViewAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DetachDisk_Task(ManagedObjectReference self, ID diskId)
    {
        var req = new DetachDiskRequestType
        {
            _this = self,
            diskId = diskId,
        };

        var res = await this.inner.DetachDisk_TaskAsync(req);

        return res.DetachDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DetachScsiLun(ManagedObjectReference self, string lunUuid)
    {
        var req = new DetachScsiLunRequestType
        {
            _this = self,
            lunUuid = lunUuid,
        };

        await this.inner.DetachScsiLunAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DetachScsiLunEx_Task(ManagedObjectReference self, string[] lunUuid)
    {
        var req = new DetachScsiLunExRequestType
        {
            _this = self,
            lunUuid = lunUuid,
        };

        var res = await this.inner.DetachScsiLunEx_TaskAsync(req);

        return res.DetachScsiLunEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DetachTagFromVStorageObject(ManagedObjectReference self, ID id, string category, string tag)
    {
        var req = new DetachTagFromVStorageObjectRequestType
        {
            _this = self,
            id = id,
            category = category,
            tag = tag,
        };

        await this.inner.DetachTagFromVStorageObjectAsync(req);
    }

    public async System.Threading.Tasks.Task<string?> DirectPathProfileManagerCreate(ManagedObjectReference self, DirectPathProfileManagerCreateSpec spec)
    {
        var req = new DirectPathProfileManagerCreateRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.DirectPathProfileManagerCreateAsync(req);

        return res.DirectPathProfileManagerCreateResponse.returnval;
    }

    public async System.Threading.Tasks.Task DirectPathProfileManagerDelete(ManagedObjectReference self, string id)
    {
        var req = new DirectPathProfileManagerDeleteRequestType
        {
            _this = self,
            id = id,
        };

        await this.inner.DirectPathProfileManagerDeleteAsync(req);
    }

    public async System.Threading.Tasks.Task<DirectPathProfileInfo[]?> DirectPathProfileManagerList(ManagedObjectReference self, DirectPathProfileManagerFilterSpec filterSpec)
    {
        var req = new DirectPathProfileManagerListRequestType
        {
            _this = self,
            filterSpec = filterSpec,
        };

        var res = await this.inner.DirectPathProfileManagerListAsync(req);

        return res.DirectPathProfileManagerListResponse1;
    }

    public async System.Threading.Tasks.Task<DirectPathProfileManagerCapacityResult[]?> DirectPathProfileManagerQueryCapacity(ManagedObjectReference self, DirectPathProfileManagerTargetEntity target, DirectPathProfileManagerCapacityQuerySpec[]? querySpec)
    {
        var req = new DirectPathProfileManagerQueryCapacityRequestType
        {
            _this = self,
            target = target,
            querySpec = querySpec,
        };

        var res = await this.inner.DirectPathProfileManagerQueryCapacityAsync(req);

        return res.DirectPathProfileManagerQueryCapacityResponse1;
    }

    public async System.Threading.Tasks.Task DirectPathProfileManagerUpdate(ManagedObjectReference self, string id, DirectPathProfileManagerUpdateSpec spec)
    {
        var req = new DirectPathProfileManagerUpdateRequestType
        {
            _this = self,
            id = id,
            spec = spec,
        };

        await this.inner.DirectPathProfileManagerUpdateAsync(req);
    }

    public async System.Threading.Tasks.Task DisableAlarm(ManagedObjectReference self, ManagedObjectReference alarm, ManagedObjectReference entity)
    {
        var req = new DisableAlarmRequestType
        {
            _this = self,
            alarm = alarm,
            entity = entity,
        };

        await this.inner.DisableAlarmAsync(req);
    }

    public async System.Threading.Tasks.Task DisableClusteredVmdkSupport(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new DisableClusteredVmdkSupportRequestType
        {
            _this = self,
            datastore = datastore,
        };

        await this.inner.DisableClusteredVmdkSupportAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DisableEvcMode_Task(ManagedObjectReference self)
    {
        var req = new DisableEvcModeRequestType
        {
            _this = self,
        };

        var res = await this.inner.DisableEvcMode_TaskAsync(req);

        return res.DisableEvcMode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> DisableFeature(ManagedObjectReference self, ManagedObjectReference? host, string featureKey)
    {
        var req = new DisableFeatureRequestType
        {
            _this = self,
            host = host,
            featureKey = featureKey,
        };

        var res = await this.inner.DisableFeatureAsync(req);

        return res.DisableFeatureResponse.returnval;
    }

    public async System.Threading.Tasks.Task DisableHyperThreading(ManagedObjectReference self)
    {
        var req = new DisableHyperThreadingRequestType
        {
            _this = self,
        };

        await this.inner.DisableHyperThreadingAsync(req);
    }

    public async System.Threading.Tasks.Task DisableMultipathPath(ManagedObjectReference self, string pathName)
    {
        var req = new DisableMultipathPathRequestType
        {
            _this = self,
            pathName = pathName,
        };

        await this.inner.DisableMultipathPathAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DisableNetworkBoot_Task(ManagedObjectReference self)
    {
        var req = new DisableNetworkBootRequestType
        {
            _this = self,
        };

        var res = await this.inner.DisableNetworkBoot_TaskAsync(req);

        return res.DisableNetworkBoot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DisableRuleset(ManagedObjectReference self, string id)
    {
        var req = new DisableRulesetRequestType
        {
            _this = self,
            id = id,
        };

        await this.inner.DisableRulesetAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DisableSecondaryVM_Task(ManagedObjectReference self, ManagedObjectReference vm)
    {
        var req = new DisableSecondaryVMRequestType
        {
            _this = self,
            vm = vm,
        };

        var res = await this.inner.DisableSecondaryVM_TaskAsync(req);

        return res.DisableSecondaryVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DisableSmartCardAuthentication(ManagedObjectReference self)
    {
        var req = new DisableSmartCardAuthenticationRequestType
        {
            _this = self,
        };

        await this.inner.DisableSmartCardAuthenticationAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DisconnectHost_Task(ManagedObjectReference self)
    {
        var req = new DisconnectHostRequestType
        {
            _this = self,
        };

        var res = await this.inner.DisconnectHost_TaskAsync(req);

        return res.DisconnectHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DisconnectNvmeController(ManagedObjectReference self, HostNvmeDisconnectSpec disconnectSpec)
    {
        var req = new DisconnectNvmeControllerRequestType
        {
            _this = self,
            disconnectSpec = disconnectSpec,
        };

        await this.inner.DisconnectNvmeControllerAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DisconnectNvmeControllerEx_Task(ManagedObjectReference self, HostNvmeDisconnectSpec[]? disconnectSpec)
    {
        var req = new DisconnectNvmeControllerExRequestType
        {
            _this = self,
            disconnectSpec = disconnectSpec,
        };

        var res = await this.inner.DisconnectNvmeControllerEx_TaskAsync(req);

        return res.DisconnectNvmeControllerEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task DiscoverFcoeHbas(ManagedObjectReference self, FcoeConfigFcoeSpecification fcoeSpec)
    {
        var req = new DiscoverFcoeHbasRequestType
        {
            _this = self,
            fcoeSpec = fcoeSpec,
        };

        await this.inner.DiscoverFcoeHbasAsync(req);
    }

    public async System.Threading.Tasks.Task<HostNvmeDiscoveryLog?> DiscoverNvmeControllers(ManagedObjectReference self, HostNvmeDiscoverSpec discoverSpec)
    {
        var req = new DiscoverNvmeControllersRequestType
        {
            _this = self,
            discoverSpec = discoverSpec,
        };

        var res = await this.inner.DiscoverNvmeControllersAsync(req);

        return res.DiscoverNvmeControllersResponse.returnval;
    }

    public async System.Threading.Tasks.Task DissociateProfile(ManagedObjectReference self, ManagedObjectReference[]? entity)
    {
        var req = new DissociateProfileRequestType
        {
            _this = self,
            entity = entity,
        };

        await this.inner.DissociateProfileAsync(req);
    }

    public async System.Threading.Tasks.Task<bool> DoesCustomizationSpecExist(ManagedObjectReference self, string name)
    {
        var req = new DoesCustomizationSpecExistRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.DoesCustomizationSpecExistAsync(req);

        return res.DoesCustomizationSpecExistResponse.returnval;
    }

    public async System.Threading.Tasks.Task<byte[]?> DownloadDescriptionTree(ManagedObjectReference self)
    {
        var req = new DownloadDescriptionTreeRequestType
        {
            _this = self,
        };

        var res = await this.inner.DownloadDescriptionTreeAsync(req);

        return res.DownloadDescriptionTreeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> DropConnections(ManagedObjectReference self, VirtualMachineConnection[]? listOfConnections)
    {
        var req = new DropConnectionsRequestType
        {
            _this = self,
            listOfConnections = listOfConnections,
        };

        var res = await this.inner.DropConnectionsAsync(req);

        return res.DropConnectionsResponse.returnval;
    }

    public async System.Threading.Tasks.Task DuplicateCustomizationSpec(ManagedObjectReference self, string name, string newName)
    {
        var req = new DuplicateCustomizationSpecRequestType
        {
            _this = self,
            name = name,
            newName = newName,
        };

        await this.inner.DuplicateCustomizationSpecAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DVPortgroupRollback_Task(ManagedObjectReference self, EntityBackupConfig? entityBackup)
    {
        var req = new DVPortgroupRollbackRequestType
        {
            _this = self,
            entityBackup = entityBackup,
        };

        var res = await this.inner.DVPortgroupRollback_TaskAsync(req);

        return res.DVPortgroupRollback_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DVSManagerExportEntity_Task(ManagedObjectReference self, SelectionSet[] selectionSet)
    {
        var req = new DVSManagerExportEntityRequestType
        {
            _this = self,
            selectionSet = selectionSet,
        };

        var res = await this.inner.DVSManagerExportEntity_TaskAsync(req);

        return res.DVSManagerExportEntity_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DVSManagerImportEntity_Task(ManagedObjectReference self, EntityBackupConfig[] entityBackup, string importType)
    {
        var req = new DVSManagerImportEntityRequestType
        {
            _this = self,
            entityBackup = entityBackup,
            importType = importType,
        };

        var res = await this.inner.DVSManagerImportEntity_TaskAsync(req);

        return res.DVSManagerImportEntity_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DVSManagerLookupDvPortGroup(ManagedObjectReference self, string switchUuid, string portgroupKey)
    {
        var req = new DVSManagerLookupDvPortGroupRequestType
        {
            _this = self,
            switchUuid = switchUuid,
            portgroupKey = portgroupKey,
        };

        var res = await this.inner.DVSManagerLookupDvPortGroupAsync(req);

        return res.DVSManagerLookupDvPortGroupResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DvsReconfigureVmVnicNetworkResourcePool_Task(ManagedObjectReference self, DvsVmVnicResourcePoolConfigSpec[] configSpec)
    {
        var req = new DvsReconfigureVmVnicNetworkResourcePoolRequestType
        {
            _this = self,
            configSpec = configSpec,
        };

        var res = await this.inner.DvsReconfigureVmVnicNetworkResourcePool_TaskAsync(req);

        return res.DvsReconfigureVmVnicNetworkResourcePool_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> DVSRollback_Task(ManagedObjectReference self, EntityBackupConfig? entityBackup)
    {
        var req = new DVSRollbackRequestType
        {
            _this = self,
            entityBackup = entityBackup,
        };

        var res = await this.inner.DVSRollback_TaskAsync(req);

        return res.DVSRollback_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> EagerZeroVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new EagerZeroVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.EagerZeroVirtualDisk_TaskAsync(req);

        return res.EagerZeroVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task EmitSyslogMark(ManagedObjectReference self, string message)
    {
        var req = new EmitSyslogMarkRequestType
        {
            _this = self,
            message = message,
        };

        await this.inner.EmitSyslogMarkAsync(req);
    }

    public async System.Threading.Tasks.Task EnableAlarm(ManagedObjectReference self, ManagedObjectReference alarm, ManagedObjectReference entity)
    {
        var req = new EnableAlarmRequestType
        {
            _this = self,
            alarm = alarm,
            entity = entity,
        };

        await this.inner.EnableAlarmAsync(req);
    }

    public async System.Threading.Tasks.Task EnableAlarmActions(ManagedObjectReference self, ManagedObjectReference entity, bool enabled)
    {
        var req = new EnableAlarmActionsRequestType
        {
            _this = self,
            entity = entity,
            enabled = enabled,
        };

        await this.inner.EnableAlarmActionsAsync(req);
    }

    public async System.Threading.Tasks.Task EnableClusteredVmdkSupport(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new EnableClusteredVmdkSupportRequestType
        {
            _this = self,
            datastore = datastore,
        };

        await this.inner.EnableClusteredVmdkSupportAsync(req);
    }

    public async System.Threading.Tasks.Task EnableCrypto(ManagedObjectReference self, CryptoKeyPlain keyPlain)
    {
        var req = new EnableCryptoRequestType
        {
            _this = self,
            keyPlain = keyPlain,
        };

        await this.inner.EnableCryptoAsync(req);
    }

    public async System.Threading.Tasks.Task<bool> EnableFeature(ManagedObjectReference self, ManagedObjectReference? host, string featureKey)
    {
        var req = new EnableFeatureRequestType
        {
            _this = self,
            host = host,
            featureKey = featureKey,
        };

        var res = await this.inner.EnableFeatureAsync(req);

        return res.EnableFeatureResponse.returnval;
    }

    public async System.Threading.Tasks.Task EnableHyperThreading(ManagedObjectReference self)
    {
        var req = new EnableHyperThreadingRequestType
        {
            _this = self,
        };

        await this.inner.EnableHyperThreadingAsync(req);
    }

    public async System.Threading.Tasks.Task EnableMultipathPath(ManagedObjectReference self, string pathName)
    {
        var req = new EnableMultipathPathRequestType
        {
            _this = self,
            pathName = pathName,
        };

        await this.inner.EnableMultipathPathAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> EnableNetworkBoot_Task(ManagedObjectReference self, string networkBootMode)
    {
        var req = new EnableNetworkBootRequestType
        {
            _this = self,
            networkBootMode = networkBootMode,
        };

        var res = await this.inner.EnableNetworkBoot_TaskAsync(req);

        return res.EnableNetworkBoot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task EnableNetworkResourceManagement(ManagedObjectReference self, bool enable)
    {
        var req = new EnableNetworkResourceManagementRequestType
        {
            _this = self,
            enable = enable,
        };

        await this.inner.EnableNetworkResourceManagementAsync(req);
    }

    public async System.Threading.Tasks.Task EnableRuleset(ManagedObjectReference self, string id)
    {
        var req = new EnableRulesetRequestType
        {
            _this = self,
            id = id,
        };

        await this.inner.EnableRulesetAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> EnableSecondaryVM_Task(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? host)
    {
        var req = new EnableSecondaryVMRequestType
        {
            _this = self,
            vm = vm,
            host = host,
        };

        var res = await this.inner.EnableSecondaryVM_TaskAsync(req);

        return res.EnableSecondaryVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task EnableSmartCardAuthentication(ManagedObjectReference self)
    {
        var req = new EnableSmartCardAuthenticationRequestType
        {
            _this = self,
        };

        await this.inner.EnableSmartCardAuthenticationAsync(req);
    }

    public async System.Threading.Tasks.Task EnterLockdownMode(ManagedObjectReference self)
    {
        var req = new EnterLockdownModeRequestType
        {
            _this = self,
        };

        await this.inner.EnterLockdownModeAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> EnterMaintenanceMode_Task(ManagedObjectReference self, int timeout, bool evacuatePoweredOffVms, bool evacuatePoweredOffVmsSpecified, HostMaintenanceSpec? maintenanceSpec)
    {
        var req = new EnterMaintenanceModeRequestType
        {
            _this = self,
            timeout = timeout,
            evacuatePoweredOffVms = evacuatePoweredOffVms,
            evacuatePoweredOffVmsSpecified = evacuatePoweredOffVmsSpecified,
            maintenanceSpec = maintenanceSpec,
        };

        var res = await this.inner.EnterMaintenanceMode_TaskAsync(req);

        return res.EnterMaintenanceMode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DatabaseSizeEstimate?> EstimateDatabaseSize(ManagedObjectReference self, DatabaseSizeParam dbSizeParam)
    {
        var req = new EstimateDatabaseSizeRequestType
        {
            _this = self,
            dbSizeParam = dbSizeParam,
        };

        var res = await this.inner.EstimateDatabaseSizeAsync(req);

        return res.EstimateDatabaseSizeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> EstimateStorageForConsolidateSnapshots_Task(ManagedObjectReference self)
    {
        var req = new EstimateStorageForConsolidateSnapshotsRequestType
        {
            _this = self,
        };

        var res = await this.inner.EstimateStorageForConsolidateSnapshots_TaskAsync(req);

        return res.EstimateStorageForConsolidateSnapshots_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task EsxAgentHostManagerUpdateConfig(ManagedObjectReference self, HostEsxAgentHostManagerConfigInfo configInfo)
    {
        var req = new EsxAgentHostManagerUpdateConfigRequestType
        {
            _this = self,
            configInfo = configInfo,
        };

        await this.inner.EsxAgentHostManagerUpdateConfigAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> EvacuateVsanNode_Task(ManagedObjectReference self, HostMaintenanceSpec maintenanceSpec, int timeout)
    {
        var req = new EvacuateVsanNodeRequestType
        {
            _this = self,
            maintenanceSpec = maintenanceSpec,
            timeout = timeout,
        };

        var res = await this.inner.EvacuateVsanNode_TaskAsync(req);

        return res.EvacuateVsanNode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> EvcManager(ManagedObjectReference self)
    {
        var req = new EvcManagerRequestType
        {
            _this = self,
        };

        var res = await this.inner.EvcManagerAsync(req);

        return res.EvcManagerResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ProfileExecuteResult?> ExecuteHostProfile(ManagedObjectReference self, ManagedObjectReference host, ProfileDeferredPolicyOptionParameter[]? deferredParam)
    {
        var req = new ExecuteHostProfileRequestType
        {
            _this = self,
            host = host,
            deferredParam = deferredParam,
        };

        var res = await this.inner.ExecuteHostProfileAsync(req);

        return res.ExecuteHostProfileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> ExecuteSimpleCommand(ManagedObjectReference self, string[]? arguments)
    {
        var req = new ExecuteSimpleCommandRequestType
        {
            _this = self,
            arguments = arguments,
        };

        var res = await this.inner.ExecuteSimpleCommandAsync(req);

        return res.ExecuteSimpleCommandResponse.returnval;
    }

    public async System.Threading.Tasks.Task ExitLockdownMode(ManagedObjectReference self)
    {
        var req = new ExitLockdownModeRequestType
        {
            _this = self,
        };

        await this.inner.ExitLockdownModeAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExitMaintenanceMode_Task(ManagedObjectReference self, int timeout)
    {
        var req = new ExitMaintenanceModeRequestType
        {
            _this = self,
            timeout = timeout,
        };

        var res = await this.inner.ExitMaintenanceMode_TaskAsync(req);

        return res.ExitMaintenanceMode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExpandVmfsDatastore(ManagedObjectReference self, ManagedObjectReference datastore, VmfsDatastoreExpandSpec spec)
    {
        var req = new ExpandVmfsDatastoreRequestType
        {
            _this = self,
            datastore = datastore,
            spec = spec,
        };

        var res = await this.inner.ExpandVmfsDatastoreAsync(req);

        return res.ExpandVmfsDatastoreResponse.returnval;
    }

    public async System.Threading.Tasks.Task ExpandVmfsExtent(ManagedObjectReference self, string vmfsPath, HostScsiDiskPartition extent)
    {
        var req = new ExpandVmfsExtentRequestType
        {
            _this = self,
            vmfsPath = vmfsPath,
            extent = extent,
        };

        await this.inner.ExpandVmfsExtentAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExportAnswerFile_Task(ManagedObjectReference self, ManagedObjectReference host)
    {
        var req = new ExportAnswerFileRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.ExportAnswerFile_TaskAsync(req);

        return res.ExportAnswerFile_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> ExportProfile(ManagedObjectReference self)
    {
        var req = new ExportProfileRequestType
        {
            _this = self,
        };

        var res = await this.inner.ExportProfileAsync(req);

        return res.ExportProfileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExportSnapshot(ManagedObjectReference self)
    {
        var req = new ExportSnapshotRequestType
        {
            _this = self,
        };

        var res = await this.inner.ExportSnapshotAsync(req);

        return res.ExportSnapshotResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExportVApp(ManagedObjectReference self)
    {
        var req = new ExportVAppRequestType
        {
            _this = self,
        };

        var res = await this.inner.ExportVAppAsync(req);

        return res.ExportVAppResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExportVm(ManagedObjectReference self)
    {
        var req = new ExportVmRequestType
        {
            _this = self,
        };

        var res = await this.inner.ExportVmAsync(req);

        return res.ExportVmResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExtendDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, long newCapacityInMB)
    {
        var req = new ExtendDiskRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            newCapacityInMB = newCapacityInMB,
        };

        var res = await this.inner.ExtendDisk_TaskAsync(req);

        return res.ExtendDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExtendHCI_Task(ManagedObjectReference self, ClusterComputeResourceHostConfigurationInput[]? hostInputs, SDDCBase? vSanConfigSpec)
    {
        var req = new ExtendHCIRequestType
        {
            _this = self,
            hostInputs = hostInputs,
            vSanConfigSpec = vSanConfigSpec,
        };

        var res = await this.inner.ExtendHCI_TaskAsync(req);

        return res.ExtendHCI_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ExtendVffs(ManagedObjectReference self, string vffsPath, string devicePath, HostDiskPartitionSpec? spec)
    {
        var req = new ExtendVffsRequestType
        {
            _this = self,
            vffsPath = vffsPath,
            devicePath = devicePath,
            spec = spec,
        };

        await this.inner.ExtendVffsAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExtendVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, long newCapacityKb, bool eagerZero, bool eagerZeroSpecified)
    {
        var req = new ExtendVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
            newCapacityKb = newCapacityKb,
            eagerZero = eagerZero,
            eagerZeroSpecified = eagerZeroSpecified,
        };

        var res = await this.inner.ExtendVirtualDisk_TaskAsync(req);

        return res.ExtendVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ExtendVmfsDatastore(ManagedObjectReference self, ManagedObjectReference datastore, VmfsDatastoreExtendSpec spec)
    {
        var req = new ExtendVmfsDatastoreRequestType
        {
            _this = self,
            datastore = datastore,
            spec = spec,
        };

        var res = await this.inner.ExtendVmfsDatastoreAsync(req);

        return res.ExtendVmfsDatastoreResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> ExtractOvfEnvironment(ManagedObjectReference self)
    {
        var req = new ExtractOvfEnvironmentRequestType
        {
            _this = self,
        };

        var res = await this.inner.ExtractOvfEnvironmentAsync(req);

        return res.ExtractOvfEnvironmentResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerAuditRecordResult?> FetchAuditRecords(ManagedObjectReference self, string? token)
    {
        var req = new FetchAuditRecordsRequestType
        {
            _this = self,
            token = token,
        };

        var res = await this.inner.FetchAuditRecordsAsync(req);

        return res.FetchAuditRecordsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string[]?> FetchDVPortKeys(ManagedObjectReference self, DistributedVirtualSwitchPortCriteria? criteria)
    {
        var req = new FetchDVPortKeysRequestType
        {
            _this = self,
            criteria = criteria,
        };

        var res = await this.inner.FetchDVPortKeysAsync(req);

        return res.FetchDVPortKeysResponse1;
    }

    public async System.Threading.Tasks.Task<DistributedVirtualPort[]?> FetchDVPorts(ManagedObjectReference self, DistributedVirtualSwitchPortCriteria? criteria)
    {
        var req = new FetchDVPortsRequestType
        {
            _this = self,
            criteria = criteria,
        };

        var res = await this.inner.FetchDVPortsAsync(req);

        return res.FetchDVPortsResponse1;
    }

    public async System.Threading.Tasks.Task<SoftwarePackage[]?> FetchSoftwarePackages(ManagedObjectReference self)
    {
        var req = new fetchSoftwarePackagesRequestType
        {
            _this = self,
        };

        var res = await this.inner.fetchSoftwarePackagesAsync(req);

        return res.fetchSoftwarePackagesResponse1;
    }

    public async System.Threading.Tasks.Task<SystemEventInfo[]?> FetchSystemEventLog(ManagedObjectReference self)
    {
        var req = new FetchSystemEventLogRequestType
        {
            _this = self,
        };

        var res = await this.inner.FetchSystemEventLogAsync(req);

        return res.FetchSystemEventLogResponse1;
    }

    public async System.Threading.Tasks.Task<UserPrivilegeResult[]?> FetchUserPrivilegeOnEntities(ManagedObjectReference self, ManagedObjectReference[] entities, string userName)
    {
        var req = new FetchUserPrivilegeOnEntitiesRequestType
        {
            _this = self,
            entities = entities,
            userName = userName,
        };

        var res = await this.inner.FetchUserPrivilegeOnEntitiesAsync(req);

        return res.FetchUserPrivilegeOnEntitiesResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAllByDnsName(ManagedObjectReference self, ManagedObjectReference? datacenter, string dnsName, bool vmSearch)
    {
        var req = new FindAllByDnsNameRequestType
        {
            _this = self,
            datacenter = datacenter,
            dnsName = dnsName,
            vmSearch = vmSearch,
        };

        var res = await this.inner.FindAllByDnsNameAsync(req);

        return res.FindAllByDnsNameResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAllByIp(ManagedObjectReference self, ManagedObjectReference? datacenter, string ip, bool vmSearch)
    {
        var req = new FindAllByIpRequestType
        {
            _this = self,
            datacenter = datacenter,
            ip = ip,
            vmSearch = vmSearch,
        };

        var res = await this.inner.FindAllByIpAsync(req);

        return res.FindAllByIpResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAllByUuid(ManagedObjectReference self, ManagedObjectReference? datacenter, string uuid, bool vmSearch, bool instanceUuid, bool instanceUuidSpecified)
    {
        var req = new FindAllByUuidRequestType
        {
            _this = self,
            datacenter = datacenter,
            uuid = uuid,
            vmSearch = vmSearch,
            instanceUuid = instanceUuid,
            instanceUuidSpecified = instanceUuidSpecified,
        };

        var res = await this.inner.FindAllByUuidAsync(req);

        return res.FindAllByUuidResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> FindAssociatedProfile(ManagedObjectReference self, ManagedObjectReference entity)
    {
        var req = new FindAssociatedProfileRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.FindAssociatedProfileAsync(req);

        return res.FindAssociatedProfileResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> FindByDatastorePath(ManagedObjectReference self, ManagedObjectReference datacenter, string path)
    {
        var req = new FindByDatastorePathRequestType
        {
            _this = self,
            datacenter = datacenter,
            path = path,
        };

        var res = await this.inner.FindByDatastorePathAsync(req);

        return res.FindByDatastorePathResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> FindByDnsName(ManagedObjectReference self, ManagedObjectReference? datacenter, string dnsName, bool vmSearch)
    {
        var req = new FindByDnsNameRequestType
        {
            _this = self,
            datacenter = datacenter,
            dnsName = dnsName,
            vmSearch = vmSearch,
        };

        var res = await this.inner.FindByDnsNameAsync(req);

        return res.FindByDnsNameResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> FindByInventoryPath(ManagedObjectReference self, string inventoryPath)
    {
        var req = new FindByInventoryPathRequestType
        {
            _this = self,
            inventoryPath = inventoryPath,
        };

        var res = await this.inner.FindByInventoryPathAsync(req);

        return res.FindByInventoryPathResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> FindByIp(ManagedObjectReference self, ManagedObjectReference? datacenter, string ip, bool vmSearch)
    {
        var req = new FindByIpRequestType
        {
            _this = self,
            datacenter = datacenter,
            ip = ip,
            vmSearch = vmSearch,
        };

        var res = await this.inner.FindByIpAsync(req);

        return res.FindByIpResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> FindByUuid(ManagedObjectReference self, ManagedObjectReference? datacenter, string uuid, bool vmSearch, bool instanceUuid, bool instanceUuidSpecified)
    {
        var req = new FindByUuidRequestType
        {
            _this = self,
            datacenter = datacenter,
            uuid = uuid,
            vmSearch = vmSearch,
            instanceUuid = instanceUuid,
            instanceUuidSpecified = instanceUuidSpecified,
        };

        var res = await this.inner.FindByUuidAsync(req);

        return res.FindByUuidResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> FindChild(ManagedObjectReference self, ManagedObjectReference entity, string name)
    {
        var req = new FindChildRequestType
        {
            _this = self,
            entity = entity,
            name = name,
        };

        var res = await this.inner.FindChildAsync(req);

        return res.FindChildResponse.returnval;
    }

    public async System.Threading.Tasks.Task<Extension?> FindExtension(ManagedObjectReference self, string extensionKey)
    {
        var req = new FindExtensionRequestType
        {
            _this = self,
            extensionKey = extensionKey,
        };

        var res = await this.inner.FindExtensionAsync(req);

        return res.FindExtensionResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ClusterRuleInfo[]?> FindRulesForVm(ManagedObjectReference self, ManagedObjectReference vm)
    {
        var req = new FindRulesForVmRequestType
        {
            _this = self,
            vm = vm,
        };

        var res = await this.inner.FindRulesForVmAsync(req);

        return res.FindRulesForVmResponse1;
    }

    public async System.Threading.Tasks.Task<HostVffsVolume?> FormatVffs(ManagedObjectReference self, HostVffsSpec createSpec)
    {
        var req = new FormatVffsRequestType
        {
            _this = self,
            createSpec = createSpec,
        };

        var res = await this.inner.FormatVffsAsync(req);

        return res.FormatVffsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostVmfsVolume?> FormatVmfs(ManagedObjectReference self, HostVmfsSpec createSpec)
    {
        var req = new FormatVmfsRequestType
        {
            _this = self,
            createSpec = createSpec,
        };

        var res = await this.inner.FormatVmfsAsync(req);

        return res.FormatVmfsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequest(ManagedObjectReference self, bool useIpAddressAsCommonName, HostCertificateManagerCertificateSpec? spec)
    {
        var req = new GenerateCertificateSigningRequestRequestType
        {
            _this = self,
            useIpAddressAsCommonName = useIpAddressAsCommonName,
            spec = spec,
        };

        var res = await this.inner.GenerateCertificateSigningRequestAsync(req);

        return res.GenerateCertificateSigningRequestResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> GenerateCertificateSigningRequestByDn(ManagedObjectReference self, string distinguishedName, HostCertificateManagerCertificateSpec? spec)
    {
        var req = new GenerateCertificateSigningRequestByDnRequestType
        {
            _this = self,
            distinguishedName = distinguishedName,
            spec = spec,
        };

        var res = await this.inner.GenerateCertificateSigningRequestByDnAsync(req);

        return res.GenerateCertificateSigningRequestByDnResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> GenerateClientCsr(ManagedObjectReference self, KeyProviderId cluster, CryptoManagerKmipCertSignRequest? request)
    {
        var req = new GenerateClientCsrRequestType
        {
            _this = self,
            cluster = cluster,
            request = request,
        };

        var res = await this.inner.GenerateClientCsrAsync(req);

        return res.GenerateClientCsrResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostProfileManagerConfigTaskList?> GenerateConfigTaskList(ManagedObjectReference self, HostConfigSpec configSpec, ManagedObjectReference host)
    {
        var req = new GenerateConfigTaskListRequestType
        {
            _this = self,
            configSpec = configSpec,
            host = host,
        };

        var res = await this.inner.GenerateConfigTaskListAsync(req);

        return res.GenerateConfigTaskListResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> GenerateHostConfigTaskSpec_Task(ManagedObjectReference self, StructuredCustomizations[]? hostsInfo)
    {
        var req = new GenerateHostConfigTaskSpecRequestType
        {
            _this = self,
            hostsInfo = hostsInfo,
        };

        var res = await this.inner.GenerateHostConfigTaskSpec_TaskAsync(req);

        return res.GenerateHostConfigTaskSpec_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> GenerateHostProfileTaskList_Task(ManagedObjectReference self, HostConfigSpec configSpec, ManagedObjectReference host)
    {
        var req = new GenerateHostProfileTaskListRequestType
        {
            _this = self,
            configSpec = configSpec,
            host = host,
        };

        var res = await this.inner.GenerateHostProfileTaskList_TaskAsync(req);

        return res.GenerateHostProfileTaskList_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult?> GenerateKey(ManagedObjectReference self, KeyProviderId? keyProvider, CryptoManagerKmipCustomAttributeSpec? spec, CryptoManagerKmipGenerateKeySpec? keySpec)
    {
        var req = new GenerateKeyRequestType
        {
            _this = self,
            keyProvider = keyProvider,
            spec = spec,
            keySpec = keySpec,
        };

        var res = await this.inner.GenerateKeyAsync(req);

        return res.GenerateKeyResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> GenerateLogBundles_Task(ManagedObjectReference self, bool includeDefault, ManagedObjectReference[]? host)
    {
        var req = new GenerateLogBundlesRequestType
        {
            _this = self,
            includeDefault = includeDefault,
            host = host,
        };

        var res = await this.inner.GenerateLogBundles_TaskAsync(req);

        return res.GenerateLogBundles_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> GenerateSelfSignedClientCert(ManagedObjectReference self, KeyProviderId cluster, CryptoManagerKmipCertSignRequest? request)
    {
        var req = new GenerateSelfSignedClientCertRequestType
        {
            _this = self,
            cluster = cluster,
            request = request,
        };

        var res = await this.inner.GenerateSelfSignedClientCertAsync(req);

        return res.GenerateSelfSignedClientCertResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> GetAlarm(ManagedObjectReference self, ManagedObjectReference? entity)
    {
        var req = new GetAlarmRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.GetAlarmAsync(req);

        return res.GetAlarmResponse1;
    }

    public async System.Threading.Tasks.Task<AlarmState[]?> GetAlarmState(ManagedObjectReference self, ManagedObjectReference entity)
    {
        var req = new GetAlarmStateRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.GetAlarmStateAsync(req);

        return res.GetAlarmStateResponse1;
    }

    public async System.Threading.Tasks.Task<string?> GetClusterMode(ManagedObjectReference self)
    {
        var req = new getClusterModeRequestType
        {
            _this = self,
        };

        var res = await this.inner.getClusterModeAsync(req);

        return res.getClusterModeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<CryptoManagerHostKeyStatus[]?> GetCryptoKeyStatus(ManagedObjectReference self, CryptoKeyId[]? keys)
    {
        var req = new GetCryptoKeyStatusRequestType
        {
            _this = self,
            keys = keys,
        };

        var res = await this.inner.GetCryptoKeyStatusAsync(req);

        return res.GetCryptoKeyStatusResponse1;
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem?> GetCustomizationSpec(ManagedObjectReference self, string name)
    {
        var req = new GetCustomizationSpecRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.GetCustomizationSpecAsync(req);

        return res.GetCustomizationSpecResponse.returnval;
    }

    public async System.Threading.Tasks.Task<KeyProviderId?> GetDefaultKmsCluster(ManagedObjectReference self, ManagedObjectReference? entity, bool defaultsToParent, bool defaultsToParentSpecified)
    {
        var req = new GetDefaultKmsClusterRequestType
        {
            _this = self,
            entity = entity,
            defaultsToParent = defaultsToParent,
            defaultsToParentSpecified = defaultsToParentSpecified,
        };

        var res = await this.inner.GetDefaultKmsClusterAsync(req);

        return res.GetDefaultKmsClusterResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> GetPublicKey(ManagedObjectReference self)
    {
        var req = new GetPublicKeyRequestType
        {
            _this = self,
        };

        var res = await this.inner.GetPublicKeyAsync(req);

        return res.GetPublicKeyResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ClusterResourceUsageSummary?> GetResourceUsage(ManagedObjectReference self)
    {
        var req = new GetResourceUsageRequestType
        {
            _this = self,
        };

        var res = await this.inner.GetResourceUsageAsync(req);

        return res.GetResourceUsageResponse.returnval;
    }

    public async System.Threading.Tasks.Task<SiteInfo?> GetSiteInfo(ManagedObjectReference self)
    {
        var req = new GetSiteInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.GetSiteInfoAsync(req);

        return res.GetSiteInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> GetSystemVMsRestrictedDatastores(ManagedObjectReference self)
    {
        var req = new GetSystemVMsRestrictedDatastoresRequestType
        {
            _this = self,
        };

        var res = await this.inner.GetSystemVMsRestrictedDatastoresAsync(req);

        return res.GetSystemVMsRestrictedDatastoresResponse1;
    }

    public async System.Threading.Tasks.Task<VchaClusterHealth?> GetVchaClusterHealth(ManagedObjectReference self)
    {
        var req = new GetVchaClusterHealthRequestType
        {
            _this = self,
        };

        var res = await this.inner.GetVchaClusterHealthAsync(req);

        return res.GetVchaClusterHealthResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VchaClusterConfigInfo?> GetVchaConfig(ManagedObjectReference self)
    {
        var req = new getVchaConfigRequestType
        {
            _this = self,
        };

        var res = await this.inner.getVchaConfigAsync(req);

        return res.getVchaConfigResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> GetVsanObjExtAttrs(ManagedObjectReference self, string[] uuids)
    {
        var req = new GetVsanObjExtAttrsRequestType
        {
            _this = self,
            uuids = uuids,
        };

        var res = await this.inner.GetVsanObjExtAttrsAsync(req);

        return res.GetVsanObjExtAttrsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> HasMonitoredEntity(ManagedObjectReference self, string providerId, ManagedObjectReference entity)
    {
        var req = new HasMonitoredEntityRequestType
        {
            _this = self,
            providerId = providerId,
            entity = entity,
        };

        var res = await this.inner.HasMonitoredEntityAsync(req);

        return res.HasMonitoredEntityResponse.returnval;
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]?> HasPrivilegeOnEntities(ManagedObjectReference self, ManagedObjectReference[] entity, string sessionId, string[]? privId)
    {
        var req = new HasPrivilegeOnEntitiesRequestType
        {
            _this = self,
            entity = entity,
            sessionId = sessionId,
            privId = privId,
        };

        var res = await this.inner.HasPrivilegeOnEntitiesAsync(req);

        return res.HasPrivilegeOnEntitiesResponse1;
    }

    public async System.Threading.Tasks.Task<bool[]?> HasPrivilegeOnEntity(ManagedObjectReference self, ManagedObjectReference entity, string sessionId, string[]? privId)
    {
        var req = new HasPrivilegeOnEntityRequestType
        {
            _this = self,
            entity = entity,
            sessionId = sessionId,
            privId = privId,
        };

        var res = await this.inner.HasPrivilegeOnEntityAsync(req);

        return res.HasPrivilegeOnEntityResponse1;
    }

    public async System.Threading.Tasks.Task<bool> HasProvider(ManagedObjectReference self, string id)
    {
        var req = new HasProviderRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.HasProviderAsync(req);

        return res.HasProviderResponse.returnval;
    }

    public async System.Threading.Tasks.Task<EntityPrivilege[]?> HasUserPrivilegeOnEntities(ManagedObjectReference self, ManagedObjectReference[] entities, string userName, string[]? privId)
    {
        var req = new HasUserPrivilegeOnEntitiesRequestType
        {
            _this = self,
            entities = entities,
            userName = userName,
            privId = privId,
        };

        var res = await this.inner.HasUserPrivilegeOnEntitiesAsync(req);

        return res.HasUserPrivilegeOnEntitiesResponse1;
    }

    public async System.Threading.Tasks.Task HostClearVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags)
    {
        var req = new HostClearVStorageObjectControlFlagsRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            controlFlags = controlFlags,
        };

        await this.inner.HostClearVStorageObjectControlFlagsAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostCloneVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmCloneSpec spec)
    {
        var req = new HostCloneVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            spec = spec,
        };

        var res = await this.inner.HostCloneVStorageObject_TaskAsync(req);

        return res.HostCloneVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task HostConfigureVFlashResource(ManagedObjectReference self, HostVFlashManagerVFlashResourceConfigSpec spec)
    {
        var req = new HostConfigureVFlashResourceRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.HostConfigureVFlashResourceAsync(req);
    }

    public async System.Threading.Tasks.Task HostConfigVFlashCache(ManagedObjectReference self, HostVFlashManagerVFlashCacheConfigSpec spec)
    {
        var req = new HostConfigVFlashCacheRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.HostConfigVFlashCacheAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostCreateDisk_Task(ManagedObjectReference self, VslmCreateSpec spec)
    {
        var req = new HostCreateDiskRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.HostCreateDisk_TaskAsync(req);

        return res.HostCreateDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostDeleteVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new HostDeleteVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.HostDeleteVStorageObject_TaskAsync(req);

        return res.HostDeleteVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostDeleteVStorageObjectEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new HostDeleteVStorageObjectExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.HostDeleteVStorageObjectEx_TaskAsync(req);

        return res.HostDeleteVStorageObjectEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostExtendDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, long newCapacityInMB)
    {
        var req = new HostExtendDiskRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            newCapacityInMB = newCapacityInMB,
        };

        var res = await this.inner.HostExtendDisk_TaskAsync(req);

        return res.HostExtendDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VirtualDiskVFlashCacheConfigInfo?> HostGetVFlashModuleDefaultConfig(ManagedObjectReference self, string vFlashModule)
    {
        var req = new HostGetVFlashModuleDefaultConfigRequestType
        {
            _this = self,
            vFlashModule = vFlashModule,
        };

        var res = await this.inner.HostGetVFlashModuleDefaultConfigAsync(req);

        return res.HostGetVFlashModuleDefaultConfigResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> HostImageConfigGetAcceptance(ManagedObjectReference self)
    {
        var req = new HostImageConfigGetAcceptanceRequestType
        {
            _this = self,
        };

        var res = await this.inner.HostImageConfigGetAcceptanceAsync(req);

        return res.HostImageConfigGetAcceptanceResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostImageProfileSummary?> HostImageConfigGetProfile(ManagedObjectReference self)
    {
        var req = new HostImageConfigGetProfileRequestType
        {
            _this = self,
        };

        var res = await this.inner.HostImageConfigGetProfileAsync(req);

        return res.HostImageConfigGetProfileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostInflateDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new HostInflateDiskRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.HostInflateDisk_TaskAsync(req);

        return res.HostInflateDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ID[]?> HostListVStorageObject(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new HostListVStorageObjectRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.HostListVStorageObjectAsync(req);

        return res.HostListVStorageObjectResponse1;
    }

    public async System.Threading.Tasks.Task HostProfileResetValidationState(ManagedObjectReference self)
    {
        var req = new HostProfileResetValidationStateRequestType
        {
            _this = self,
        };

        await this.inner.HostProfileResetValidationStateAsync(req);
    }

    public async System.Threading.Tasks.Task<string?> HostQueryVirtualDiskUuid(ManagedObjectReference self, string name)
    {
        var req = new HostQueryVirtualDiskUuidRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.HostQueryVirtualDiskUuidAsync(req);

        return res.HostQueryVirtualDiskUuidResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostReconcileDatastoreInventory_Task(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified)
    {
        var req = new HostReconcileDatastoreInventoryRequestType
        {
            _this = self,
            datastore = datastore,
            deepCleansing = deepCleansing,
            deepCleansingSpecified = deepCleansingSpecified,
        };

        var res = await this.inner.HostReconcileDatastoreInventory_TaskAsync(req);

        return res.HostReconcileDatastoreInventory_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObject?> HostRegisterDisk(ManagedObjectReference self, string path, string? name, bool modifyControlFlags, bool modifyControlFlagsSpecified)
    {
        var req = new HostRegisterDiskRequestType
        {
            _this = self,
            path = path,
            name = name,
            modifyControlFlags = modifyControlFlags,
            modifyControlFlagsSpecified = modifyControlFlagsSpecified,
        };

        var res = await this.inner.HostRegisterDiskAsync(req);

        return res.HostRegisterDiskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostRelocateVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmRelocateSpec spec)
    {
        var req = new HostRelocateVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            spec = spec,
        };

        var res = await this.inner.HostRelocateVStorageObject_TaskAsync(req);

        return res.HostRelocateVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task HostRemoveVFlashResource(ManagedObjectReference self)
    {
        var req = new HostRemoveVFlashResourceRequestType
        {
            _this = self,
        };

        await this.inner.HostRemoveVFlashResourceAsync(req);
    }

    public async System.Threading.Tasks.Task HostRenameVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string name)
    {
        var req = new HostRenameVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            name = name,
        };

        await this.inner.HostRenameVStorageObjectAsync(req);
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> HostRetrieveVStorageInfrastructureObjectPolicy(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new HostRetrieveVStorageInfrastructureObjectPolicyRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.HostRetrieveVStorageInfrastructureObjectPolicyAsync(req);

        return res.HostRetrieveVStorageInfrastructureObjectPolicyResponse1;
    }

    public async System.Threading.Tasks.Task<VStorageObject?> HostRetrieveVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? diskInfoFlags)
    {
        var req = new HostRetrieveVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            diskInfoFlags = diskInfoFlags,
        };

        var res = await this.inner.HostRetrieveVStorageObjectAsync(req);

        return res.HostRetrieveVStorageObjectResponse.returnval;
    }

    public async System.Threading.Tasks.Task<KeyValue[]?> HostRetrieveVStorageObjectMetadata(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID? snapshotId, string? prefix)
    {
        var req = new HostRetrieveVStorageObjectMetadataRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
            prefix = prefix,
        };

        var res = await this.inner.HostRetrieveVStorageObjectMetadataAsync(req);

        return res.HostRetrieveVStorageObjectMetadataResponse1;
    }

    public async System.Threading.Tasks.Task<string?> HostRetrieveVStorageObjectMetadataValue(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID? snapshotId, string key)
    {
        var req = new HostRetrieveVStorageObjectMetadataValueRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
            key = key,
        };

        var res = await this.inner.HostRetrieveVStorageObjectMetadataValueAsync(req);

        return res.HostRetrieveVStorageObjectMetadataValueResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> HostRetrieveVStorageObjectState(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new HostRetrieveVStorageObjectStateRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.HostRetrieveVStorageObjectStateAsync(req);

        return res.HostRetrieveVStorageObjectStateResponse.returnval;
    }

    public async System.Threading.Tasks.Task HostScheduleReconcileDatastoreInventory(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified)
    {
        var req = new HostScheduleReconcileDatastoreInventoryRequestType
        {
            _this = self,
            datastore = datastore,
            deepCleansing = deepCleansing,
            deepCleansingSpecified = deepCleansingSpecified,
        };

        await this.inner.HostScheduleReconcileDatastoreInventoryAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostSetVirtualDiskUuid_Task(ManagedObjectReference self, string name, string? uuid)
    {
        var req = new HostSetVirtualDiskUuidRequestType
        {
            _this = self,
            name = name,
            uuid = uuid,
        };

        var res = await this.inner.HostSetVirtualDiskUuid_TaskAsync(req);

        return res.HostSetVirtualDiskUuid_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task HostSetVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags)
    {
        var req = new HostSetVStorageObjectControlFlagsRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            controlFlags = controlFlags,
        };

        await this.inner.HostSetVStorageObjectControlFlagsAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> HostSpecGetUpdatedHosts(ManagedObjectReference self, string? startChangeID, string? endChangeID)
    {
        var req = new HostSpecGetUpdatedHostsRequestType
        {
            _this = self,
            startChangeID = startChangeID,
            endChangeID = endChangeID,
        };

        var res = await this.inner.HostSpecGetUpdatedHostsAsync(req);

        return res.HostSpecGetUpdatedHostsResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostUpdateVStorageObjectMetadata_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var req = new HostUpdateVStorageObjectMetadataRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            metadata = metadata,
            deleteKeys = deleteKeys,
        };

        var res = await this.inner.HostUpdateVStorageObjectMetadata_TaskAsync(req);

        return res.HostUpdateVStorageObjectMetadata_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostUpdateVStorageObjectMetadataEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var req = new HostUpdateVStorageObjectMetadataExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            metadata = metadata,
            deleteKeys = deleteKeys,
        };

        var res = await this.inner.HostUpdateVStorageObjectMetadataEx_TaskAsync(req);

        return res.HostUpdateVStorageObjectMetadataEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectCreateDiskFromSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId, string name, VirtualMachineProfileSpec[]? profile, CryptoSpec? crypto, string? path, string? provisioningType)
    {
        var req = new HostVStorageObjectCreateDiskFromSnapshotRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
            name = name,
            profile = profile,
            crypto = crypto,
            path = path,
            provisioningType = provisioningType,
        };

        var res = await this.inner.HostVStorageObjectCreateDiskFromSnapshot_TaskAsync(req);

        return res.HostVStorageObjectCreateDiskFromSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectCreateSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string description)
    {
        var req = new HostVStorageObjectCreateSnapshotRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            description = description,
        };

        var res = await this.inner.HostVStorageObjectCreateSnapshot_TaskAsync(req);

        return res.HostVStorageObjectCreateSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectDeleteSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new HostVStorageObjectDeleteSnapshotRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.HostVStorageObjectDeleteSnapshot_TaskAsync(req);

        return res.HostVStorageObjectDeleteSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> HostVStorageObjectRetrieveSnapshotInfo(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new HostVStorageObjectRetrieveSnapshotInfoRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.HostVStorageObjectRetrieveSnapshotInfoAsync(req);

        return res.HostVStorageObjectRetrieveSnapshotInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HostVStorageObjectRevert_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new HostVStorageObjectRevertRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.HostVStorageObjectRevert_TaskAsync(req);

        return res.HostVStorageObjectRevert_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseAbort(ManagedObjectReference self, LocalizedMethodFault? fault)
    {
        var req = new HttpNfcLeaseAbortRequestType
        {
            _this = self,
            fault = fault,
        };

        await this.inner.HttpNfcLeaseAbortAsync(req);
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseComplete(ManagedObjectReference self)
    {
        var req = new HttpNfcLeaseCompleteRequestType
        {
            _this = self,
        };

        await this.inner.HttpNfcLeaseCompleteAsync(req);
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseManifestEntry[]?> HttpNfcLeaseGetManifest(ManagedObjectReference self)
    {
        var req = new HttpNfcLeaseGetManifestRequestType
        {
            _this = self,
        };

        var res = await this.inner.HttpNfcLeaseGetManifestAsync(req);

        return res.HttpNfcLeaseGetManifestResponse1;
    }

    public async System.Threading.Tasks.Task<HttpNfcLeaseProbeResult[]?> HttpNfcLeaseProbeUrls(ManagedObjectReference self, HttpNfcLeaseSourceFile[]? files, int timeout, bool timeoutSpecified)
    {
        var req = new HttpNfcLeaseProbeUrlsRequestType
        {
            _this = self,
            files = files,
            timeout = timeout,
            timeoutSpecified = timeoutSpecified,
        };

        var res = await this.inner.HttpNfcLeaseProbeUrlsAsync(req);

        return res.HttpNfcLeaseProbeUrlsResponse1;
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseProgress(ManagedObjectReference self, int percent)
    {
        var req = new HttpNfcLeaseProgressRequestType
        {
            _this = self,
            percent = percent,
        };

        await this.inner.HttpNfcLeaseProgressAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> HttpNfcLeasePullFromUrls_Task(ManagedObjectReference self, HttpNfcLeaseSourceFile[]? files)
    {
        var req = new HttpNfcLeasePullFromUrlsRequestType
        {
            _this = self,
            files = files,
        };

        var res = await this.inner.HttpNfcLeasePullFromUrls_TaskAsync(req);

        return res.HttpNfcLeasePullFromUrls_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task HttpNfcLeaseSetManifestChecksumType(ManagedObjectReference self, KeyValue[]? deviceUrlsToChecksumTypes)
    {
        var req = new HttpNfcLeaseSetManifestChecksumTypeRequestType
        {
            _this = self,
            deviceUrlsToChecksumTypes = deviceUrlsToChecksumTypes,
        };

        await this.inner.HttpNfcLeaseSetManifestChecksumTypeAsync(req);
    }

    public async System.Threading.Tasks.Task<UserSession?> ImpersonateUser(ManagedObjectReference self, string userName, string? locale)
    {
        var req = new ImpersonateUserRequestType
        {
            _this = self,
            userName = userName,
            locale = locale,
        };

        var res = await this.inner.ImpersonateUserAsync(req);

        return res.ImpersonateUserResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ImportCertificateForCAM_Task(ManagedObjectReference self, string certPath, string camServer)
    {
        var req = new ImportCertificateForCAMRequestType
        {
            _this = self,
            certPath = certPath,
            camServer = camServer,
        };

        var res = await this.inner.ImportCertificateForCAM_TaskAsync(req);

        return res.ImportCertificateForCAM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ImportUnmanagedSnapshot(ManagedObjectReference self, string vdisk, ManagedObjectReference? datacenter, string vvolId)
    {
        var req = new ImportUnmanagedSnapshotRequestType
        {
            _this = self,
            vdisk = vdisk,
            datacenter = datacenter,
            vvolId = vvolId,
        };

        await this.inner.ImportUnmanagedSnapshotAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ImportVApp(ManagedObjectReference self, ImportSpec spec, ManagedObjectReference? folder, ManagedObjectReference? host)
    {
        var req = new ImportVAppRequestType
        {
            _this = self,
            spec = spec,
            folder = folder,
            host = host,
        };

        var res = await this.inner.ImportVAppAsync(req);

        return res.ImportVAppResponse.returnval;
    }

    public async System.Threading.Tasks.Task IncreaseDirectorySize(ManagedObjectReference self, ManagedObjectReference? datacenter, string stableName, long size)
    {
        var req = new IncreaseDirectorySizeRequestType
        {
            _this = self,
            datacenter = datacenter,
            stableName = stableName,
            size = size,
        };

        await this.inner.IncreaseDirectorySizeAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InflateDisk_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new InflateDiskRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.InflateDisk_TaskAsync(req);

        return res.InflateDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InflateVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new InflateVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.InflateVirtualDisk_TaskAsync(req);

        return res.InflateVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InitializeDisks_Task(ManagedObjectReference self, VsanHostDiskMapping[] mapping)
    {
        var req = new InitializeDisksRequestType
        {
            _this = self,
            mapping = mapping,
        };

        var res = await this.inner.InitializeDisks_TaskAsync(req);

        return res.InitializeDisks_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InitiateFailover_Task(ManagedObjectReference self, bool planned)
    {
        var req = new initiateFailoverRequestType
        {
            _this = self,
            planned = planned,
        };

        var res = await this.inner.initiateFailover_TaskAsync(req);

        return res.initiateFailover_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<FileTransferInformation?> InitiateFileTransferFromGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string guestFilePath)
    {
        var req = new InitiateFileTransferFromGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            guestFilePath = guestFilePath,
        };

        var res = await this.inner.InitiateFileTransferFromGuestAsync(req);

        return res.InitiateFileTransferFromGuestResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> InitiateFileTransferToGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string guestFilePath, GuestFileAttributes fileAttributes, long fileSize, bool overwrite)
    {
        var req = new InitiateFileTransferToGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            guestFilePath = guestFilePath,
            fileAttributes = fileAttributes,
            fileSize = fileSize,
            overwrite = overwrite,
        };

        var res = await this.inner.InitiateFileTransferToGuestAsync(req);

        return res.InitiateFileTransferToGuestResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InitiateTransitionToVLCM_Task(ManagedObjectReference self, ManagedObjectReference cluster)
    {
        var req = new InitiateTransitionToVLCMRequestType
        {
            _this = self,
            cluster = cluster,
        };

        var res = await this.inner.InitiateTransitionToVLCM_TaskAsync(req);

        return res.InitiateTransitionToVLCM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DateTime> InstallDate(ManagedObjectReference self)
    {
        var req = new installDateRequestType
        {
            _this = self,
        };

        var res = await this.inner.installDateAsync(req);

        return res.installDateResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InstallHostPatch_Task(ManagedObjectReference self, HostPatchManagerLocator repository, string updateID, bool force, bool forceSpecified)
    {
        var req = new InstallHostPatchRequestType
        {
            _this = self,
            repository = repository,
            updateID = updateID,
            force = force,
            forceSpecified = forceSpecified,
        };

        var res = await this.inner.InstallHostPatch_TaskAsync(req);

        return res.InstallHostPatch_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InstallHostPatchV2_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var req = new InstallHostPatchV2RequestType
        {
            _this = self,
            metaUrls = metaUrls,
            bundleUrls = bundleUrls,
            vibUrls = vibUrls,
            spec = spec,
        };

        var res = await this.inner.InstallHostPatchV2_TaskAsync(req);

        return res.InstallHostPatchV2_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InstallIoFilter_Task(ManagedObjectReference self, string vibUrl, ManagedObjectReference compRes, IoFilterManagerSslTrust? vibSslTrust)
    {
        var req = new InstallIoFilterRequestType
        {
            _this = self,
            vibUrl = vibUrl,
            compRes = compRes,
            vibSslTrust = vibSslTrust,
        };

        var res = await this.inner.InstallIoFilter_TaskAsync(req);

        return res.InstallIoFilter_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task InstallServerCertificate(ManagedObjectReference self, string cert)
    {
        var req = new InstallServerCertificateRequestType
        {
            _this = self,
            cert = cert,
        };

        await this.inner.InstallServerCertificateAsync(req);
    }

    public async System.Threading.Tasks.Task InstallSmartCardTrustAnchor(ManagedObjectReference self, string cert)
    {
        var req = new InstallSmartCardTrustAnchorRequestType
        {
            _this = self,
            cert = cert,
        };

        await this.inner.InstallSmartCardTrustAnchorAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> InstantClone_Task(ManagedObjectReference self, VirtualMachineInstantCloneSpec spec)
    {
        var req = new InstantCloneRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.InstantClone_TaskAsync(req);

        return res.InstantClone_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> IsClusteredVmdkEnabled(ManagedObjectReference self)
    {
        var req = new IsClusteredVmdkEnabledRequestType
        {
            _this = self,
        };

        var res = await this.inner.IsClusteredVmdkEnabledAsync(req);

        return res.IsClusteredVmdkEnabledResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> IsGuestOsCustomizable(ManagedObjectReference self, string guestId)
    {
        var req = new IsGuestOsCustomizableRequestType
        {
            _this = self,
            guestId = guestId,
        };

        var res = await this.inner.IsGuestOsCustomizableAsync(req);

        return res.IsGuestOsCustomizableResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> IsKmsClusterActive(ManagedObjectReference self, KeyProviderId? cluster)
    {
        var req = new IsKmsClusterActiveRequestType
        {
            _this = self,
            cluster = cluster,
        };

        var res = await this.inner.IsKmsClusterActiveAsync(req);

        return res.IsKmsClusterActiveResponse.returnval;
    }

    public async System.Threading.Tasks.Task<bool> IsSharedGraphicsActive(ManagedObjectReference self)
    {
        var req = new IsSharedGraphicsActiveRequestType
        {
            _this = self,
        };

        var res = await this.inner.IsSharedGraphicsActiveAsync(req);

        return res.IsSharedGraphicsActiveResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> JoinDomain_Task(ManagedObjectReference self, string domainName, string userName, string password)
    {
        var req = new JoinDomainRequestType
        {
            _this = self,
            domainName = domainName,
            userName = userName,
            password = password,
        };

        var res = await this.inner.JoinDomain_TaskAsync(req);

        return res.JoinDomain_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> JoinDomainWithCAM_Task(ManagedObjectReference self, string domainName, string camServer)
    {
        var req = new JoinDomainWithCAMRequestType
        {
            _this = self,
            domainName = domainName,
            camServer = camServer,
        };

        var res = await this.inner.JoinDomainWithCAM_TaskAsync(req);

        return res.JoinDomainWithCAM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> LeaveCurrentDomain_Task(ManagedObjectReference self, bool force)
    {
        var req = new LeaveCurrentDomainRequestType
        {
            _this = self,
            force = force,
        };

        var res = await this.inner.LeaveCurrentDomain_TaskAsync(req);

        return res.LeaveCurrentDomain_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string[]?> ListCACertificateRevocationLists(ManagedObjectReference self)
    {
        var req = new ListCACertificateRevocationListsRequestType
        {
            _this = self,
        };

        var res = await this.inner.ListCACertificateRevocationListsAsync(req);

        return res.ListCACertificateRevocationListsResponse1;
    }

    public async System.Threading.Tasks.Task<string[]?> ListCACertificates(ManagedObjectReference self)
    {
        var req = new ListCACertificatesRequestType
        {
            _this = self,
        };

        var res = await this.inner.ListCACertificatesAsync(req);

        return res.ListCACertificatesResponse1;
    }

    public async System.Threading.Tasks.Task<GuestListFileInfo?> ListFilesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string filePath, int index, bool indexSpecified, int maxResults, bool maxResultsSpecified, string? matchPattern)
    {
        var req = new ListFilesInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            filePath = filePath,
            index = index,
            indexSpecified = indexSpecified,
            maxResults = maxResults,
            maxResultsSpecified = maxResultsSpecified,
            matchPattern = matchPattern,
        };

        var res = await this.inner.ListFilesInGuestAsync(req);

        return res.ListFilesInGuestResponse.returnval;
    }

    public async System.Threading.Tasks.Task<GuestAliases[]?> ListGuestAliases(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username)
    {
        var req = new ListGuestAliasesRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            username = username,
        };

        var res = await this.inner.ListGuestAliasesAsync(req);

        return res.ListGuestAliasesResponse1;
    }

    public async System.Threading.Tasks.Task<GuestMappedAliases[]?> ListGuestMappedAliases(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth)
    {
        var req = new ListGuestMappedAliasesRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
        };

        var res = await this.inner.ListGuestMappedAliasesAsync(req);

        return res.ListGuestMappedAliasesResponse1;
    }

    public async System.Threading.Tasks.Task<CryptoKeyId[]?> ListKeys(ManagedObjectReference self, int limit, bool limitSpecified)
    {
        var req = new ListKeysRequestType
        {
            _this = self,
            limit = limit,
            limitSpecified = limitSpecified,
        };

        var res = await this.inner.ListKeysAsync(req);

        return res.ListKeysResponse1;
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmipServers(ManagedObjectReference self, int limit, bool limitSpecified)
    {
        var req = new ListKmipServersRequestType
        {
            _this = self,
            limit = limit,
            limitSpecified = limitSpecified,
        };

        var res = await this.inner.ListKmipServersAsync(req);

        return res.ListKmipServersResponse1;
    }

    public async System.Threading.Tasks.Task<KmipClusterInfo[]?> ListKmsClusters(ManagedObjectReference self, bool includeKmsServers, bool includeKmsServersSpecified, int managementTypeFilter, bool managementTypeFilterSpecified, int statusFilter, bool statusFilterSpecified)
    {
        var req = new ListKmsClustersRequestType
        {
            _this = self,
            includeKmsServers = includeKmsServers,
            includeKmsServersSpecified = includeKmsServersSpecified,
            managementTypeFilter = managementTypeFilter,
            managementTypeFilterSpecified = managementTypeFilterSpecified,
            statusFilter = statusFilter,
            statusFilterSpecified = statusFilterSpecified,
        };

        var res = await this.inner.ListKmsClustersAsync(req);

        return res.ListKmsClustersResponse1;
    }

    public async System.Threading.Tasks.Task<GuestProcessInfo[]?> ListProcessesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, long[]? pids)
    {
        var req = new ListProcessesInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            pids = pids,
        };

        var res = await this.inner.ListProcessesInGuestAsync(req);

        return res.ListProcessesInGuestResponse1;
    }

    public async System.Threading.Tasks.Task<GuestRegKeyRecordSpec[]?> ListRegistryKeysInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool recursive, string? matchPattern)
    {
        var req = new ListRegistryKeysInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            keyName = keyName,
            recursive = recursive,
            matchPattern = matchPattern,
        };

        var res = await this.inner.ListRegistryKeysInGuestAsync(req);

        return res.ListRegistryKeysInGuestResponse1;
    }

    public async System.Threading.Tasks.Task<GuestRegValueSpec[]?> ListRegistryValuesInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegKeyNameSpec keyName, bool expandStrings, string? matchPattern)
    {
        var req = new ListRegistryValuesInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            keyName = keyName,
            expandStrings = expandStrings,
            matchPattern = matchPattern,
        };

        var res = await this.inner.ListRegistryValuesInGuestAsync(req);

        return res.ListRegistryValuesInGuestResponse1;
    }

    public async System.Threading.Tasks.Task<string[]?> ListSmartCardTrustAnchors(ManagedObjectReference self)
    {
        var req = new ListSmartCardTrustAnchorsRequestType
        {
            _this = self,
        };

        var res = await this.inner.ListSmartCardTrustAnchorsAsync(req);

        return res.ListSmartCardTrustAnchorsResponse1;
    }

    public async System.Threading.Tasks.Task<VslmTagEntry[]?> ListTagsAttachedToVStorageObject(ManagedObjectReference self, ID id)
    {
        var req = new ListTagsAttachedToVStorageObjectRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.ListTagsAttachedToVStorageObjectAsync(req);

        return res.ListTagsAttachedToVStorageObjectResponse1;
    }

    public async System.Threading.Tasks.Task<ID[]?> ListVStorageObject(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new ListVStorageObjectRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.ListVStorageObjectAsync(req);

        return res.ListVStorageObjectResponse1;
    }

    public async System.Threading.Tasks.Task<ID[]?> ListVStorageObjectsAttachedToTag(ManagedObjectReference self, string category, string tag)
    {
        var req = new ListVStorageObjectsAttachedToTagRequestType
        {
            _this = self,
            category = category,
            tag = tag,
        };

        var res = await this.inner.ListVStorageObjectsAttachedToTagAsync(req);

        return res.ListVStorageObjectsAttachedToTagResponse1;
    }

    public async System.Threading.Tasks.Task<UserSession?> Login(ManagedObjectReference self, string userName, string password, string? locale)
    {
        var req = new LoginRequestType
        {
            _this = self,
            userName = userName,
            password = password,
            locale = locale,
        };

        var res = await this.inner.LoginAsync(req);

        return res.LoginResponse.returnval;
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginBySSPI(ManagedObjectReference self, string base64Token, string? locale)
    {
        var req = new LoginBySSPIRequestType
        {
            _this = self,
            base64Token = base64Token,
            locale = locale,
        };

        var res = await this.inner.LoginBySSPIAsync(req);

        return res.LoginBySSPIResponse.returnval;
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginByToken(ManagedObjectReference self, string? locale)
    {
        var req = new LoginByTokenRequestType
        {
            _this = self,
            locale = locale,
        };

        var res = await this.inner.LoginByTokenAsync(req);

        return res.LoginByTokenResponse.returnval;
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginExtensionByCertificate(ManagedObjectReference self, string extensionKey, string? locale)
    {
        var req = new LoginExtensionByCertificateRequestType
        {
            _this = self,
            extensionKey = extensionKey,
            locale = locale,
        };

        var res = await this.inner.LoginExtensionByCertificateAsync(req);

        return res.LoginExtensionByCertificateResponse.returnval;
    }

    public async System.Threading.Tasks.Task<UserSession?> LoginExtensionBySubjectName(ManagedObjectReference self, string extensionKey, string? locale)
    {
        var req = new LoginExtensionBySubjectNameRequestType
        {
            _this = self,
            extensionKey = extensionKey,
            locale = locale,
        };

        var res = await this.inner.LoginExtensionBySubjectNameAsync(req);

        return res.LoginExtensionBySubjectNameResponse.returnval;
    }

    public async System.Threading.Tasks.Task Logout(ManagedObjectReference self)
    {
        var req = new LogoutRequestType
        {
            _this = self,
        };

        await this.inner.LogoutAsync(req);
    }

    public async System.Threading.Tasks.Task LogUserEvent(ManagedObjectReference self, ManagedObjectReference entity, string msg)
    {
        var req = new LogUserEventRequestType
        {
            _this = self,
            entity = entity,
            msg = msg,
        };

        await this.inner.LogUserEventAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> LookupDvPortGroup(ManagedObjectReference self, string portgroupKey)
    {
        var req = new LookupDvPortGroupRequestType
        {
            _this = self,
            portgroupKey = portgroupKey,
        };

        var res = await this.inner.LookupDvPortGroupAsync(req);

        return res.LookupDvPortGroupResponse.returnval;
    }

    public async System.Threading.Tasks.Task<long> LookupVmOverheadMemory(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference host)
    {
        var req = new LookupVmOverheadMemoryRequestType
        {
            _this = self,
            vm = vm,
            host = host,
        };

        var res = await this.inner.LookupVmOverheadMemoryAsync(req);

        return res.LookupVmOverheadMemoryResponse.returnval;
    }

    public async System.Threading.Tasks.Task MakeDirectory(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, bool createParentDirectories, bool createParentDirectoriesSpecified)
    {
        var req = new MakeDirectoryRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
            createParentDirectories = createParentDirectories,
            createParentDirectoriesSpecified = createParentDirectoriesSpecified,
        };

        await this.inner.MakeDirectoryAsync(req);
    }

    public async System.Threading.Tasks.Task MakeDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string directoryPath, bool createParentDirectories)
    {
        var req = new MakeDirectoryInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            directoryPath = directoryPath,
            createParentDirectories = createParentDirectories,
        };

        await this.inner.MakeDirectoryInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MakePrimaryVM_Task(ManagedObjectReference self, ManagedObjectReference vm)
    {
        var req = new MakePrimaryVMRequestType
        {
            _this = self,
            vm = vm,
        };

        var res = await this.inner.MakePrimaryVM_TaskAsync(req);

        return res.MakePrimaryVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsLocal_Task(ManagedObjectReference self, string scsiDiskUuid)
    {
        var req = new MarkAsLocalRequestType
        {
            _this = self,
            scsiDiskUuid = scsiDiskUuid,
        };

        var res = await this.inner.MarkAsLocal_TaskAsync(req);

        return res.MarkAsLocal_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsNonLocal_Task(ManagedObjectReference self, string scsiDiskUuid)
    {
        var req = new MarkAsNonLocalRequestType
        {
            _this = self,
            scsiDiskUuid = scsiDiskUuid,
        };

        var res = await this.inner.MarkAsNonLocal_TaskAsync(req);

        return res.MarkAsNonLocal_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsNonSsd_Task(ManagedObjectReference self, string scsiDiskUuid)
    {
        var req = new MarkAsNonSsdRequestType
        {
            _this = self,
            scsiDiskUuid = scsiDiskUuid,
        };

        var res = await this.inner.MarkAsNonSsd_TaskAsync(req);

        return res.MarkAsNonSsd_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MarkAsSsd_Task(ManagedObjectReference self, string scsiDiskUuid)
    {
        var req = new MarkAsSsdRequestType
        {
            _this = self,
            scsiDiskUuid = scsiDiskUuid,
        };

        var res = await this.inner.MarkAsSsd_TaskAsync(req);

        return res.MarkAsSsd_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task MarkAsTemplate(ManagedObjectReference self)
    {
        var req = new MarkAsTemplateRequestType
        {
            _this = self,
        };

        await this.inner.MarkAsTemplateAsync(req);
    }

    public async System.Threading.Tasks.Task MarkAsVirtualMachine(ManagedObjectReference self, ManagedObjectReference pool, ManagedObjectReference? host)
    {
        var req = new MarkAsVirtualMachineRequestType
        {
            _this = self,
            pool = pool,
            host = host,
        };

        await this.inner.MarkAsVirtualMachineAsync(req);
    }

    public async System.Threading.Tasks.Task MarkDefault(ManagedObjectReference self, KeyProviderId clusterId)
    {
        var req = new MarkDefaultRequestType
        {
            _this = self,
            clusterId = clusterId,
        };

        await this.inner.MarkDefaultAsync(req);
    }

    public async System.Threading.Tasks.Task MarkForRemoval(ManagedObjectReference self, string hbaName, bool remove)
    {
        var req = new MarkForRemovalRequestType
        {
            _this = self,
            hbaName = hbaName,
            remove = remove,
        };

        await this.inner.MarkForRemovalAsync(req);
    }

    public async System.Threading.Tasks.Task MarkPerenniallyReserved(ManagedObjectReference self, string lunUuid, bool state)
    {
        var req = new MarkPerenniallyReservedRequestType
        {
            _this = self,
            lunUuid = lunUuid,
            state = state,
        };

        await this.inner.MarkPerenniallyReservedAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MarkPerenniallyReservedEx_Task(ManagedObjectReference self, string[]? lunUuid, bool state)
    {
        var req = new MarkPerenniallyReservedExRequestType
        {
            _this = self,
            lunUuid = lunUuid,
            state = state,
        };

        var res = await this.inner.MarkPerenniallyReservedEx_TaskAsync(req);

        return res.MarkPerenniallyReservedEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task MarkServiceProviderEntities(ManagedObjectReference self, ManagedObjectReference[]? entity)
    {
        var req = new MarkServiceProviderEntitiesRequestType
        {
            _this = self,
            entity = entity,
        };

        await this.inner.MarkServiceProviderEntitiesAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MergeDvs_Task(ManagedObjectReference self, ManagedObjectReference dvs)
    {
        var req = new MergeDvsRequestType
        {
            _this = self,
            dvs = dvs,
        };

        var res = await this.inner.MergeDvs_TaskAsync(req);

        return res.MergeDvs_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task MergePermissions(ManagedObjectReference self, int srcRoleId, int dstRoleId)
    {
        var req = new MergePermissionsRequestType
        {
            _this = self,
            srcRoleId = srcRoleId,
            dstRoleId = dstRoleId,
        };

        await this.inner.MergePermissionsAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MigrateVM_Task(ManagedObjectReference self, ManagedObjectReference? pool, ManagedObjectReference? host, VirtualMachineMovePriority priority, VirtualMachinePowerState state, bool stateSpecified)
    {
        var req = new MigrateVMRequestType
        {
            _this = self,
            pool = pool,
            host = host,
            priority = priority,
            state = state,
            stateSpecified = stateSpecified,
        };

        var res = await this.inner.MigrateVM_TaskAsync(req);

        return res.MigrateVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> ModifyListView(ManagedObjectReference self, ManagedObjectReference[]? add, ManagedObjectReference[]? remove)
    {
        var req = new ModifyListViewRequestType
        {
            _this = self,
            add = add,
            remove = remove,
        };

        var res = await this.inner.ModifyListViewAsync(req);

        return res.ModifyListViewResponse1;
    }

    public async System.Threading.Tasks.Task MountToolsInstaller(ManagedObjectReference self)
    {
        var req = new MountToolsInstallerRequestType
        {
            _this = self,
        };

        await this.inner.MountToolsInstallerAsync(req);
    }

    public async System.Threading.Tasks.Task MountVffsVolume(ManagedObjectReference self, string vffsUuid)
    {
        var req = new MountVffsVolumeRequestType
        {
            _this = self,
            vffsUuid = vffsUuid,
        };

        await this.inner.MountVffsVolumeAsync(req);
    }

    public async System.Threading.Tasks.Task MountVmfsVolume(ManagedObjectReference self, string vmfsUuid)
    {
        var req = new MountVmfsVolumeRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
        };

        await this.inner.MountVmfsVolumeAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MountVmfsVolumeEx_Task(ManagedObjectReference self, string[] vmfsUuid)
    {
        var req = new MountVmfsVolumeExRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
        };

        var res = await this.inner.MountVmfsVolumeEx_TaskAsync(req);

        return res.MountVmfsVolumeEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MoveDatastoreFile_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destinationName, ManagedObjectReference? destinationDatacenter, bool force, bool forceSpecified)
    {
        var req = new MoveDatastoreFileRequestType
        {
            _this = self,
            sourceName = sourceName,
            sourceDatacenter = sourceDatacenter,
            destinationName = destinationName,
            destinationDatacenter = destinationDatacenter,
            force = force,
            forceSpecified = forceSpecified,
        };

        var res = await this.inner.MoveDatastoreFile_TaskAsync(req);

        return res.MoveDatastoreFile_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task MoveDirectoryInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string srcDirectoryPath, string dstDirectoryPath)
    {
        var req = new MoveDirectoryInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            srcDirectoryPath = srcDirectoryPath,
            dstDirectoryPath = dstDirectoryPath,
        };

        await this.inner.MoveDirectoryInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MoveDVPort_Task(ManagedObjectReference self, string[] portKey, string? destinationPortgroupKey)
    {
        var req = new MoveDVPortRequestType
        {
            _this = self,
            portKey = portKey,
            destinationPortgroupKey = destinationPortgroupKey,
        };

        var res = await this.inner.MoveDVPort_TaskAsync(req);

        return res.MoveDVPort_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task MoveFileInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string srcFilePath, string dstFilePath, bool overwrite)
    {
        var req = new MoveFileInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            srcFilePath = srcFilePath,
            dstFilePath = dstFilePath,
            overwrite = overwrite,
        };

        await this.inner.MoveFileInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MoveHostInto_Task(ManagedObjectReference self, ManagedObjectReference host, ManagedObjectReference? resourcePool)
    {
        var req = new MoveHostIntoRequestType
        {
            _this = self,
            host = host,
            resourcePool = resourcePool,
        };

        var res = await this.inner.MoveHostInto_TaskAsync(req);

        return res.MoveHostInto_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MoveInto_Task(ManagedObjectReference self, ManagedObjectReference[] host)
    {
        var req = new MoveIntoRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.MoveInto_TaskAsync(req);

        return res.MoveInto_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MoveIntoFolder_Task(ManagedObjectReference self, ManagedObjectReference[] list)
    {
        var req = new MoveIntoFolderRequestType
        {
            _this = self,
            list = list,
        };

        var res = await this.inner.MoveIntoFolder_TaskAsync(req);

        return res.MoveIntoFolder_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task MoveIntoResourcePool(ManagedObjectReference self, ManagedObjectReference[] list)
    {
        var req = new MoveIntoResourcePoolRequestType
        {
            _this = self,
            list = list,
        };

        await this.inner.MoveIntoResourcePoolAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> MoveVirtualDisk_Task(ManagedObjectReference self, string sourceName, ManagedObjectReference? sourceDatacenter, string destName, ManagedObjectReference? destDatacenter, bool force, bool forceSpecified, VirtualMachineProfileSpec[]? profile)
    {
        var req = new MoveVirtualDiskRequestType
        {
            _this = self,
            sourceName = sourceName,
            sourceDatacenter = sourceDatacenter,
            destName = destName,
            destDatacenter = destDatacenter,
            force = force,
            forceSpecified = forceSpecified,
            profile = profile,
        };

        var res = await this.inner.MoveVirtualDisk_TaskAsync(req);

        return res.MoveVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task NotifyAffectedServices(ManagedObjectReference self, string[]? services)
    {
        var req = new NotifyAffectedServicesRequestType
        {
            _this = self,
            services = services,
        };

        await this.inner.NotifyAffectedServicesAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> OpenInventoryViewFolder(ManagedObjectReference self, ManagedObjectReference[] entity)
    {
        var req = new OpenInventoryViewFolderRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.OpenInventoryViewFolderAsync(req);

        return res.OpenInventoryViewFolderResponse1;
    }

    public async System.Threading.Tasks.Task OverwriteCustomizationSpec(ManagedObjectReference self, CustomizationSpecItem item)
    {
        var req = new OverwriteCustomizationSpecRequestType
        {
            _this = self,
            item = item,
        };

        await this.inner.OverwriteCustomizationSpecAsync(req);
    }

    public async System.Threading.Tasks.Task<OvfParseDescriptorResult?> ParseDescriptor(ManagedObjectReference self, string ovfDescriptor, OvfParseDescriptorParams pdp)
    {
        var req = new ParseDescriptorRequestType
        {
            _this = self,
            ovfDescriptor = ovfDescriptor,
            pdp = pdp,
        };

        var res = await this.inner.ParseDescriptorAsync(req);

        return res.ParseDescriptorResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PerformDvsProductSpecOperation_Task(ManagedObjectReference self, string operation, DistributedVirtualSwitchProductSpec? productSpec)
    {
        var req = new PerformDvsProductSpecOperationRequestType
        {
            _this = self,
            operation = operation,
            productSpec = productSpec,
        };

        var res = await this.inner.PerformDvsProductSpecOperation_TaskAsync(req);

        return res.PerformDvsProductSpecOperation_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PerformVsanUpgrade_Task(ManagedObjectReference self, ManagedObjectReference cluster, bool performObjectUpgrade, bool performObjectUpgradeSpecified, bool downgradeFormat, bool downgradeFormatSpecified, bool allowReducedRedundancy, bool allowReducedRedundancySpecified, ManagedObjectReference[]? excludeHosts)
    {
        var req = new PerformVsanUpgradeRequestType
        {
            _this = self,
            cluster = cluster,
            performObjectUpgrade = performObjectUpgrade,
            performObjectUpgradeSpecified = performObjectUpgradeSpecified,
            downgradeFormat = downgradeFormat,
            downgradeFormatSpecified = downgradeFormatSpecified,
            allowReducedRedundancy = allowReducedRedundancy,
            allowReducedRedundancySpecified = allowReducedRedundancySpecified,
            excludeHosts = excludeHosts,
        };

        var res = await this.inner.PerformVsanUpgrade_TaskAsync(req);

        return res.PerformVsanUpgrade_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemPreflightCheckResult?> PerformVsanUpgradePreflightCheck(ManagedObjectReference self, ManagedObjectReference cluster, bool downgradeFormat, bool downgradeFormatSpecified)
    {
        var req = new PerformVsanUpgradePreflightCheckRequestType
        {
            _this = self,
            cluster = cluster,
            downgradeFormat = downgradeFormat,
            downgradeFormatSpecified = downgradeFormatSpecified,
        };

        var res = await this.inner.PerformVsanUpgradePreflightCheckAsync(req);

        return res.PerformVsanUpgradePreflightCheckResponse.returnval;
    }

    public async System.Threading.Tasks.Task<PlacementResult?> PlaceVm(ManagedObjectReference self, PlacementSpec placementSpec)
    {
        var req = new PlaceVmRequestType
        {
            _this = self,
            placementSpec = placementSpec,
        };

        var res = await this.inner.PlaceVmAsync(req);

        return res.PlaceVmResponse.returnval;
    }

    public async System.Threading.Tasks.Task PostEvent(ManagedObjectReference self, Event eventToPost, TaskInfo? taskInfo)
    {
        var req = new PostEventRequestType
        {
            _this = self,
            eventToPost = eventToPost,
            taskInfo = taskInfo,
        };

        await this.inner.PostEventAsync(req);
    }

    public async System.Threading.Tasks.Task PostHealthUpdates(ManagedObjectReference self, string providerId, HealthUpdate[]? updates)
    {
        var req = new PostHealthUpdatesRequestType
        {
            _this = self,
            providerId = providerId,
            updates = updates,
        };

        await this.inner.PostHealthUpdatesAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PowerDownHostToStandBy_Task(ManagedObjectReference self, int timeoutSec, bool evacuatePoweredOffVms, bool evacuatePoweredOffVmsSpecified)
    {
        var req = new PowerDownHostToStandByRequestType
        {
            _this = self,
            timeoutSec = timeoutSec,
            evacuatePoweredOffVms = evacuatePoweredOffVms,
            evacuatePoweredOffVmsSpecified = evacuatePoweredOffVmsSpecified,
        };

        var res = await this.inner.PowerDownHostToStandBy_TaskAsync(req);

        return res.PowerDownHostToStandBy_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PowerOffVApp_Task(ManagedObjectReference self, bool force)
    {
        var req = new PowerOffVAppRequestType
        {
            _this = self,
            force = force,
        };

        var res = await this.inner.PowerOffVApp_TaskAsync(req);

        return res.PowerOffVApp_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PowerOffVM_Task(ManagedObjectReference self)
    {
        var req = new PowerOffVMRequestType
        {
            _this = self,
        };

        var res = await this.inner.PowerOffVM_TaskAsync(req);

        return res.PowerOffVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PowerOnMultiVM_Task(ManagedObjectReference self, ManagedObjectReference[] vm, OptionValue[]? option)
    {
        var req = new PowerOnMultiVMRequestType
        {
            _this = self,
            vm = vm,
            option = option,
        };

        var res = await this.inner.PowerOnMultiVM_TaskAsync(req);

        return res.PowerOnMultiVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PowerOnVApp_Task(ManagedObjectReference self)
    {
        var req = new PowerOnVAppRequestType
        {
            _this = self,
        };

        var res = await this.inner.PowerOnVApp_TaskAsync(req);

        return res.PowerOnVApp_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PowerOnVM_Task(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new PowerOnVMRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.PowerOnVM_TaskAsync(req);

        return res.PowerOnVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PowerUpHostFromStandBy_Task(ManagedObjectReference self, int timeoutSec)
    {
        var req = new PowerUpHostFromStandByRequestType
        {
            _this = self,
            timeoutSec = timeoutSec,
        };

        var res = await this.inner.PowerUpHostFromStandBy_TaskAsync(req);

        return res.PowerUpHostFromStandBy_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task PrepareCrypto(ManagedObjectReference self)
    {
        var req = new PrepareCryptoRequestType
        {
            _this = self,
        };

        await this.inner.PrepareCryptoAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PrepareVcha_Task(ManagedObjectReference self, VchaClusterNetworkSpec networkSpec)
    {
        var req = new prepareVchaRequestType
        {
            _this = self,
            networkSpec = networkSpec,
        };

        var res = await this.inner.prepareVcha_TaskAsync(req);

        return res.prepareVcha_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> PromoteDisks_Task(ManagedObjectReference self, bool unlink, VirtualDisk[]? disks)
    {
        var req = new PromoteDisksRequestType
        {
            _this = self,
            unlink = unlink,
            disks = disks,
        };

        var res = await this.inner.PromoteDisks_TaskAsync(req);

        return res.PromoteDisks_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ProvisionServerPrivateKey(ManagedObjectReference self, string key)
    {
        var req = new ProvisionServerPrivateKeyRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.ProvisionServerPrivateKeyAsync(req);
    }

    public async System.Threading.Tasks.Task<int> PutUsbScanCodes(ManagedObjectReference self, UsbScanCodeSpec spec)
    {
        var req = new PutUsbScanCodesRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.PutUsbScanCodesAsync(req);

        return res.PutUsbScanCodesResponse.returnval;
    }

    public async System.Threading.Tasks.Task<AnswerFileStatusResult[]?> QueryAnswerFileStatus(ManagedObjectReference self, ManagedObjectReference[] host)
    {
        var req = new QueryAnswerFileStatusRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QueryAnswerFileStatusAsync(req);

        return res.QueryAnswerFileStatusResponse1;
    }

    public async System.Threading.Tasks.Task<LicenseAssignmentManagerLicenseAssignment[]?> QueryAssignedLicenses(ManagedObjectReference self, string? entityId)
    {
        var req = new QueryAssignedLicensesRequestType
        {
            _this = self,
            entityId = entityId,
        };

        var res = await this.inner.QueryAssignedLicensesAsync(req);

        return res.QueryAssignedLicensesResponse1;
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableDisksForVmfs(ManagedObjectReference self, ManagedObjectReference? datastore)
    {
        var req = new QueryAvailableDisksForVmfsRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.QueryAvailableDisksForVmfsAsync(req);

        return res.QueryAvailableDisksForVmfsResponse1;
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchProductSpec[]?> QueryAvailableDvsSpec(ManagedObjectReference self, bool recommended, bool recommendedSpecified)
    {
        var req = new QueryAvailableDvsSpecRequestType
        {
            _this = self,
            recommended = recommended,
            recommendedSpecified = recommendedSpecified,
        };

        var res = await this.inner.QueryAvailableDvsSpecAsync(req);

        return res.QueryAvailableDvsSpecResponse1;
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartition[]?> QueryAvailablePartition(ManagedObjectReference self)
    {
        var req = new QueryAvailablePartitionRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryAvailablePartitionAsync(req);

        return res.QueryAvailablePartitionResponse1;
    }

    public async System.Threading.Tasks.Task<PerfMetricId[]?> QueryAvailablePerfMetric(ManagedObjectReference self, ManagedObjectReference entity, DateTime beginTime, bool beginTimeSpecified, DateTime endTime, bool endTimeSpecified, int intervalId, bool intervalIdSpecified)
    {
        var req = new QueryAvailablePerfMetricRequestType
        {
            _this = self,
            entity = entity,
            beginTime = beginTime,
            beginTimeSpecified = beginTimeSpecified,
            endTime = endTime,
            endTimeSpecified = endTimeSpecified,
            intervalId = intervalId,
            intervalIdSpecified = intervalIdSpecified,
        };

        var res = await this.inner.QueryAvailablePerfMetricAsync(req);

        return res.QueryAvailablePerfMetricResponse1;
    }

    public async System.Threading.Tasks.Task<HostScsiDisk[]?> QueryAvailableSsds(ManagedObjectReference self, string? vffsPath)
    {
        var req = new QueryAvailableSsdsRequestType
        {
            _this = self,
            vffsPath = vffsPath,
        };

        var res = await this.inner.QueryAvailableSsdsAsync(req);

        return res.QueryAvailableSsdsResponse1;
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemTimeZone[]?> QueryAvailableTimeZones(ManagedObjectReference self)
    {
        var req = new QueryAvailableTimeZonesRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryAvailableTimeZonesAsync(req);

        return res.QueryAvailableTimeZonesResponse1;
    }

    public async System.Threading.Tasks.Task<HostBootDeviceInfo?> QueryBootDevices(ManagedObjectReference self)
    {
        var req = new QueryBootDevicesRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryBootDevicesAsync(req);

        return res.QueryBootDevicesResponse.returnval;
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryBoundVnics(ManagedObjectReference self, string iScsiHbaName)
    {
        var req = new QueryBoundVnicsRequestType
        {
            _this = self,
            iScsiHbaName = iScsiHbaName,
        };

        var res = await this.inner.QueryBoundVnicsAsync(req);

        return res.QueryBoundVnicsResponse1;
    }

    public async System.Threading.Tasks.Task<IscsiPortInfo[]?> QueryCandidateNics(ManagedObjectReference self, string iScsiHbaName)
    {
        var req = new QueryCandidateNicsRequestType
        {
            _this = self,
            iScsiHbaName = iScsiHbaName,
        };

        var res = await this.inner.QueryCandidateNicsAsync(req);

        return res.QueryCandidateNicsResponse1;
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> QueryChangedDiskAreas(ManagedObjectReference self, ManagedObjectReference? snapshot, int deviceKey, long startOffset, string changeId)
    {
        var req = new QueryChangedDiskAreasRequestType
        {
            _this = self,
            snapshot = snapshot,
            deviceKey = deviceKey,
            startOffset = startOffset,
            changeId = changeId,
        };

        var res = await this.inner.QueryChangedDiskAreasAsync(req);

        return res.QueryChangedDiskAreasResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryCmmds(ManagedObjectReference self, HostVsanInternalSystemCmmdsQuery[] queries)
    {
        var req = new QueryCmmdsRequestType
        {
            _this = self,
            queries = queries,
        };

        var res = await this.inner.QueryCmmdsAsync(req);

        return res.QueryCmmdsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryCompatibleHostForExistingDvs(ManagedObjectReference self, ManagedObjectReference container, bool recursive, ManagedObjectReference dvs)
    {
        var req = new QueryCompatibleHostForExistingDvsRequestType
        {
            _this = self,
            container = container,
            recursive = recursive,
            dvs = dvs,
        };

        var res = await this.inner.QueryCompatibleHostForExistingDvsAsync(req);

        return res.QueryCompatibleHostForExistingDvsResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryCompatibleHostForNewDvs(ManagedObjectReference self, ManagedObjectReference container, bool recursive, DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        var req = new QueryCompatibleHostForNewDvsRequestType
        {
            _this = self,
            container = container,
            recursive = recursive,
            switchProductSpec = switchProductSpec,
        };

        var res = await this.inner.QueryCompatibleHostForNewDvsAsync(req);

        return res.QueryCompatibleHostForNewDvsResponse1;
    }

    public async System.Threading.Tasks.Task<DVSManagerPhysicalNicsList[]?> QueryCompatibleVmnicsFromHosts(ManagedObjectReference self, ManagedObjectReference[]? hosts, ManagedObjectReference dvs)
    {
        var req = new QueryCompatibleVmnicsFromHostsRequestType
        {
            _this = self,
            hosts = hosts,
            dvs = dvs,
        };

        var res = await this.inner.QueryCompatibleVmnicsFromHostsAsync(req);

        return res.QueryCompatibleVmnicsFromHostsResponse1;
    }

    public async System.Threading.Tasks.Task<ComplianceResult[]?> QueryComplianceStatus(ManagedObjectReference self, ManagedObjectReference[]? profile, ManagedObjectReference[]? entity)
    {
        var req = new QueryComplianceStatusRequestType
        {
            _this = self,
            profile = profile,
            entity = entity,
        };

        var res = await this.inner.QueryComplianceStatusAsync(req);

        return res.QueryComplianceStatusResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOption(ManagedObjectReference self, string? key, ManagedObjectReference? host)
    {
        var req = new QueryConfigOptionRequestType
        {
            _this = self,
            key = key,
            host = host,
        };

        var res = await this.inner.QueryConfigOptionAsync(req);

        return res.QueryConfigOptionResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryConfigOptionDescriptor(ManagedObjectReference self)
    {
        var req = new QueryConfigOptionDescriptorRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryConfigOptionDescriptorAsync(req);

        return res.QueryConfigOptionDescriptorResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOption?> QueryConfigOptionEx(ManagedObjectReference self, EnvironmentBrowserConfigOptionQuerySpec? spec)
    {
        var req = new QueryConfigOptionExRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.QueryConfigOptionExAsync(req);

        return res.QueryConfigOptionExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ConfigTarget?> QueryConfigTarget(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new QueryConfigTargetRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QueryConfigTargetAsync(req);

        return res.QueryConfigTargetResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryConfiguredModuleOptionString(ManagedObjectReference self, string name)
    {
        var req = new QueryConfiguredModuleOptionStringRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.QueryConfiguredModuleOptionStringAsync(req);

        return res.QueryConfiguredModuleOptionStringResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfo(ManagedObjectReference self, string hostname, int port, string username, string password, string? sslThumbprint, string? sslCertificate)
    {
        var req = new QueryConnectionInfoRequestType
        {
            _this = self,
            hostname = hostname,
            port = port,
            username = username,
            password = password,
            sslThumbprint = sslThumbprint,
            sslCertificate = sslCertificate,
        };

        var res = await this.inner.QueryConnectionInfoAsync(req);

        return res.QueryConnectionInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryConnectionInfoViaSpec(ManagedObjectReference self, HostConnectSpec spec)
    {
        var req = new QueryConnectionInfoViaSpecRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.QueryConnectionInfoViaSpecAsync(req);

        return res.QueryConnectionInfoViaSpecResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VirtualMachineConnection[]?> QueryConnections(ManagedObjectReference self)
    {
        var req = new QueryConnectionsRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryConnectionsAsync(req);

        return res.QueryConnectionsResponse1;
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipCryptoKeyStatus[]?> QueryCryptoKeyStatus(ManagedObjectReference self, CryptoKeyId[]? keyIds, int checkKeyBitMap)
    {
        var req = new QueryCryptoKeyStatusRequestType
        {
            _this = self,
            keyIds = keyIds,
            checkKeyBitMap = checkKeyBitMap,
        };

        var res = await this.inner.QueryCryptoKeyStatusAsync(req);

        return res.QueryCryptoKeyStatusResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualMachineConfigOptionDescriptor[]?> QueryDatacenterConfigOptionDescriptor(ManagedObjectReference self)
    {
        var req = new queryDatacenterConfigOptionDescriptorRequestType
        {
            _this = self,
        };

        var res = await this.inner.queryDatacenterConfigOptionDescriptorAsync(req);

        return res.queryDatacenterConfigOptionDescriptorResponse1;
    }

    public async System.Threading.Tasks.Task<StoragePerformanceSummary[]?> QueryDatastorePerformanceSummary(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new QueryDatastorePerformanceSummaryRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.QueryDatastorePerformanceSummaryAsync(req);

        return res.QueryDatastorePerformanceSummaryResponse1;
    }

    public async System.Threading.Tasks.Task<DateTime> QueryDateTime(ManagedObjectReference self)
    {
        var req = new QueryDateTimeRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryDateTimeAsync(req);

        return res.QueryDateTimeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DiagnosticManagerLogDescriptor[]?> QueryDescriptions(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new QueryDescriptionsRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QueryDescriptionsAsync(req);

        return res.QueryDescriptionsResponse1;
    }

    public async System.Threading.Tasks.Task<DatastoreNamespaceManagerDirectoryInfo?> QueryDirectoryInfo(ManagedObjectReference self, ManagedObjectReference? datacenter, string stableName)
    {
        var req = new QueryDirectoryInfoRequestType
        {
            _this = self,
            datacenter = datacenter,
            stableName = stableName,
        };

        var res = await this.inner.QueryDirectoryInfoAsync(req);

        return res.QueryDirectoryInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VsanHostDiskResult[]?> QueryDisksForVsan(ManagedObjectReference self, string[]? canonicalName)
    {
        var req = new QueryDisksForVsanRequestType
        {
            _this = self,
            canonicalName = canonicalName,
        };

        var res = await this.inner.QueryDisksForVsanAsync(req);

        return res.QueryDisksForVsanResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualDiskId[]?> QueryDisksUsingFilter(ManagedObjectReference self, string filterId, ManagedObjectReference compRes)
    {
        var req = new QueryDisksUsingFilterRequestType
        {
            _this = self,
            filterId = filterId,
            compRes = compRes,
        };

        var res = await this.inner.QueryDisksUsingFilterAsync(req);

        return res.QueryDisksUsingFilterResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> QueryDvsByUuid(ManagedObjectReference self, string uuid)
    {
        var req = new QueryDvsByUuidRequestType
        {
            _this = self,
            uuid = uuid,
        };

        var res = await this.inner.QueryDvsByUuidAsync(req);

        return res.QueryDvsByUuidResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchManagerCompatibilityResult[]?> QueryDvsCheckCompatibility(ManagedObjectReference self, DistributedVirtualSwitchManagerHostContainer hostContainer, DistributedVirtualSwitchManagerDvsProductSpec? dvsProductSpec, DistributedVirtualSwitchManagerHostDvsFilterSpec[]? hostFilterSpec)
    {
        var req = new QueryDvsCheckCompatibilityRequestType
        {
            _this = self,
            hostContainer = hostContainer,
            dvsProductSpec = dvsProductSpec,
            hostFilterSpec = hostFilterSpec,
        };

        var res = await this.inner.QueryDvsCheckCompatibilityAsync(req);

        return res.QueryDvsCheckCompatibilityResponse1;
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchHostProductSpec[]?> QueryDvsCompatibleHostSpec(ManagedObjectReference self, DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        var req = new QueryDvsCompatibleHostSpecRequestType
        {
            _this = self,
            switchProductSpec = switchProductSpec,
        };

        var res = await this.inner.QueryDvsCompatibleHostSpecAsync(req);

        return res.QueryDvsCompatibleHostSpecResponse1;
    }

    public async System.Threading.Tasks.Task<DVSManagerDvsConfigTarget?> QueryDvsConfigTarget(ManagedObjectReference self, ManagedObjectReference? host, ManagedObjectReference? dvs)
    {
        var req = new QueryDvsConfigTargetRequestType
        {
            _this = self,
            host = host,
            dvs = dvs,
        };

        var res = await this.inner.QueryDvsConfigTargetAsync(req);

        return res.QueryDvsConfigTargetResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DVSFeatureCapability?> QueryDvsFeatureCapability(ManagedObjectReference self, DistributedVirtualSwitchProductSpec? switchProductSpec)
    {
        var req = new QueryDvsFeatureCapabilityRequestType
        {
            _this = self,
            switchProductSpec = switchProductSpec,
        };

        var res = await this.inner.QueryDvsFeatureCapabilityAsync(req);

        return res.QueryDvsFeatureCapabilityResponse.returnval;
    }

    public async System.Threading.Tasks.Task<Event[]?> QueryEvents(ManagedObjectReference self, EventFilterSpec filter, EventManagerEventViewSpec? eventViewSpec)
    {
        var req = new QueryEventsRequestType
        {
            _this = self,
            filter = filter,
            eventViewSpec = eventViewSpec,
        };

        var res = await this.inner.QueryEventsAsync(req);

        return res.QueryEventsResponse1;
    }

    public async System.Threading.Tasks.Task<ProfileExpressionMetadata[]?> QueryExpressionMetadata(ManagedObjectReference self, string[]? expressionName, ManagedObjectReference? profile)
    {
        var req = new QueryExpressionMetadataRequestType
        {
            _this = self,
            expressionName = expressionName,
            profile = profile,
        };

        var res = await this.inner.QueryExpressionMetadataAsync(req);

        return res.QueryExpressionMetadataResponse1;
    }

    public async System.Threading.Tasks.Task<ExtensionManagerIpAllocationUsage[]?> QueryExtensionIpAllocationUsage(ManagedObjectReference self, string[]? extensionKeys)
    {
        var req = new QueryExtensionIpAllocationUsageRequestType
        {
            _this = self,
            extensionKeys = extensionKeys,
        };

        var res = await this.inner.QueryExtensionIpAllocationUsageAsync(req);

        return res.QueryExtensionIpAllocationUsageResponse1;
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibility(ManagedObjectReference self)
    {
        var req = new QueryFaultToleranceCompatibilityRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryFaultToleranceCompatibilityAsync(req);

        return res.QueryFaultToleranceCompatibilityResponse1;
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault[]?> QueryFaultToleranceCompatibilityEx(ManagedObjectReference self, bool forLegacyFt, bool forLegacyFtSpecified)
    {
        var req = new QueryFaultToleranceCompatibilityExRequestType
        {
            _this = self,
            forLegacyFt = forLegacyFt,
            forLegacyFtSpecified = forLegacyFtSpecified,
        };

        var res = await this.inner.QueryFaultToleranceCompatibilityExAsync(req);

        return res.QueryFaultToleranceCompatibilityExResponse1;
    }

    public async System.Threading.Tasks.Task<FileLockInfoResult?> QueryFileLockInfo(ManagedObjectReference self, string path, ManagedObjectReference? host)
    {
        var req = new QueryFileLockInfoRequestType
        {
            _this = self,
            path = path,
            host = host,
        };

        var res = await this.inner.QueryFileLockInfoAsync(req);

        return res.QueryFileLockInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryFilterEntities(ManagedObjectReference self, string filterId)
    {
        var req = new QueryFilterEntitiesRequestType
        {
            _this = self,
            filterId = filterId,
        };

        var res = await this.inner.QueryFilterEntitiesAsync(req);

        return res.QueryFilterEntitiesResponse1;
    }

    public async System.Threading.Tasks.Task<string[]?> QueryFilterInfoIds(ManagedObjectReference self, string filterId)
    {
        var req = new QueryFilterInfoIdsRequestType
        {
            _this = self,
            filterId = filterId,
        };

        var res = await this.inner.QueryFilterInfoIdsAsync(req);

        return res.QueryFilterInfoIdsResponse1;
    }

    public async System.Threading.Tasks.Task<string[]?> QueryFilterList(ManagedObjectReference self, string providerId)
    {
        var req = new QueryFilterListRequestType
        {
            _this = self,
            providerId = providerId,
        };

        var res = await this.inner.QueryFilterListAsync(req);

        return res.QueryFilterListResponse1;
    }

    public async System.Threading.Tasks.Task<string?> QueryFilterName(ManagedObjectReference self, string filterId)
    {
        var req = new QueryFilterNameRequestType
        {
            _this = self,
            filterId = filterId,
        };

        var res = await this.inner.QueryFilterNameAsync(req);

        return res.QueryFilterNameResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryFirmwareConfigUploadURL(ManagedObjectReference self)
    {
        var req = new QueryFirmwareConfigUploadURLRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryFirmwareConfigUploadURLAsync(req);

        return res.QueryFirmwareConfigUploadURLResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HealthUpdateInfo[]?> QueryHealthUpdateInfos(ManagedObjectReference self, string providerId)
    {
        var req = new QueryHealthUpdateInfosRequestType
        {
            _this = self,
            providerId = providerId,
        };

        var res = await this.inner.QueryHealthUpdateInfosAsync(req);

        return res.QueryHealthUpdateInfosResponse1;
    }

    public async System.Threading.Tasks.Task<HealthUpdate[]?> QueryHealthUpdates(ManagedObjectReference self, string providerId)
    {
        var req = new QueryHealthUpdatesRequestType
        {
            _this = self,
            providerId = providerId,
        };

        var res = await this.inner.QueryHealthUpdatesAsync(req);

        return res.QueryHealthUpdatesResponse1;
    }

    public async System.Threading.Tasks.Task<HostConnectInfo?> QueryHostConnectionInfo(ManagedObjectReference self)
    {
        var req = new QueryHostConnectionInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryHostConnectionInfoAsync(req);

        return res.QueryHostConnectionInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> QueryHostPatch_Task(ManagedObjectReference self, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var req = new QueryHostPatchRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.QueryHostPatch_TaskAsync(req);

        return res.QueryHostPatch_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ProfileMetadata[]?> QueryHostProfileMetadata(ManagedObjectReference self, string[]? profileName, ManagedObjectReference? profile)
    {
        var req = new QueryHostProfileMetadataRequestType
        {
            _this = self,
            profileName = profileName,
            profile = profile,
        };

        var res = await this.inner.QueryHostProfileMetadataAsync(req);

        return res.QueryHostProfileMetadataResponse1;
    }

    public async System.Threading.Tasks.Task<VsanHostClusterStatus?> QueryHostStatus(ManagedObjectReference self)
    {
        var req = new QueryHostStatusRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryHostStatusAsync(req);

        return res.QueryHostStatusResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryHostsWithAttachedLun(ManagedObjectReference self, string lunUuid)
    {
        var req = new QueryHostsWithAttachedLunRequestType
        {
            _this = self,
            lunUuid = lunUuid,
        };

        var res = await this.inner.QueryHostsWithAttachedLunAsync(req);

        return res.QueryHostsWithAttachedLunResponse1;
    }

    public async System.Threading.Tasks.Task<ClusterIoFilterInfo[]?> QueryIoFilterInfo(ManagedObjectReference self, ManagedObjectReference compRes)
    {
        var req = new QueryIoFilterInfoRequestType
        {
            _this = self,
            compRes = compRes,
        };

        var res = await this.inner.QueryIoFilterInfoAsync(req);

        return res.QueryIoFilterInfoResponse1;
    }

    public async System.Threading.Tasks.Task<IoFilterQueryIssueResult?> QueryIoFilterIssues(ManagedObjectReference self, string filterId, ManagedObjectReference compRes)
    {
        var req = new QueryIoFilterIssuesRequestType
        {
            _this = self,
            filterId = filterId,
            compRes = compRes,
        };

        var res = await this.inner.QueryIoFilterIssuesAsync(req);

        return res.QueryIoFilterIssuesResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StorageIORMConfigOption?> QueryIORMConfigOption(ManagedObjectReference self, ManagedObjectReference host)
    {
        var req = new QueryIORMConfigOptionRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QueryIORMConfigOptionAsync(req);

        return res.QueryIORMConfigOptionResponse.returnval;
    }

    public async System.Threading.Tasks.Task<IpPoolManagerIpAllocation[]?> QueryIPAllocations(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string extensionKey)
    {
        var req = new QueryIPAllocationsRequestType
        {
            _this = self,
            dc = dc,
            poolId = poolId,
            extensionKey = extensionKey,
        };

        var res = await this.inner.QueryIPAllocationsAsync(req);

        return res.QueryIPAllocationsResponse1;
    }

    public async System.Threading.Tasks.Task<IpPool[]?> QueryIpPools(ManagedObjectReference self, ManagedObjectReference dc)
    {
        var req = new QueryIpPoolsRequestType
        {
            _this = self,
            dc = dc,
        };

        var res = await this.inner.QueryIpPoolsAsync(req);

        return res.QueryIpPoolsResponse1;
    }

    public async System.Threading.Tasks.Task<LicenseAvailabilityInfo[]?> QueryLicenseSourceAvailability(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new QueryLicenseSourceAvailabilityRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QueryLicenseSourceAvailabilityAsync(req);

        return res.QueryLicenseSourceAvailabilityResponse1;
    }

    public async System.Threading.Tasks.Task<LicenseUsageInfo?> QueryLicenseUsage(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new QueryLicenseUsageRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QueryLicenseUsageAsync(req);

        return res.QueryLicenseUsageResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string[]?> QueryLockdownExceptions(ManagedObjectReference self)
    {
        var req = new QueryLockdownExceptionsRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryLockdownExceptionsAsync(req);

        return res.QueryLockdownExceptionsResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryManagedBy(ManagedObjectReference self, string extensionKey)
    {
        var req = new QueryManagedByRequestType
        {
            _this = self,
            extensionKey = extensionKey,
        };

        var res = await this.inner.QueryManagedByAsync(req);

        return res.QueryManagedByResponse1;
    }

    public async System.Threading.Tasks.Task<long> QueryMaxQueueDepth(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new QueryMaxQueueDepthRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.QueryMaxQueueDepthAsync(req);

        return res.QueryMaxQueueDepthResponse.returnval;
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverhead(ManagedObjectReference self, long memorySize, int videoRamSize, bool videoRamSizeSpecified, int numVcpus)
    {
        var req = new QueryMemoryOverheadRequestType
        {
            _this = self,
            memorySize = memorySize,
            videoRamSize = videoRamSize,
            videoRamSizeSpecified = videoRamSizeSpecified,
            numVcpus = numVcpus,
        };

        var res = await this.inner.QueryMemoryOverheadAsync(req);

        return res.QueryMemoryOverheadResponse.returnval;
    }

    public async System.Threading.Tasks.Task<long> QueryMemoryOverheadEx(ManagedObjectReference self, VirtualMachineConfigInfo vmConfigInfo)
    {
        var req = new QueryMemoryOverheadExRequestType
        {
            _this = self,
            vmConfigInfo = vmConfigInfo,
        };

        var res = await this.inner.QueryMemoryOverheadExAsync(req);

        return res.QueryMemoryOverheadExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<IscsiMigrationDependency?> QueryMigrationDependencies(ManagedObjectReference self, string[] pnicDevice)
    {
        var req = new QueryMigrationDependenciesRequestType
        {
            _this = self,
            pnicDevice = pnicDevice,
        };

        var res = await this.inner.QueryMigrationDependenciesAsync(req);

        return res.QueryMigrationDependenciesResponse.returnval;
    }

    public async System.Threading.Tasks.Task<KernelModuleInfo[]?> QueryModules(ManagedObjectReference self)
    {
        var req = new QueryModulesRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryModulesAsync(req);

        return res.QueryModulesResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryMonitoredEntities(ManagedObjectReference self, string providerId)
    {
        var req = new QueryMonitoredEntitiesRequestType
        {
            _this = self,
            providerId = providerId,
        };

        var res = await this.inner.QueryMonitoredEntitiesAsync(req);

        return res.QueryMonitoredEntitiesResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualNicManagerNetConfig?> QueryNetConfig(ManagedObjectReference self, string nicType)
    {
        var req = new QueryNetConfigRequestType
        {
            _this = self,
            nicType = nicType,
        };

        var res = await this.inner.QueryNetConfigAsync(req);

        return res.QueryNetConfigResponse.returnval;
    }

    public async System.Threading.Tasks.Task<PhysicalNicHintInfo[]?> QueryNetworkHint(ManagedObjectReference self, string[]? device)
    {
        var req = new QueryNetworkHintRequestType
        {
            _this = self,
            device = device,
        };

        var res = await this.inner.QueryNetworkHintAsync(req);

        return res.QueryNetworkHintResponse1;
    }

    public async System.Threading.Tasks.Task<HostNasVolumeUserInfo?> QueryNFSUser(ManagedObjectReference self)
    {
        var req = new QueryNFSUserRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryNFSUserAsync(req);

        return res.QueryNFSUserResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryObjectsOnPhysicalVsanDisk(ManagedObjectReference self, string[] disks)
    {
        var req = new QueryObjectsOnPhysicalVsanDiskRequestType
        {
            _this = self,
            disks = disks,
        };

        var res = await this.inner.QueryObjectsOnPhysicalVsanDiskAsync(req);

        return res.QueryObjectsOnPhysicalVsanDiskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<OptionValue[]?> QueryOptions(ManagedObjectReference self, string? name)
    {
        var req = new QueryOptionsRequestType
        {
            _this = self,
            name = name,
        };

        var res = await this.inner.QueryOptionsAsync(req);

        return res.QueryOptionsResponse1;
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateDescription?> QueryPartitionCreateDesc(ManagedObjectReference self, string diskUuid, string diagnosticType)
    {
        var req = new QueryPartitionCreateDescRequestType
        {
            _this = self,
            diskUuid = diskUuid,
            diagnosticType = diagnosticType,
        };

        var res = await this.inner.QueryPartitionCreateDescAsync(req);

        return res.QueryPartitionCreateDescResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostDiagnosticPartitionCreateOption[]?> QueryPartitionCreateOptions(ManagedObjectReference self, string storageType, string diagnosticType)
    {
        var req = new QueryPartitionCreateOptionsRequestType
        {
            _this = self,
            storageType = storageType,
            diagnosticType = diagnosticType,
        };

        var res = await this.inner.QueryPartitionCreateOptionsAsync(req);

        return res.QueryPartitionCreateOptionsResponse1;
    }

    public async System.Threading.Tasks.Task<HostPathSelectionPolicyOption[]?> QueryPathSelectionPolicyOptions(ManagedObjectReference self)
    {
        var req = new QueryPathSelectionPolicyOptionsRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryPathSelectionPolicyOptionsAsync(req);

        return res.QueryPathSelectionPolicyOptionsResponse1;
    }

    public async System.Threading.Tasks.Task<PerfEntityMetricBase[]?> QueryPerf(ManagedObjectReference self, PerfQuerySpec[] querySpec)
    {
        var req = new QueryPerfRequestType
        {
            _this = self,
            querySpec = querySpec,
        };

        var res = await this.inner.QueryPerfAsync(req);

        return res.QueryPerfResponse1;
    }

    public async System.Threading.Tasks.Task<PerfCompositeMetric?> QueryPerfComposite(ManagedObjectReference self, PerfQuerySpec querySpec)
    {
        var req = new QueryPerfCompositeRequestType
        {
            _this = self,
            querySpec = querySpec,
        };

        var res = await this.inner.QueryPerfCompositeAsync(req);

        return res.QueryPerfCompositeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounter(ManagedObjectReference self, int[] counterId)
    {
        var req = new QueryPerfCounterRequestType
        {
            _this = self,
            counterId = counterId,
        };

        var res = await this.inner.QueryPerfCounterAsync(req);

        return res.QueryPerfCounterResponse1;
    }

    public async System.Threading.Tasks.Task<PerfCounterInfo[]?> QueryPerfCounterByLevel(ManagedObjectReference self, int level)
    {
        var req = new QueryPerfCounterByLevelRequestType
        {
            _this = self,
            level = level,
        };

        var res = await this.inner.QueryPerfCounterByLevelAsync(req);

        return res.QueryPerfCounterByLevelResponse1;
    }

    public async System.Threading.Tasks.Task<PerfProviderSummary?> QueryPerfProviderSummary(ManagedObjectReference self, ManagedObjectReference entity)
    {
        var req = new QueryPerfProviderSummaryRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.QueryPerfProviderSummaryAsync(req);

        return res.QueryPerfProviderSummaryResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryPhysicalVsanDisks(ManagedObjectReference self, string[]? props)
    {
        var req = new QueryPhysicalVsanDisksRequestType
        {
            _this = self,
            props = props,
        };

        var res = await this.inner.QueryPhysicalVsanDisksAsync(req);

        return res.QueryPhysicalVsanDisksResponse.returnval;
    }

    public async System.Threading.Tasks.Task<IscsiStatus?> QueryPnicStatus(ManagedObjectReference self, string pnicDevice)
    {
        var req = new QueryPnicStatusRequestType
        {
            _this = self,
            pnicDevice = pnicDevice,
        };

        var res = await this.inner.QueryPnicStatusAsync(req);

        return res.QueryPnicStatusResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ProfilePolicyMetadata[]?> QueryPolicyMetadata(ManagedObjectReference self, string[]? policyName, ManagedObjectReference? profile)
    {
        var req = new QueryPolicyMetadataRequestType
        {
            _this = self,
            policyName = policyName,
            profile = profile,
        };

        var res = await this.inner.QueryPolicyMetadataAsync(req);

        return res.QueryPolicyMetadataResponse1;
    }

    public async System.Threading.Tasks.Task<string?> QueryProductLockerLocation(ManagedObjectReference self)
    {
        var req = new QueryProductLockerLocationRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryProductLockerLocationAsync(req);

        return res.QueryProductLockerLocationResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ProfileProfileStructure?> QueryProfileStructure(ManagedObjectReference self, ManagedObjectReference? profile)
    {
        var req = new QueryProfileStructureRequestType
        {
            _this = self,
            profile = profile,
        };

        var res = await this.inner.QueryProfileStructureAsync(req);

        return res.QueryProfileStructureResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string[]?> QueryProviderList(ManagedObjectReference self)
    {
        var req = new QueryProviderListRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryProviderListAsync(req);

        return res.QueryProviderListResponse1;
    }

    public async System.Threading.Tasks.Task<string?> QueryProviderName(ManagedObjectReference self, string id)
    {
        var req = new QueryProviderNameRequestType
        {
            _this = self,
            id = id,
        };

        var res = await this.inner.QueryProviderNameAsync(req);

        return res.QueryProviderNameResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ResourceConfigOption?> QueryResourceConfigOption(ManagedObjectReference self)
    {
        var req = new QueryResourceConfigOptionRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryResourceConfigOptionAsync(req);

        return res.QueryResourceConfigOptionResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ServiceManagerServiceInfo[]?> QueryServiceList(ManagedObjectReference self, string? serviceName, string[]? location)
    {
        var req = new QueryServiceListRequestType
        {
            _this = self,
            serviceName = serviceName,
            location = location,
        };

        var res = await this.inner.QueryServiceListAsync(req);

        return res.QueryServiceListResponse1;
    }

    public async System.Threading.Tasks.Task<HostStorageArrayTypePolicyOption[]?> QueryStorageArrayTypePolicyOptions(ManagedObjectReference self)
    {
        var req = new QueryStorageArrayTypePolicyOptionsRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryStorageArrayTypePolicyOptionsAsync(req);

        return res.QueryStorageArrayTypePolicyOptionsResponse1;
    }

    public async System.Threading.Tasks.Task<LicenseFeatureInfo[]?> QuerySupportedFeatures(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new QuerySupportedFeaturesRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QuerySupportedFeaturesAsync(req);

        return res.QuerySupportedFeaturesResponse1;
    }

    public async System.Threading.Tasks.Task<DistributedVirtualSwitchNetworkOffloadSpec[]?> QuerySupportedNetworkOffloadSpec(ManagedObjectReference self, DistributedVirtualSwitchProductSpec switchProductSpec)
    {
        var req = new QuerySupportedNetworkOffloadSpecRequestType
        {
            _this = self,
            switchProductSpec = switchProductSpec,
        };

        var res = await this.inner.QuerySupportedNetworkOffloadSpecAsync(req);

        return res.QuerySupportedNetworkOffloadSpecResponse1;
    }

    public async System.Threading.Tasks.Task<string?> QuerySyncingVsanObjects(ManagedObjectReference self, string[]? uuids)
    {
        var req = new QuerySyncingVsanObjectsRequestType
        {
            _this = self,
            uuids = uuids,
        };

        var res = await this.inner.QuerySyncingVsanObjectsAsync(req);

        return res.QuerySyncingVsanObjectsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string[]?> QuerySystemUsers(ManagedObjectReference self)
    {
        var req = new QuerySystemUsersRequestType
        {
            _this = self,
        };

        var res = await this.inner.QuerySystemUsersAsync(req);

        return res.QuerySystemUsersResponse1;
    }

    public async System.Threading.Tasks.Task<HostCapability?> QueryTargetCapabilities(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new QueryTargetCapabilitiesRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.QueryTargetCapabilitiesAsync(req);

        return res.QueryTargetCapabilitiesResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostTpmAttestationReport?> QueryTpmAttestationReport(ManagedObjectReference self)
    {
        var req = new QueryTpmAttestationReportRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryTpmAttestationReportAsync(req);

        return res.QueryTpmAttestationReportResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> QueryUnmonitoredHosts(ManagedObjectReference self, string providerId, ManagedObjectReference cluster)
    {
        var req = new QueryUnmonitoredHostsRequestType
        {
            _this = self,
            providerId = providerId,
            cluster = cluster,
        };

        var res = await this.inner.QueryUnmonitoredHostsAsync(req);

        return res.QueryUnmonitoredHostsResponse1;
    }

    public async System.Threading.Tasks.Task<string[]?> QueryUnownedFiles(ManagedObjectReference self)
    {
        var req = new QueryUnownedFilesRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryUnownedFilesAsync(req);

        return res.QueryUnownedFilesResponse1;
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolume(ManagedObjectReference self)
    {
        var req = new QueryUnresolvedVmfsVolumeRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryUnresolvedVmfsVolumeAsync(req);

        return res.QueryUnresolvedVmfsVolumeResponse1;
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsVolume[]?> QueryUnresolvedVmfsVolumes(ManagedObjectReference self)
    {
        var req = new QueryUnresolvedVmfsVolumesRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryUnresolvedVmfsVolumesAsync(req);

        return res.QueryUnresolvedVmfsVolumesResponse1;
    }

    public async System.Threading.Tasks.Task<int[]?> QueryUsedVlanIdInDvs(ManagedObjectReference self)
    {
        var req = new QueryUsedVlanIdInDvsRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryUsedVlanIdInDvsAsync(req);

        return res.QueryUsedVlanIdInDvsResponse1;
    }

    public async System.Threading.Tasks.Task<int> QueryVirtualDiskFragmentation(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new QueryVirtualDiskFragmentationRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.QueryVirtualDiskFragmentationAsync(req);

        return res.QueryVirtualDiskFragmentationResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostDiskDimensionsChs?> QueryVirtualDiskGeometry(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new QueryVirtualDiskGeometryRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.QueryVirtualDiskGeometryAsync(req);

        return res.QueryVirtualDiskGeometryResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryVirtualDiskUuid(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new QueryVirtualDiskUuidRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.QueryVirtualDiskUuidAsync(req);

        return res.QueryVirtualDiskUuidResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryVirtualDiskUuidEx(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new QueryVirtualDiskUuidExRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.QueryVirtualDiskUuidExAsync(req);

        return res.QueryVirtualDiskUuidExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VmfsConfigOption[]?> QueryVmfsConfigOption(ManagedObjectReference self)
    {
        var req = new QueryVmfsConfigOptionRequestType
        {
            _this = self,
        };

        var res = await this.inner.QueryVmfsConfigOptionAsync(req);

        return res.QueryVmfsConfigOptionResponse1;
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreCreateOptions(ManagedObjectReference self, string devicePath, int vmfsMajorVersion, bool vmfsMajorVersionSpecified)
    {
        var req = new QueryVmfsDatastoreCreateOptionsRequestType
        {
            _this = self,
            devicePath = devicePath,
            vmfsMajorVersion = vmfsMajorVersion,
            vmfsMajorVersionSpecified = vmfsMajorVersionSpecified,
        };

        var res = await this.inner.QueryVmfsDatastoreCreateOptionsAsync(req);

        return res.QueryVmfsDatastoreCreateOptionsResponse1;
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExpandOptions(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new QueryVmfsDatastoreExpandOptionsRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.QueryVmfsDatastoreExpandOptionsAsync(req);

        return res.QueryVmfsDatastoreExpandOptionsResponse1;
    }

    public async System.Threading.Tasks.Task<VmfsDatastoreOption[]?> QueryVmfsDatastoreExtendOptions(ManagedObjectReference self, ManagedObjectReference datastore, string devicePath, bool suppressExpandCandidates, bool suppressExpandCandidatesSpecified)
    {
        var req = new QueryVmfsDatastoreExtendOptionsRequestType
        {
            _this = self,
            datastore = datastore,
            devicePath = devicePath,
            suppressExpandCandidates = suppressExpandCandidates,
            suppressExpandCandidatesSpecified = suppressExpandCandidatesSpecified,
        };

        var res = await this.inner.QueryVmfsDatastoreExtendOptionsAsync(req);

        return res.QueryVmfsDatastoreExtendOptionsResponse1;
    }

    public async System.Threading.Tasks.Task<HostVMotionCompatibility[]?> QueryVMotionCompatibility(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference[] host, string[]? compatibility)
    {
        var req = new QueryVMotionCompatibilityRequestType
        {
            _this = self,
            vm = vm,
            host = host,
            compatibility = compatibility,
        };

        var res = await this.inner.QueryVMotionCompatibilityAsync(req);

        return res.QueryVMotionCompatibilityResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> QueryVMotionCompatibilityEx_Task(ManagedObjectReference self, ManagedObjectReference[] vm, ManagedObjectReference[] host)
    {
        var req = new QueryVMotionCompatibilityExRequestType
        {
            _this = self,
            vm = vm,
            host = host,
        };

        var res = await this.inner.QueryVMotionCompatibilityEx_TaskAsync(req);

        return res.QueryVMotionCompatibilityEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<IscsiStatus?> QueryVnicStatus(ManagedObjectReference self, string vnicDevice)
    {
        var req = new QueryVnicStatusRequestType
        {
            _this = self,
            vnicDevice = vnicDevice,
        };

        var res = await this.inner.QueryVnicStatusAsync(req);

        return res.QueryVnicStatusResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> QueryVsanObjects(ManagedObjectReference self, string[]? uuids)
    {
        var req = new QueryVsanObjectsRequestType
        {
            _this = self,
            uuids = uuids,
        };

        var res = await this.inner.QueryVsanObjectsAsync(req);

        return res.QueryVsanObjectsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string[]?> QueryVsanObjectUuidsByFilter(ManagedObjectReference self, string[]? uuids, int limit, bool limitSpecified, int version, bool versionSpecified)
    {
        var req = new QueryVsanObjectUuidsByFilterRequestType
        {
            _this = self,
            uuids = uuids,
            limit = limit,
            limitSpecified = limitSpecified,
            version = version,
            versionSpecified = versionSpecified,
        };

        var res = await this.inner.QueryVsanObjectUuidsByFilterAsync(req);

        return res.QueryVsanObjectUuidsByFilterResponse1;
    }

    public async System.Threading.Tasks.Task<string?> QueryVsanStatistics(ManagedObjectReference self, string[] labels)
    {
        var req = new QueryVsanStatisticsRequestType
        {
            _this = self,
            labels = labels,
        };

        var res = await this.inner.QueryVsanStatisticsAsync(req);

        return res.QueryVsanStatisticsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VsanUpgradeSystemUpgradeStatus?> QueryVsanUpgradeStatus(ManagedObjectReference self, ManagedObjectReference cluster)
    {
        var req = new QueryVsanUpgradeStatusRequestType
        {
            _this = self,
            cluster = cluster,
        };

        var res = await this.inner.QueryVsanUpgradeStatusAsync(req);

        return res.QueryVsanUpgradeStatusResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string[]?> ReadEnvironmentVariableInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string[]? names)
    {
        var req = new ReadEnvironmentVariableInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            names = names,
        };

        var res = await this.inner.ReadEnvironmentVariableInGuestAsync(req);

        return res.ReadEnvironmentVariableInGuestResponse1;
    }

    public async System.Threading.Tasks.Task<Event[]?> ReadNextEvents(ManagedObjectReference self, int maxCount)
    {
        var req = new ReadNextEventsRequestType
        {
            _this = self,
            maxCount = maxCount,
        };

        var res = await this.inner.ReadNextEventsAsync(req);

        return res.ReadNextEventsResponse1;
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadNextTasks(ManagedObjectReference self, int maxCount)
    {
        var req = new ReadNextTasksRequestType
        {
            _this = self,
            maxCount = maxCount,
        };

        var res = await this.inner.ReadNextTasksAsync(req);

        return res.ReadNextTasksResponse1;
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadNextTasksByViewSpec(ManagedObjectReference self, TaskManagerTaskViewSpec viewSpec, TaskFilterSpec filterSpec, TaskInfoFilterSpec? infoFilterSpec)
    {
        var req = new ReadNextTasksByViewSpecRequestType
        {
            _this = self,
            viewSpec = viewSpec,
            filterSpec = filterSpec,
            infoFilterSpec = infoFilterSpec,
        };

        var res = await this.inner.ReadNextTasksByViewSpecAsync(req);

        return res.ReadNextTasksByViewSpecResponse1;
    }

    public async System.Threading.Tasks.Task<Event[]?> ReadPreviousEvents(ManagedObjectReference self, int maxCount)
    {
        var req = new ReadPreviousEventsRequestType
        {
            _this = self,
            maxCount = maxCount,
        };

        var res = await this.inner.ReadPreviousEventsAsync(req);

        return res.ReadPreviousEventsResponse1;
    }

    public async System.Threading.Tasks.Task<TaskInfo[]?> ReadPreviousTasks(ManagedObjectReference self, int maxCount)
    {
        var req = new ReadPreviousTasksRequestType
        {
            _this = self,
            maxCount = maxCount,
        };

        var res = await this.inner.ReadPreviousTasksAsync(req);

        return res.ReadPreviousTasksResponse1;
    }

    public async System.Threading.Tasks.Task RebootGuest(ManagedObjectReference self)
    {
        var req = new RebootGuestRequestType
        {
            _this = self,
        };

        await this.inner.RebootGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RebootHost_Task(ManagedObjectReference self, bool force)
    {
        var req = new RebootHostRequestType
        {
            _this = self,
            force = force,
        };

        var res = await this.inner.RebootHost_TaskAsync(req);

        return res.RebootHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<StoragePlacementResult?> RecommendDatastores(ManagedObjectReference self, StoragePlacementSpec storageSpec)
    {
        var req = new RecommendDatastoresRequestType
        {
            _this = self,
            storageSpec = storageSpec,
        };

        var res = await this.inner.RecommendDatastoresAsync(req);

        return res.RecommendDatastoresResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ClusterHostRecommendation[]?> RecommendHostsForVm(ManagedObjectReference self, ManagedObjectReference vm, ManagedObjectReference? pool)
    {
        var req = new RecommendHostsForVmRequestType
        {
            _this = self,
            vm = vm,
            pool = pool,
        };

        var res = await this.inner.RecommendHostsForVmAsync(req);

        return res.RecommendHostsForVmResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RecommissionVsanNode_Task(ManagedObjectReference self)
    {
        var req = new RecommissionVsanNodeRequestType
        {
            _this = self,
        };

        var res = await this.inner.RecommissionVsanNode_TaskAsync(req);

        return res.RecommissionVsanNode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconcileDatastoreInventory_Task(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified)
    {
        var req = new ReconcileDatastoreInventoryRequestType
        {
            _this = self,
            datastore = datastore,
            deepCleansing = deepCleansing,
            deepCleansingSpecified = deepCleansingSpecified,
        };

        var res = await this.inner.ReconcileDatastoreInventory_TaskAsync(req);

        return res.ReconcileDatastoreInventory_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconcileDatastoreInventoryEx_Task(ManagedObjectReference self, VStorageObjectReconcileSpec spec)
    {
        var req = new ReconcileDatastoreInventoryExRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.ReconcileDatastoreInventoryEx_TaskAsync(req);

        return res.ReconcileDatastoreInventoryEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VsanPolicySatisfiability[]?> ReconfigurationSatisfiable(ManagedObjectReference self, VsanPolicyChangeBatch[] pcbs, bool ignoreSatisfiability, bool ignoreSatisfiabilitySpecified)
    {
        var req = new ReconfigurationSatisfiableRequestType
        {
            _this = self,
            pcbs = pcbs,
            ignoreSatisfiability = ignoreSatisfiability,
            ignoreSatisfiabilitySpecified = ignoreSatisfiabilitySpecified,
        };

        var res = await this.inner.ReconfigurationSatisfiableAsync(req);

        return res.ReconfigurationSatisfiableResponse1;
    }

    public async System.Threading.Tasks.Task ReconfigureAlarm(ManagedObjectReference self, AlarmSpec spec)
    {
        var req = new ReconfigureAlarmRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.ReconfigureAlarmAsync(req);
    }

    public async System.Threading.Tasks.Task ReconfigureAutostart(ManagedObjectReference self, HostAutoStartManagerConfig spec)
    {
        var req = new ReconfigureAutostartRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.ReconfigureAutostartAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureCluster_Task(ManagedObjectReference self, ClusterConfigSpec spec, bool modify)
    {
        var req = new ReconfigureClusterRequestType
        {
            _this = self,
            spec = spec,
            modify = modify,
        };

        var res = await this.inner.ReconfigureCluster_TaskAsync(req);

        return res.ReconfigureCluster_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureComputeResource_Task(ManagedObjectReference self, ComputeResourceConfigSpec spec, bool modify)
    {
        var req = new ReconfigureComputeResourceRequestType
        {
            _this = self,
            spec = spec,
            modify = modify,
        };

        var res = await this.inner.ReconfigureComputeResource_TaskAsync(req);

        return res.ReconfigureComputeResource_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDatacenter_Task(ManagedObjectReference self, DatacenterConfigSpec spec, bool modify)
    {
        var req = new ReconfigureDatacenterRequestType
        {
            _this = self,
            spec = spec,
            modify = modify,
        };

        var res = await this.inner.ReconfigureDatacenter_TaskAsync(req);

        return res.ReconfigureDatacenter_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ReconfigureDomObject(ManagedObjectReference self, string uuid, string policy)
    {
        var req = new ReconfigureDomObjectRequestType
        {
            _this = self,
            uuid = uuid,
            policy = policy,
        };

        await this.inner.ReconfigureDomObjectAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDVPort_Task(ManagedObjectReference self, DVPortConfigSpec[] port)
    {
        var req = new ReconfigureDVPortRequestType
        {
            _this = self,
            port = port,
        };

        var res = await this.inner.ReconfigureDVPort_TaskAsync(req);

        return res.ReconfigureDVPort_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDVPortgroup_Task(ManagedObjectReference self, DVPortgroupConfigSpec spec)
    {
        var req = new ReconfigureDVPortgroupRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.ReconfigureDVPortgroup_TaskAsync(req);

        return res.ReconfigureDVPortgroup_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureDvs_Task(ManagedObjectReference self, DVSConfigSpec spec)
    {
        var req = new ReconfigureDvsRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.ReconfigureDvs_TaskAsync(req);

        return res.ReconfigureDvs_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigureHostForDAS_Task(ManagedObjectReference self)
    {
        var req = new ReconfigureHostForDASRequestType
        {
            _this = self,
        };

        var res = await this.inner.ReconfigureHostForDAS_TaskAsync(req);

        return res.ReconfigureHostForDAS_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ReconfigureScheduledTask(ManagedObjectReference self, ScheduledTaskSpec spec)
    {
        var req = new ReconfigureScheduledTaskRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.ReconfigureScheduledTaskAsync(req);
    }

    public async System.Threading.Tasks.Task ReconfigureServiceConsoleReservation(ManagedObjectReference self, long cfgBytes)
    {
        var req = new ReconfigureServiceConsoleReservationRequestType
        {
            _this = self,
            cfgBytes = cfgBytes,
        };

        await this.inner.ReconfigureServiceConsoleReservationAsync(req);
    }

    public async System.Threading.Tasks.Task ReconfigureSnmpAgent(ManagedObjectReference self, HostSnmpConfigSpec spec)
    {
        var req = new ReconfigureSnmpAgentRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.ReconfigureSnmpAgentAsync(req);
    }

    public async System.Threading.Tasks.Task ReconfigureVirtualMachineReservation(ManagedObjectReference self, VirtualMachineMemoryReservationSpec spec)
    {
        var req = new ReconfigureVirtualMachineReservationRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.ReconfigureVirtualMachineReservationAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconfigVM_Task(ManagedObjectReference self, VirtualMachineConfigSpec spec)
    {
        var req = new ReconfigVMRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.ReconfigVM_TaskAsync(req);

        return res.ReconfigVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReconnectHost_Task(ManagedObjectReference self, HostConnectSpec? cnxSpec, HostSystemReconnectSpec? reconnectSpec)
    {
        var req = new ReconnectHostRequestType
        {
            _this = self,
            cnxSpec = cnxSpec,
            reconnectSpec = reconnectSpec,
        };

        var res = await this.inner.ReconnectHost_TaskAsync(req);

        return res.ReconnectHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RectifyDvsHost_Task(ManagedObjectReference self, ManagedObjectReference[]? hosts)
    {
        var req = new RectifyDvsHostRequestType
        {
            _this = self,
            hosts = hosts,
        };

        var res = await this.inner.RectifyDvsHost_TaskAsync(req);

        return res.RectifyDvsHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RectifyDvsOnHost_Task(ManagedObjectReference self, ManagedObjectReference[] hosts)
    {
        var req = new RectifyDvsOnHostRequestType
        {
            _this = self,
            hosts = hosts,
        };

        var res = await this.inner.RectifyDvsOnHost_TaskAsync(req);

        return res.RectifyDvsOnHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task Refresh(ManagedObjectReference self)
    {
        var req = new RefreshRequestType
        {
            _this = self,
        };

        await this.inner.RefreshAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshDatastore(ManagedObjectReference self)
    {
        var req = new RefreshDatastoreRequestType
        {
            _this = self,
        };

        await this.inner.RefreshDatastoreAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshDatastoreStorageInfo(ManagedObjectReference self)
    {
        var req = new RefreshDatastoreStorageInfoRequestType
        {
            _this = self,
        };

        await this.inner.RefreshDatastoreStorageInfoAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshDateTimeSystem(ManagedObjectReference self)
    {
        var req = new RefreshDateTimeSystemRequestType
        {
            _this = self,
        };

        await this.inner.RefreshDateTimeSystemAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshDVPortState(ManagedObjectReference self, string[]? portKeys)
    {
        var req = new RefreshDVPortStateRequestType
        {
            _this = self,
            portKeys = portKeys,
        };

        await this.inner.RefreshDVPortStateAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshFirewall(ManagedObjectReference self)
    {
        var req = new RefreshFirewallRequestType
        {
            _this = self,
        };

        await this.inner.RefreshFirewallAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshGraphicsManager(ManagedObjectReference self)
    {
        var req = new RefreshGraphicsManagerRequestType
        {
            _this = self,
        };

        await this.inner.RefreshGraphicsManagerAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshHealthStatusSystem(ManagedObjectReference self)
    {
        var req = new RefreshHealthStatusSystemRequestType
        {
            _this = self,
        };

        await this.inner.RefreshHealthStatusSystemAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshNetworkSystem(ManagedObjectReference self)
    {
        var req = new RefreshNetworkSystemRequestType
        {
            _this = self,
        };

        await this.inner.RefreshNetworkSystemAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshRecommendation(ManagedObjectReference self)
    {
        var req = new RefreshRecommendationRequestType
        {
            _this = self,
        };

        await this.inner.RefreshRecommendationAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshRuntime(ManagedObjectReference self)
    {
        var req = new RefreshRuntimeRequestType
        {
            _this = self,
        };

        await this.inner.RefreshRuntimeAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshServices(ManagedObjectReference self)
    {
        var req = new RefreshServicesRequestType
        {
            _this = self,
        };

        await this.inner.RefreshServicesAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshStorageDrsRecommendation(ManagedObjectReference self, ManagedObjectReference pod)
    {
        var req = new RefreshStorageDrsRecommendationRequestType
        {
            _this = self,
            pod = pod,
        };

        await this.inner.RefreshStorageDrsRecommendationAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RefreshStorageDrsRecommendationsForPod_Task(ManagedObjectReference self, ManagedObjectReference pod)
    {
        var req = new RefreshStorageDrsRecommendationsForPodRequestType
        {
            _this = self,
            pod = pod,
        };

        var res = await this.inner.RefreshStorageDrsRecommendationsForPod_TaskAsync(req);

        return res.RefreshStorageDrsRecommendationsForPod_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RefreshStorageInfo(ManagedObjectReference self)
    {
        var req = new RefreshStorageInfoRequestType
        {
            _this = self,
        };

        await this.inner.RefreshStorageInfoAsync(req);
    }

    public async System.Threading.Tasks.Task RefreshStorageSystem(ManagedObjectReference self)
    {
        var req = new RefreshStorageSystemRequestType
        {
            _this = self,
        };

        await this.inner.RefreshStorageSystemAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RegisterChildVM_Task(ManagedObjectReference self, string path, string? name, ManagedObjectReference? host)
    {
        var req = new RegisterChildVMRequestType
        {
            _this = self,
            path = path,
            name = name,
            host = host,
        };

        var res = await this.inner.RegisterChildVM_TaskAsync(req);

        return res.RegisterChildVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObject?> RegisterDisk(ManagedObjectReference self, string path, string? name)
    {
        var req = new RegisterDiskRequestType
        {
            _this = self,
            path = path,
            name = name,
        };

        var res = await this.inner.RegisterDiskAsync(req);

        return res.RegisterDiskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RegisterExtension(ManagedObjectReference self, Extension extension)
    {
        var req = new RegisterExtensionRequestType
        {
            _this = self,
            extension = extension,
        };

        await this.inner.RegisterExtensionAsync(req);
    }

    public async System.Threading.Tasks.Task<string?> RegisterHealthUpdateProvider(ManagedObjectReference self, string name, HealthUpdateInfo[]? healthUpdateInfo)
    {
        var req = new RegisterHealthUpdateProviderRequestType
        {
            _this = self,
            name = name,
            healthUpdateInfo = healthUpdateInfo,
        };

        var res = await this.inner.RegisterHealthUpdateProviderAsync(req);

        return res.RegisterHealthUpdateProviderResponse.returnval;
    }

    public async System.Threading.Tasks.Task RegisterKmipServer(ManagedObjectReference self, KmipServerSpec server)
    {
        var req = new RegisterKmipServerRequestType
        {
            _this = self,
            server = server,
        };

        await this.inner.RegisterKmipServerAsync(req);
    }

    public async System.Threading.Tasks.Task RegisterKmsCluster(ManagedObjectReference self, KeyProviderId clusterId, string? managementType)
    {
        var req = new RegisterKmsClusterRequestType
        {
            _this = self,
            clusterId = clusterId,
            managementType = managementType,
        };

        await this.inner.RegisterKmsClusterAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RegisterVM_Task(ManagedObjectReference self, string path, string? name, bool asTemplate, ManagedObjectReference? pool, ManagedObjectReference? host)
    {
        var req = new RegisterVMRequestType
        {
            _this = self,
            path = path,
            name = name,
            asTemplate = asTemplate,
            pool = pool,
            host = host,
        };

        var res = await this.inner.RegisterVM_TaskAsync(req);

        return res.RegisterVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ReleaseCredentialsInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth)
    {
        var req = new ReleaseCredentialsInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
        };

        await this.inner.ReleaseCredentialsInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task ReleaseIpAllocation(ManagedObjectReference self, ManagedObjectReference dc, int poolId, string allocationId)
    {
        var req = new ReleaseIpAllocationRequestType
        {
            _this = self,
            dc = dc,
            poolId = poolId,
            allocationId = allocationId,
        };

        await this.inner.ReleaseIpAllocationAsync(req);
    }

    public async System.Threading.Tasks.Task ReleaseManagedSnapshot(ManagedObjectReference self, string vdisk, ManagedObjectReference? datacenter)
    {
        var req = new ReleaseManagedSnapshotRequestType
        {
            _this = self,
            vdisk = vdisk,
            datacenter = datacenter,
        };

        await this.inner.ReleaseManagedSnapshotAsync(req);
    }

    public async System.Threading.Tasks.Task Reload(ManagedObjectReference self)
    {
        var req = new ReloadRequestType
        {
            _this = self,
        };

        await this.inner.ReloadAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ReloadVirtualMachineFromPath_Task(ManagedObjectReference self, string configurationPath)
    {
        var req = new reloadVirtualMachineFromPathRequestType
        {
            _this = self,
            configurationPath = configurationPath,
        };

        var res = await this.inner.reloadVirtualMachineFromPath_TaskAsync(req);

        return res.reloadVirtualMachineFromPath_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RelocateVM_Task(ManagedObjectReference self, VirtualMachineRelocateSpec spec, VirtualMachineMovePriority priority, bool prioritySpecified)
    {
        var req = new RelocateVMRequestType
        {
            _this = self,
            spec = spec,
            priority = priority,
            prioritySpecified = prioritySpecified,
        };

        var res = await this.inner.RelocateVM_TaskAsync(req);

        return res.RelocateVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RelocateVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VslmRelocateSpec spec)
    {
        var req = new RelocateVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            spec = spec,
        };

        var res = await this.inner.RelocateVStorageObject_TaskAsync(req);

        return res.RelocateVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RemoveAlarm(ManagedObjectReference self)
    {
        var req = new RemoveAlarmRequestType
        {
            _this = self,
        };

        await this.inner.RemoveAlarmAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RemoveAllSnapshots_Task(ManagedObjectReference self, bool consolidate, bool consolidateSpecified, SnapshotSelectionSpec? spec)
    {
        var req = new RemoveAllSnapshotsRequestType
        {
            _this = self,
            consolidate = consolidate,
            consolidateSpecified = consolidateSpecified,
            spec = spec,
        };

        var res = await this.inner.RemoveAllSnapshots_TaskAsync(req);

        return res.RemoveAllSnapshots_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RemoveAssignedLicense(ManagedObjectReference self, string entityId)
    {
        var req = new RemoveAssignedLicenseRequestType
        {
            _this = self,
            entityId = entityId,
        };

        await this.inner.RemoveAssignedLicenseAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveAuthorizationRole(ManagedObjectReference self, int roleId, bool failIfUsed)
    {
        var req = new RemoveAuthorizationRoleRequestType
        {
            _this = self,
            roleId = roleId,
            failIfUsed = failIfUsed,
        };

        await this.inner.RemoveAuthorizationRoleAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveCustomFieldDef(ManagedObjectReference self, int key)
    {
        var req = new RemoveCustomFieldDefRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.RemoveCustomFieldDefAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveDatastore(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new RemoveDatastoreRequestType
        {
            _this = self,
            datastore = datastore,
        };

        await this.inner.RemoveDatastoreAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RemoveDatastoreEx_Task(ManagedObjectReference self, ManagedObjectReference[] datastore)
    {
        var req = new RemoveDatastoreExRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.RemoveDatastoreEx_TaskAsync(req);

        return res.RemoveDatastoreEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RemoveDisk_Task(ManagedObjectReference self, HostScsiDisk[] disk, HostMaintenanceSpec? maintenanceSpec, int timeout, bool timeoutSpecified)
    {
        var req = new RemoveDiskRequestType
        {
            _this = self,
            disk = disk,
            maintenanceSpec = maintenanceSpec,
            timeout = timeout,
            timeoutSpecified = timeoutSpecified,
        };

        var res = await this.inner.RemoveDisk_TaskAsync(req);

        return res.RemoveDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RemoveDiskMapping_Task(ManagedObjectReference self, VsanHostDiskMapping[] mapping, HostMaintenanceSpec? maintenanceSpec, int timeout, bool timeoutSpecified)
    {
        var req = new RemoveDiskMappingRequestType
        {
            _this = self,
            mapping = mapping,
            maintenanceSpec = maintenanceSpec,
            timeout = timeout,
            timeoutSpecified = timeoutSpecified,
        };

        var res = await this.inner.RemoveDiskMapping_TaskAsync(req);

        return res.RemoveDiskMapping_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RemoveEntityPermission(ManagedObjectReference self, ManagedObjectReference entity, string user, bool isGroup)
    {
        var req = new RemoveEntityPermissionRequestType
        {
            _this = self,
            entity = entity,
            user = user,
            isGroup = isGroup,
        };

        await this.inner.RemoveEntityPermissionAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveFilter(ManagedObjectReference self, string filterId)
    {
        var req = new RemoveFilterRequestType
        {
            _this = self,
            filterId = filterId,
        };

        await this.inner.RemoveFilterAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveFilterEntities(ManagedObjectReference self, string filterId, ManagedObjectReference[]? entities)
    {
        var req = new RemoveFilterEntitiesRequestType
        {
            _this = self,
            filterId = filterId,
            entities = entities,
        };

        await this.inner.RemoveFilterEntitiesAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveGroup(ManagedObjectReference self, string groupName)
    {
        var req = new RemoveGroupRequestType
        {
            _this = self,
            groupName = groupName,
        };

        await this.inner.RemoveGroupAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveGuestAlias(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username, string base64Cert, GuestAuthSubject subject)
    {
        var req = new RemoveGuestAliasRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            username = username,
            base64Cert = base64Cert,
            subject = subject,
        };

        await this.inner.RemoveGuestAliasAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveGuestAliasByCert(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, string username, string base64Cert)
    {
        var req = new RemoveGuestAliasByCertRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            username = username,
            base64Cert = base64Cert,
        };

        await this.inner.RemoveGuestAliasByCertAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiSendTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaSendTarget[] targets, bool force, bool forceSpecified)
    {
        var req = new RemoveInternetScsiSendTargetsRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            targets = targets,
            force = force,
            forceSpecified = forceSpecified,
        };

        await this.inner.RemoveInternetScsiSendTargetsAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveInternetScsiStaticTargets(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaStaticTarget[] targets)
    {
        var req = new RemoveInternetScsiStaticTargetsRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            targets = targets,
        };

        await this.inner.RemoveInternetScsiStaticTargetsAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveKey(ManagedObjectReference self, CryptoKeyId key, bool force)
    {
        var req = new RemoveKeyRequestType
        {
            _this = self,
            key = key,
            force = force,
        };

        await this.inner.RemoveKeyAsync(req);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult[]?> RemoveKeys(ManagedObjectReference self, CryptoKeyId[]? keys, bool force)
    {
        var req = new RemoveKeysRequestType
        {
            _this = self,
            keys = keys,
            force = force,
        };

        var res = await this.inner.RemoveKeysAsync(req);

        return res.RemoveKeysResponse1;
    }

    public async System.Threading.Tasks.Task RemoveKmipServer(ManagedObjectReference self, KeyProviderId clusterId, string serverName)
    {
        var req = new RemoveKmipServerRequestType
        {
            _this = self,
            clusterId = clusterId,
            serverName = serverName,
        };

        await this.inner.RemoveKmipServerAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveLicense(ManagedObjectReference self, string licenseKey)
    {
        var req = new RemoveLicenseRequestType
        {
            _this = self,
            licenseKey = licenseKey,
        };

        await this.inner.RemoveLicenseAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveLicenseLabel(ManagedObjectReference self, string licenseKey, string labelKey)
    {
        var req = new RemoveLicenseLabelRequestType
        {
            _this = self,
            licenseKey = licenseKey,
            labelKey = labelKey,
        };

        await this.inner.RemoveLicenseLabelAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveMonitoredEntities(ManagedObjectReference self, string providerId, ManagedObjectReference[]? entities)
    {
        var req = new RemoveMonitoredEntitiesRequestType
        {
            _this = self,
            providerId = providerId,
            entities = entities,
        };

        await this.inner.RemoveMonitoredEntitiesAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveNetworkResourcePool(ManagedObjectReference self, string[] key)
    {
        var req = new RemoveNetworkResourcePoolRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.RemoveNetworkResourcePoolAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveNvmeOverRdmaAdapter(ManagedObjectReference self, string hbaDeviceName)
    {
        var req = new RemoveNvmeOverRdmaAdapterRequestType
        {
            _this = self,
            hbaDeviceName = hbaDeviceName,
        };

        await this.inner.RemoveNvmeOverRdmaAdapterAsync(req);
    }

    public async System.Threading.Tasks.Task RemovePerfInterval(ManagedObjectReference self, int samplePeriod)
    {
        var req = new RemovePerfIntervalRequestType
        {
            _this = self,
            samplePeriod = samplePeriod,
        };

        await this.inner.RemovePerfIntervalAsync(req);
    }

    public async System.Threading.Tasks.Task RemovePortGroup(ManagedObjectReference self, string pgName)
    {
        var req = new RemovePortGroupRequestType
        {
            _this = self,
            pgName = pgName,
        };

        await this.inner.RemovePortGroupAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveScheduledTask(ManagedObjectReference self)
    {
        var req = new RemoveScheduledTaskRequestType
        {
            _this = self,
        };

        await this.inner.RemoveScheduledTaskAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveServiceConsoleVirtualNic(ManagedObjectReference self, string device)
    {
        var req = new RemoveServiceConsoleVirtualNicRequestType
        {
            _this = self,
            device = device,
        };

        await this.inner.RemoveServiceConsoleVirtualNicAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchor(ManagedObjectReference self, string issuer, string serial)
    {
        var req = new RemoveSmartCardTrustAnchorRequestType
        {
            _this = self,
            issuer = issuer,
            serial = serial,
        };

        await this.inner.RemoveSmartCardTrustAnchorAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchorByFingerprint(ManagedObjectReference self, string fingerprint, string digest)
    {
        var req = new RemoveSmartCardTrustAnchorByFingerprintRequestType
        {
            _this = self,
            fingerprint = fingerprint,
            digest = digest,
        };

        await this.inner.RemoveSmartCardTrustAnchorByFingerprintAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveSmartCardTrustAnchorCertificate(ManagedObjectReference self, string certificate)
    {
        var req = new RemoveSmartCardTrustAnchorCertificateRequestType
        {
            _this = self,
            certificate = certificate,
        };

        await this.inner.RemoveSmartCardTrustAnchorCertificateAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RemoveSnapshot_Task(ManagedObjectReference self, bool removeChildren, bool consolidate, bool consolidateSpecified)
    {
        var req = new RemoveSnapshotRequestType
        {
            _this = self,
            removeChildren = removeChildren,
            consolidate = consolidate,
            consolidateSpecified = consolidateSpecified,
        };

        var res = await this.inner.RemoveSnapshot_TaskAsync(req);

        return res.RemoveSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RemoveSoftwareAdapter(ManagedObjectReference self, string hbaDeviceName)
    {
        var req = new RemoveSoftwareAdapterRequestType
        {
            _this = self,
            hbaDeviceName = hbaDeviceName,
        };

        await this.inner.RemoveSoftwareAdapterAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveUser(ManagedObjectReference self, string userName)
    {
        var req = new RemoveUserRequestType
        {
            _this = self,
            userName = userName,
        };

        await this.inner.RemoveUserAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveVirtualNic(ManagedObjectReference self, string device)
    {
        var req = new RemoveVirtualNicRequestType
        {
            _this = self,
            device = device,
        };

        await this.inner.RemoveVirtualNicAsync(req);
    }

    public async System.Threading.Tasks.Task RemoveVirtualSwitch(ManagedObjectReference self, string vswitchName)
    {
        var req = new RemoveVirtualSwitchRequestType
        {
            _this = self,
            vswitchName = vswitchName,
        };

        await this.inner.RemoveVirtualSwitchAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> Rename_Task(ManagedObjectReference self, string newName)
    {
        var req = new RenameRequestType
        {
            _this = self,
            newName = newName,
        };

        var res = await this.inner.Rename_TaskAsync(req);

        return res.Rename_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RenameCustomFieldDef(ManagedObjectReference self, int key, string name)
    {
        var req = new RenameCustomFieldDefRequestType
        {
            _this = self,
            key = key,
            name = name,
        };

        await this.inner.RenameCustomFieldDefAsync(req);
    }

    public async System.Threading.Tasks.Task RenameCustomizationSpec(ManagedObjectReference self, string name, string newName)
    {
        var req = new RenameCustomizationSpecRequestType
        {
            _this = self,
            name = name,
            newName = newName,
        };

        await this.inner.RenameCustomizationSpecAsync(req);
    }

    public async System.Threading.Tasks.Task RenameDatastore(ManagedObjectReference self, string newName)
    {
        var req = new RenameDatastoreRequestType
        {
            _this = self,
            newName = newName,
        };

        await this.inner.RenameDatastoreAsync(req);
    }

    public async System.Threading.Tasks.Task RenameSnapshot(ManagedObjectReference self, string? name, string? description)
    {
        var req = new RenameSnapshotRequestType
        {
            _this = self,
            name = name,
            description = description,
        };

        await this.inner.RenameSnapshotAsync(req);
    }

    public async System.Threading.Tasks.Task RenameVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string name)
    {
        var req = new RenameVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            name = name,
        };

        await this.inner.RenameVStorageObjectAsync(req);
    }

    public async System.Threading.Tasks.Task<vslmVClockInfo?> RenameVStorageObjectEx(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string name)
    {
        var req = new RenameVStorageObjectExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            name = name,
        };

        var res = await this.inner.RenameVStorageObjectExAsync(req);

        return res.RenameVStorageObjectExResponse.returnval;
    }

    public async System.Threading.Tasks.Task ReplaceCACertificatesAndCRLs(ManagedObjectReference self, string[] caCert, string[]? caCrl)
    {
        var req = new ReplaceCACertificatesAndCRLsRequestType
        {
            _this = self,
            caCert = caCert,
            caCrl = caCrl,
        };

        await this.inner.ReplaceCACertificatesAndCRLsAsync(req);
    }

    public async System.Threading.Tasks.Task ReplaceSmartCardTrustAnchors(ManagedObjectReference self, string[]? certs)
    {
        var req = new ReplaceSmartCardTrustAnchorsRequestType
        {
            _this = self,
            certs = certs,
        };

        await this.inner.ReplaceSmartCardTrustAnchorsAsync(req);
    }

    public async System.Threading.Tasks.Task RescanAllHba(ManagedObjectReference self)
    {
        var req = new RescanAllHbaRequestType
        {
            _this = self,
        };

        await this.inner.RescanAllHbaAsync(req);
    }

    public async System.Threading.Tasks.Task RescanHba(ManagedObjectReference self, string hbaDevice)
    {
        var req = new RescanHbaRequestType
        {
            _this = self,
            hbaDevice = hbaDevice,
        };

        await this.inner.RescanHbaAsync(req);
    }

    public async System.Threading.Tasks.Task RescanVffs(ManagedObjectReference self)
    {
        var req = new RescanVffsRequestType
        {
            _this = self,
        };

        await this.inner.RescanVffsAsync(req);
    }

    public async System.Threading.Tasks.Task RescanVmfs(ManagedObjectReference self)
    {
        var req = new RescanVmfsRequestType
        {
            _this = self,
        };

        await this.inner.RescanVmfsAsync(req);
    }

    public async System.Threading.Tasks.Task ResetCollector(ManagedObjectReference self)
    {
        var req = new ResetCollectorRequestType
        {
            _this = self,
        };

        await this.inner.ResetCollectorAsync(req);
    }

    public async System.Threading.Tasks.Task ResetCounterLevelMapping(ManagedObjectReference self, int[] counters)
    {
        var req = new ResetCounterLevelMappingRequestType
        {
            _this = self,
            counters = counters,
        };

        await this.inner.ResetCounterLevelMappingAsync(req);
    }

    public async System.Threading.Tasks.Task ResetEntityPermissions(ManagedObjectReference self, ManagedObjectReference entity, Permission[]? permission)
    {
        var req = new ResetEntityPermissionsRequestType
        {
            _this = self,
            entity = entity,
            permission = permission,
        };

        await this.inner.ResetEntityPermissionsAsync(req);
    }

    public async System.Threading.Tasks.Task ResetFirmwareToFactoryDefaults(ManagedObjectReference self)
    {
        var req = new ResetFirmwareToFactoryDefaultsRequestType
        {
            _this = self,
        };

        await this.inner.ResetFirmwareToFactoryDefaultsAsync(req);
    }

    public async System.Threading.Tasks.Task ResetGuestInformation(ManagedObjectReference self)
    {
        var req = new ResetGuestInformationRequestType
        {
            _this = self,
        };

        await this.inner.ResetGuestInformationAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> ResetListView(ManagedObjectReference self, ManagedObjectReference[]? obj)
    {
        var req = new ResetListViewRequestType
        {
            _this = self,
            obj = obj,
        };

        var res = await this.inner.ResetListViewAsync(req);

        return res.ResetListViewResponse1;
    }

    public async System.Threading.Tasks.Task ResetListViewFromView(ManagedObjectReference self, ManagedObjectReference view)
    {
        var req = new ResetListViewFromViewRequestType
        {
            _this = self,
            view = view,
        };

        await this.inner.ResetListViewFromViewAsync(req);
    }

    public async System.Threading.Tasks.Task ResetSystemHealthInfo(ManagedObjectReference self)
    {
        var req = new ResetSystemHealthInfoRequestType
        {
            _this = self,
        };

        await this.inner.ResetSystemHealthInfoAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ResetVM_Task(ManagedObjectReference self)
    {
        var req = new ResetVMRequestType
        {
            _this = self,
        };

        var res = await this.inner.ResetVM_TaskAsync(req);

        return res.ResetVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ResignatureUnresolvedVmfsVolume_Task(ManagedObjectReference self, HostUnresolvedVmfsResignatureSpec resolutionSpec)
    {
        var req = new ResignatureUnresolvedVmfsVolumeRequestType
        {
            _this = self,
            resolutionSpec = resolutionSpec,
        };

        var res = await this.inner.ResignatureUnresolvedVmfsVolume_TaskAsync(req);

        return res.ResignatureUnresolvedVmfsVolume_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ResolveInstallationErrorsOnCluster_Task(ManagedObjectReference self, string filterId, ManagedObjectReference cluster)
    {
        var req = new ResolveInstallationErrorsOnClusterRequestType
        {
            _this = self,
            filterId = filterId,
            cluster = cluster,
        };

        var res = await this.inner.ResolveInstallationErrorsOnCluster_TaskAsync(req);

        return res.ResolveInstallationErrorsOnCluster_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ResolveInstallationErrorsOnHost_Task(ManagedObjectReference self, string filterId, ManagedObjectReference host)
    {
        var req = new ResolveInstallationErrorsOnHostRequestType
        {
            _this = self,
            filterId = filterId,
            host = host,
        };

        var res = await this.inner.ResolveInstallationErrorsOnHost_TaskAsync(req);

        return res.ResolveInstallationErrorsOnHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostUnresolvedVmfsResolutionResult[]?> ResolveMultipleUnresolvedVmfsVolumes(ManagedObjectReference self, HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        var req = new ResolveMultipleUnresolvedVmfsVolumesRequestType
        {
            _this = self,
            resolutionSpec = resolutionSpec,
        };

        var res = await this.inner.ResolveMultipleUnresolvedVmfsVolumesAsync(req);

        return res.ResolveMultipleUnresolvedVmfsVolumesResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ResolveMultipleUnresolvedVmfsVolumesEx_Task(ManagedObjectReference self, HostUnresolvedVmfsResolutionSpec[] resolutionSpec)
    {
        var req = new ResolveMultipleUnresolvedVmfsVolumesExRequestType
        {
            _this = self,
            resolutionSpec = resolutionSpec,
        };

        var res = await this.inner.ResolveMultipleUnresolvedVmfsVolumesEx_TaskAsync(req);

        return res.ResolveMultipleUnresolvedVmfsVolumesEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RestartService(ManagedObjectReference self, string id)
    {
        var req = new RestartServiceRequestType
        {
            _this = self,
            id = id,
        };

        await this.inner.RestartServiceAsync(req);
    }

    public async System.Threading.Tasks.Task RestartServiceConsoleVirtualNic(ManagedObjectReference self, string device)
    {
        var req = new RestartServiceConsoleVirtualNicRequestType
        {
            _this = self,
            device = device,
        };

        await this.inner.RestartServiceConsoleVirtualNicAsync(req);
    }

    public async System.Threading.Tasks.Task RestoreFirmwareConfiguration(ManagedObjectReference self, bool force)
    {
        var req = new RestoreFirmwareConfigurationRequestType
        {
            _this = self,
            force = force,
        };

        await this.inner.RestoreFirmwareConfigurationAsync(req);
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveAllPermissions(ManagedObjectReference self)
    {
        var req = new RetrieveAllPermissionsRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveAllPermissionsAsync(req);

        return res.RetrieveAllPermissionsResponse1;
    }

    public async System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFile(ManagedObjectReference self, ManagedObjectReference host)
    {
        var req = new RetrieveAnswerFileRequestType
        {
            _this = self,
            host = host,
        };

        var res = await this.inner.RetrieveAnswerFileAsync(req);

        return res.RetrieveAnswerFileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<AnswerFile?> RetrieveAnswerFileForProfile(ManagedObjectReference self, ManagedObjectReference host, HostApplyProfile applyProfile)
    {
        var req = new RetrieveAnswerFileForProfileRequestType
        {
            _this = self,
            host = host,
            applyProfile = applyProfile,
        };

        var res = await this.inner.RetrieveAnswerFileForProfileAsync(req);

        return res.RetrieveAnswerFileForProfileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<EventArgDesc[]?> RetrieveArgumentDescription(ManagedObjectReference self, string eventTypeId)
    {
        var req = new RetrieveArgumentDescriptionRequestType
        {
            _this = self,
            eventTypeId = eventTypeId,
        };

        var res = await this.inner.RetrieveArgumentDescriptionAsync(req);

        return res.RetrieveArgumentDescriptionResponse1;
    }

    public async System.Threading.Tasks.Task<HostCertificateManagerCertificateInfo[]?> RetrieveCertificateInfoList(ManagedObjectReference self)
    {
        var req = new RetrieveCertificateInfoListRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveCertificateInfoListAsync(req);

        return res.RetrieveCertificateInfoListResponse1;
    }

    public async System.Threading.Tasks.Task<string?> RetrieveClientCert(ManagedObjectReference self, KeyProviderId cluster)
    {
        var req = new RetrieveClientCertRequestType
        {
            _this = self,
            cluster = cluster,
        };

        var res = await this.inner.RetrieveClientCertAsync(req);

        return res.RetrieveClientCertResponse.returnval;
    }

    public async System.Threading.Tasks.Task<string?> RetrieveClientCsr(ManagedObjectReference self, KeyProviderId cluster)
    {
        var req = new RetrieveClientCsrRequestType
        {
            _this = self,
            cluster = cluster,
        };

        var res = await this.inner.RetrieveClientCsrAsync(req);

        return res.RetrieveClientCsrResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ClusterDasAdvancedRuntimeInfo?> RetrieveDasAdvancedRuntimeInfo(ManagedObjectReference self)
    {
        var req = new RetrieveDasAdvancedRuntimeInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveDasAdvancedRuntimeInfoAsync(req);

        return res.RetrieveDasAdvancedRuntimeInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ProfileDescription?> RetrieveDescription(ManagedObjectReference self)
    {
        var req = new RetrieveDescriptionRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveDescriptionAsync(req);

        return res.RetrieveDescriptionResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostDiskPartitionInfo[]?> RetrieveDiskPartitionInfo(ManagedObjectReference self, string[] devicePath)
    {
        var req = new RetrieveDiskPartitionInfoRequestType
        {
            _this = self,
            devicePath = devicePath,
        };

        var res = await this.inner.RetrieveDiskPartitionInfoAsync(req);

        return res.RetrieveDiskPartitionInfoResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualMachineDynamicPassthroughInfo[]?> RetrieveDynamicPassthroughInfo(ManagedObjectReference self)
    {
        var req = new RetrieveDynamicPassthroughInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveDynamicPassthroughInfoAsync(req);

        return res.RetrieveDynamicPassthroughInfoResponse1;
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveEntityPermissions(ManagedObjectReference self, ManagedObjectReference entity, bool inherited)
    {
        var req = new RetrieveEntityPermissionsRequestType
        {
            _this = self,
            entity = entity,
            inherited = inherited,
        };

        var res = await this.inner.RetrieveEntityPermissionsAsync(req);

        return res.RetrieveEntityPermissionsResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> RetrieveEntityScheduledTask(ManagedObjectReference self, ManagedObjectReference? entity)
    {
        var req = new RetrieveEntityScheduledTaskRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.RetrieveEntityScheduledTaskAsync(req);

        return res.RetrieveEntityScheduledTaskResponse1;
    }

    public async System.Threading.Tasks.Task<long> RetrieveFreeEpcMemory(ManagedObjectReference self)
    {
        var req = new RetrieveFreeEpcMemoryRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveFreeEpcMemoryAsync(req);

        return res.RetrieveFreeEpcMemoryResponse.returnval;
    }

    public async System.Threading.Tasks.Task<long> RetrieveHardwareUptime(ManagedObjectReference self)
    {
        var req = new RetrieveHardwareUptimeRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveHardwareUptimeAsync(req);

        return res.RetrieveHardwareUptimeResponse.returnval;
    }

    public async System.Threading.Tasks.Task<HostAccessControlEntry[]?> RetrieveHostAccessControlEntries(ManagedObjectReference self)
    {
        var req = new RetrieveHostAccessControlEntriesRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveHostAccessControlEntriesAsync(req);

        return res.RetrieveHostAccessControlEntriesResponse1;
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizations(ManagedObjectReference self, ManagedObjectReference[]? hosts)
    {
        var req = new RetrieveHostCustomizationsRequestType
        {
            _this = self,
            hosts = hosts,
        };

        var res = await this.inner.RetrieveHostCustomizationsAsync(req);

        return res.RetrieveHostCustomizationsResponse1;
    }

    public async System.Threading.Tasks.Task<StructuredCustomizations[]?> RetrieveHostCustomizationsForProfile(ManagedObjectReference self, ManagedObjectReference[]? hosts, HostApplyProfile applyProfile)
    {
        var req = new RetrieveHostCustomizationsForProfileRequestType
        {
            _this = self,
            hosts = hosts,
            applyProfile = applyProfile,
        };

        var res = await this.inner.RetrieveHostCustomizationsForProfileAsync(req);

        return res.RetrieveHostCustomizationsForProfileResponse1;
    }

    public async System.Threading.Tasks.Task<HostSpecification?> RetrieveHostSpecification(ManagedObjectReference self, ManagedObjectReference host, bool fromHost)
    {
        var req = new RetrieveHostSpecificationRequestType
        {
            _this = self,
            host = host,
            fromHost = fromHost,
        };

        var res = await this.inner.RetrieveHostSpecificationAsync(req);

        return res.RetrieveHostSpecificationResponse.returnval;
    }

    public async System.Threading.Tasks.Task<CryptoManagerKmipServerCertInfo?> RetrieveKmipServerCert(ManagedObjectReference self, KeyProviderId keyProvider, KmipServerInfo server)
    {
        var req = new RetrieveKmipServerCertRequestType
        {
            _this = self,
            keyProvider = keyProvider,
            server = server,
        };

        var res = await this.inner.RetrieveKmipServerCertAsync(req);

        return res.RetrieveKmipServerCertResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RetrieveKmipServersStatus_Task(ManagedObjectReference self, KmipClusterInfo[]? clusters)
    {
        var req = new RetrieveKmipServersStatusRequestType
        {
            _this = self,
            clusters = clusters,
        };

        var res = await this.inner.RetrieveKmipServersStatus_TaskAsync(req);

        return res.RetrieveKmipServersStatus_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> RetrieveObjectScheduledTask(ManagedObjectReference self, ManagedObjectReference? obj)
    {
        var req = new RetrieveObjectScheduledTaskRequestType
        {
            _this = self,
            obj = obj,
        };

        var res = await this.inner.RetrieveObjectScheduledTaskAsync(req);

        return res.RetrieveObjectScheduledTaskResponse1;
    }

    public async System.Threading.Tasks.Task<ProductComponentInfo[]?> RetrieveProductComponents(ManagedObjectReference self)
    {
        var req = new RetrieveProductComponentsRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveProductComponentsAsync(req);

        return res.RetrieveProductComponentsResponse1;
    }

    public async System.Threading.Tasks.Task<ObjectContent[]?> RetrieveProperties(ManagedObjectReference self, PropertyFilterSpec[] specSet)
    {
        var req = new RetrievePropertiesRequestType
        {
            _this = self,
            specSet = specSet,
        };

        var res = await this.inner.RetrievePropertiesAsync(req);

        return res.RetrievePropertiesResponse1;
    }

    public async System.Threading.Tasks.Task<RetrieveResult?> RetrievePropertiesEx(ManagedObjectReference self, PropertyFilterSpec[] specSet, RetrieveOptions options)
    {
        var req = new RetrievePropertiesExRequestType
        {
            _this = self,
            specSet = specSet,
            options = options,
        };

        var res = await this.inner.RetrievePropertiesExAsync(req);

        return res.RetrievePropertiesExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<Permission[]?> RetrieveRolePermissions(ManagedObjectReference self, int roleId)
    {
        var req = new RetrieveRolePermissionsRequestType
        {
            _this = self,
            roleId = roleId,
        };

        var res = await this.inner.RetrieveRolePermissionsAsync(req);

        return res.RetrieveRolePermissionsResponse1;
    }

    public async System.Threading.Tasks.Task<string?> RetrieveSelfSignedClientCert(ManagedObjectReference self, KeyProviderId cluster)
    {
        var req = new RetrieveSelfSignedClientCertRequestType
        {
            _this = self,
            cluster = cluster,
        };

        var res = await this.inner.RetrieveSelfSignedClientCertAsync(req);

        return res.RetrieveSelfSignedClientCertResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ServiceContent?> RetrieveServiceContent(ManagedObjectReference self)
    {
        var req = new RetrieveServiceContentRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveServiceContentAsync(req);

        return res.RetrieveServiceContentResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference[]?> RetrieveServiceProviderEntities(ManagedObjectReference self)
    {
        var req = new RetrieveServiceProviderEntitiesRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveServiceProviderEntitiesAsync(req);

        return res.RetrieveServiceProviderEntitiesResponse1;
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotDetails?> RetrieveSnapshotDetails(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new RetrieveSnapshotDetailsRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.RetrieveSnapshotDetailsAsync(req);

        return res.RetrieveSnapshotDetailsResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObjectSnapshotInfo?> RetrieveSnapshotInfo(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new RetrieveSnapshotInfoRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.RetrieveSnapshotInfoAsync(req);

        return res.RetrieveSnapshotInfoResponse.returnval;
    }

    public async System.Threading.Tasks.Task<UserSearchResult[]?> RetrieveUserGroups(ManagedObjectReference self, string? domain, string searchStr, string? belongsToGroup, string? belongsToUser, bool exactMatch, bool findUsers, bool findGroups)
    {
        var req = new RetrieveUserGroupsRequestType
        {
            _this = self,
            domain = domain,
            searchStr = searchStr,
            belongsToGroup = belongsToGroup,
            belongsToUser = belongsToUser,
            exactMatch = exactMatch,
            findUsers = findUsers,
            findGroups = findGroups,
        };

        var res = await this.inner.RetrieveUserGroupsAsync(req);

        return res.RetrieveUserGroupsResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualMachineVendorDeviceGroupInfo[]?> RetrieveVendorDeviceGroupInfo(ManagedObjectReference self)
    {
        var req = new RetrieveVendorDeviceGroupInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveVendorDeviceGroupInfoAsync(req);

        return res.RetrieveVendorDeviceGroupInfoResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuDeviceInfo[]?> RetrieveVgpuDeviceInfo(ManagedObjectReference self)
    {
        var req = new RetrieveVgpuDeviceInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveVgpuDeviceInfoAsync(req);

        return res.RetrieveVgpuDeviceInfoResponse1;
    }

    public async System.Threading.Tasks.Task<VirtualMachineVgpuProfileInfo[]?> RetrieveVgpuProfileInfo(ManagedObjectReference self)
    {
        var req = new RetrieveVgpuProfileInfoRequestType
        {
            _this = self,
        };

        var res = await this.inner.RetrieveVgpuProfileInfoAsync(req);

        return res.RetrieveVgpuProfileInfoResponse1;
    }

    public async System.Threading.Tasks.Task<vslmInfrastructureObjectPolicy[]?> RetrieveVStorageInfrastructureObjectPolicy(ManagedObjectReference self, ManagedObjectReference datastore)
    {
        var req = new RetrieveVStorageInfrastructureObjectPolicyRequestType
        {
            _this = self,
            datastore = datastore,
        };

        var res = await this.inner.RetrieveVStorageInfrastructureObjectPolicyAsync(req);

        return res.RetrieveVStorageInfrastructureObjectPolicyResponse1;
    }

    public async System.Threading.Tasks.Task<VStorageObject?> RetrieveVStorageObject(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? diskInfoFlags)
    {
        var req = new RetrieveVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            diskInfoFlags = diskInfoFlags,
        };

        var res = await this.inner.RetrieveVStorageObjectAsync(req);

        return res.RetrieveVStorageObjectResponse.returnval;
    }

    public async System.Threading.Tasks.Task<VStorageObjectAssociations[]?> RetrieveVStorageObjectAssociations(ManagedObjectReference self, RetrieveVStorageObjSpec[]? ids)
    {
        var req = new RetrieveVStorageObjectAssociationsRequestType
        {
            _this = self,
            ids = ids,
        };

        var res = await this.inner.RetrieveVStorageObjectAssociationsAsync(req);

        return res.RetrieveVStorageObjectAssociationsResponse1;
    }

    public async System.Threading.Tasks.Task<VStorageObjectStateInfo?> RetrieveVStorageObjectState(ManagedObjectReference self, ID id, ManagedObjectReference datastore)
    {
        var req = new RetrieveVStorageObjectStateRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
        };

        var res = await this.inner.RetrieveVStorageObjectStateAsync(req);

        return res.RetrieveVStorageObjectStateResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RevertToCurrentSnapshot_Task(ManagedObjectReference self, ManagedObjectReference? host, bool suppressPowerOn, bool suppressPowerOnSpecified)
    {
        var req = new RevertToCurrentSnapshotRequestType
        {
            _this = self,
            host = host,
            suppressPowerOn = suppressPowerOn,
            suppressPowerOnSpecified = suppressPowerOnSpecified,
        };

        var res = await this.inner.RevertToCurrentSnapshot_TaskAsync(req);

        return res.RevertToCurrentSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RevertToSnapshot_Task(ManagedObjectReference self, ManagedObjectReference? host, bool suppressPowerOn, bool suppressPowerOnSpecified)
    {
        var req = new RevertToSnapshotRequestType
        {
            _this = self,
            host = host,
            suppressPowerOn = suppressPowerOn,
            suppressPowerOnSpecified = suppressPowerOnSpecified,
        };

        var res = await this.inner.RevertToSnapshot_TaskAsync(req);

        return res.RevertToSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RevertVStorageObject_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new RevertVStorageObjectRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.RevertVStorageObject_TaskAsync(req);

        return res.RevertVStorageObject_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> RevertVStorageObjectEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new RevertVStorageObjectExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.RevertVStorageObjectEx_TaskAsync(req);

        return res.RevertVStorageObjectEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task RewindCollector(ManagedObjectReference self)
    {
        var req = new RewindCollectorRequestType
        {
            _this = self,
        };

        await this.inner.RewindCollectorAsync(req);
    }

    public async System.Threading.Tasks.Task RunScheduledTask(ManagedObjectReference self)
    {
        var req = new RunScheduledTaskRequestType
        {
            _this = self,
        };

        await this.inner.RunScheduledTaskAsync(req);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanPhysicalDiskDiagnosticsResult[]?> RunVsanPhysicalDiskDiagnostics(ManagedObjectReference self, string[]? disks)
    {
        var req = new RunVsanPhysicalDiskDiagnosticsRequestType
        {
            _this = self,
            disks = disks,
        };

        var res = await this.inner.RunVsanPhysicalDiskDiagnosticsAsync(req);

        return res.RunVsanPhysicalDiskDiagnosticsResponse1;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ScanHostPatch_Task(ManagedObjectReference self, HostPatchManagerLocator repository, string[]? updateID)
    {
        var req = new ScanHostPatchRequestType
        {
            _this = self,
            repository = repository,
            updateID = updateID,
        };

        var res = await this.inner.ScanHostPatch_TaskAsync(req);

        return res.ScanHostPatch_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ScanHostPatchV2_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var req = new ScanHostPatchV2RequestType
        {
            _this = self,
            metaUrls = metaUrls,
            bundleUrls = bundleUrls,
            spec = spec,
        };

        var res = await this.inner.ScanHostPatchV2_TaskAsync(req);

        return res.ScanHostPatchV2_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ScheduleReconcileDatastoreInventory(ManagedObjectReference self, ManagedObjectReference datastore, bool deepCleansing, bool deepCleansingSpecified)
    {
        var req = new ScheduleReconcileDatastoreInventoryRequestType
        {
            _this = self,
            datastore = datastore,
            deepCleansing = deepCleansing,
            deepCleansingSpecified = deepCleansingSpecified,
        };

        await this.inner.ScheduleReconcileDatastoreInventoryAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> SearchDatastore_Task(ManagedObjectReference self, string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec)
    {
        var req = new SearchDatastoreRequestType
        {
            _this = self,
            datastorePath = datastorePath,
            searchSpec = searchSpec,
        };

        var res = await this.inner.SearchDatastore_TaskAsync(req);

        return res.SearchDatastore_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> SearchDatastoreSubFolders_Task(ManagedObjectReference self, string datastorePath, HostDatastoreBrowserSearchSpec? searchSpec)
    {
        var req = new SearchDatastoreSubFoldersRequestType
        {
            _this = self,
            datastorePath = datastorePath,
            searchSpec = searchSpec,
        };

        var res = await this.inner.SearchDatastoreSubFolders_TaskAsync(req);

        return res.SearchDatastoreSubFolders_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task SelectActivePartition(ManagedObjectReference self, HostScsiDiskPartition? partition)
    {
        var req = new SelectActivePartitionRequestType
        {
            _this = self,
            partition = partition,
        };

        await this.inner.SelectActivePartitionAsync(req);
    }

    public async System.Threading.Tasks.Task SelectVnic(ManagedObjectReference self, string device)
    {
        var req = new SelectVnicRequestType
        {
            _this = self,
            device = device,
        };

        await this.inner.SelectVnicAsync(req);
    }

    public async System.Threading.Tasks.Task SelectVnicForNicType(ManagedObjectReference self, string nicType, string device)
    {
        var req = new SelectVnicForNicTypeRequestType
        {
            _this = self,
            nicType = nicType,
            device = device,
        };

        await this.inner.SelectVnicForNicTypeAsync(req);
    }

    public async System.Threading.Tasks.Task SendNMI(ManagedObjectReference self)
    {
        var req = new SendNMIRequestType
        {
            _this = self,
        };

        await this.inner.SendNMIAsync(req);
    }

    public async System.Threading.Tasks.Task SendTestNotification(ManagedObjectReference self)
    {
        var req = new SendTestNotificationRequestType
        {
            _this = self,
        };

        await this.inner.SendTestNotificationAsync(req);
    }

    public async System.Threading.Tasks.Task<bool> SessionIsActive(ManagedObjectReference self, string sessionID, string userName)
    {
        var req = new SessionIsActiveRequestType
        {
            _this = self,
            sessionID = sessionID,
            userName = userName,
        };

        var res = await this.inner.SessionIsActiveAsync(req);

        return res.SessionIsActiveResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> SetClusterMode_Task(ManagedObjectReference self, string mode)
    {
        var req = new setClusterModeRequestType
        {
            _this = self,
            mode = mode,
        };

        var res = await this.inner.setClusterMode_TaskAsync(req);

        return res.setClusterMode_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task SetCollectorPageSize(ManagedObjectReference self, int maxCount)
    {
        var req = new SetCollectorPageSizeRequestType
        {
            _this = self,
            maxCount = maxCount,
        };

        await this.inner.SetCollectorPageSizeAsync(req);
    }

    public async System.Threading.Tasks.Task SetCryptoMode(ManagedObjectReference self, string cryptoMode, ClusterComputeResourceCryptoModePolicy? policy)
    {
        var req = new SetCryptoModeRequestType
        {
            _this = self,
            cryptoMode = cryptoMode,
            policy = policy,
        };

        await this.inner.SetCryptoModeAsync(req);
    }

    public async System.Threading.Tasks.Task SetCustomValue(ManagedObjectReference self, string key, string value)
    {
        var req = new setCustomValueRequestType
        {
            _this = self,
            key = key,
            value = value,
        };

        await this.inner.setCustomValueAsync(req);
    }

    public async System.Threading.Tasks.Task SetDefaultKmsCluster(ManagedObjectReference self, ManagedObjectReference? entity, KeyProviderId? clusterId)
    {
        var req = new SetDefaultKmsClusterRequestType
        {
            _this = self,
            entity = entity,
            clusterId = clusterId,
        };

        await this.inner.SetDefaultKmsClusterAsync(req);
    }

    public async System.Threading.Tasks.Task SetDisplayTopology(ManagedObjectReference self, VirtualMachineDisplayTopology[] displays)
    {
        var req = new SetDisplayTopologyRequestType
        {
            _this = self,
            displays = displays,
        };

        await this.inner.SetDisplayTopologyAsync(req);
    }

    public async System.Threading.Tasks.Task SetEntityPermissions(ManagedObjectReference self, ManagedObjectReference entity, Permission[]? permission)
    {
        var req = new SetEntityPermissionsRequestType
        {
            _this = self,
            entity = entity,
            permission = permission,
        };

        await this.inner.SetEntityPermissionsAsync(req);
    }

    public async System.Threading.Tasks.Task SetExtensionCertificate(ManagedObjectReference self, string extensionKey, string? certificatePem)
    {
        var req = new SetExtensionCertificateRequestType
        {
            _this = self,
            extensionKey = extensionKey,
            certificatePem = certificatePem,
        };

        await this.inner.SetExtensionCertificateAsync(req);
    }

    public async System.Threading.Tasks.Task SetField(ManagedObjectReference self, ManagedObjectReference entity, int key, string value)
    {
        var req = new SetFieldRequestType
        {
            _this = self,
            entity = entity,
            key = key,
            value = value,
        };

        await this.inner.SetFieldAsync(req);
    }

    public async System.Threading.Tasks.Task<CryptoKeyResult?> SetKeyCustomAttributes(ManagedObjectReference self, CryptoKeyId keyId, CryptoManagerKmipCustomAttributeSpec spec)
    {
        var req = new SetKeyCustomAttributesRequestType
        {
            _this = self,
            keyId = keyId,
            spec = spec,
        };

        var res = await this.inner.SetKeyCustomAttributesAsync(req);

        return res.SetKeyCustomAttributesResponse.returnval;
    }

    public async System.Threading.Tasks.Task SetLicenseEdition(ManagedObjectReference self, ManagedObjectReference? host, string? featureKey)
    {
        var req = new SetLicenseEditionRequestType
        {
            _this = self,
            host = host,
            featureKey = featureKey,
        };

        await this.inner.SetLicenseEditionAsync(req);
    }

    public async System.Threading.Tasks.Task SetLocale(ManagedObjectReference self, string locale)
    {
        var req = new SetLocaleRequestType
        {
            _this = self,
            locale = locale,
        };

        await this.inner.SetLocaleAsync(req);
    }

    public async System.Threading.Tasks.Task SetMaxQueueDepth(ManagedObjectReference self, ManagedObjectReference datastore, long maxQdepth)
    {
        var req = new SetMaxQueueDepthRequestType
        {
            _this = self,
            datastore = datastore,
            maxQdepth = maxQdepth,
        };

        await this.inner.SetMaxQueueDepthAsync(req);
    }

    public async System.Threading.Tasks.Task SetMultipathLunPolicy(ManagedObjectReference self, string lunId, HostMultipathInfoLogicalUnitPolicy policy)
    {
        var req = new SetMultipathLunPolicyRequestType
        {
            _this = self,
            lunId = lunId,
            policy = policy,
        };

        await this.inner.SetMultipathLunPolicyAsync(req);
    }

    public async System.Threading.Tasks.Task SetNFSUser(ManagedObjectReference self, string user, string password)
    {
        var req = new SetNFSUserRequestType
        {
            _this = self,
            user = user,
            password = password,
        };

        await this.inner.SetNFSUserAsync(req);
    }

    public async System.Threading.Tasks.Task SetPublicKey(ManagedObjectReference self, string extensionKey, string publicKey)
    {
        var req = new SetPublicKeyRequestType
        {
            _this = self,
            extensionKey = extensionKey,
            publicKey = publicKey,
        };

        await this.inner.SetPublicKeyAsync(req);
    }

    public async System.Threading.Tasks.Task SetRegistryValueInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestRegValueSpec value)
    {
        var req = new SetRegistryValueInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            value = value,
        };

        await this.inner.SetRegistryValueInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task SetScreenResolution(ManagedObjectReference self, int width, int height)
    {
        var req = new SetScreenResolutionRequestType
        {
            _this = self,
            width = width,
            height = height,
        };

        await this.inner.SetScreenResolutionAsync(req);
    }

    public async System.Threading.Tasks.Task SetServiceAccount(ManagedObjectReference self, string extensionKey, string serviceAccount)
    {
        var req = new SetServiceAccountRequestType
        {
            _this = self,
            extensionKey = extensionKey,
            serviceAccount = serviceAccount,
        };

        await this.inner.SetServiceAccountAsync(req);
    }

    public async System.Threading.Tasks.Task SetTaskDescription(ManagedObjectReference self, LocalizableMessage description)
    {
        var req = new SetTaskDescriptionRequestType
        {
            _this = self,
            description = description,
        };

        await this.inner.SetTaskDescriptionAsync(req);
    }

    public async System.Threading.Tasks.Task SetTaskState(ManagedObjectReference self, TaskInfoState state, object? result, LocalizedMethodFault? fault)
    {
        var req = new SetTaskStateRequestType
        {
            _this = self,
            state = state,
            result = result,
            fault = fault,
        };

        await this.inner.SetTaskStateAsync(req);
    }

    public async System.Threading.Tasks.Task SetVirtualDiskUuid(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, string uuid)
    {
        var req = new SetVirtualDiskUuidRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
            uuid = uuid,
        };

        await this.inner.SetVirtualDiskUuidAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> SetVirtualDiskUuidEx_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, string? uuid)
    {
        var req = new SetVirtualDiskUuidExRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
            uuid = uuid,
        };

        var res = await this.inner.SetVirtualDiskUuidEx_TaskAsync(req);

        return res.SetVirtualDiskUuidEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task SetVStorageObjectControlFlags(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string[]? controlFlags)
    {
        var req = new SetVStorageObjectControlFlagsRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            controlFlags = controlFlags,
        };

        await this.inner.SetVStorageObjectControlFlagsAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ShrinkVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter, bool copy, bool copySpecified)
    {
        var req = new ShrinkVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
            copy = copy,
            copySpecified = copySpecified,
        };

        var res = await this.inner.ShrinkVirtualDisk_TaskAsync(req);

        return res.ShrinkVirtualDisk_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task ShutdownGuest(ManagedObjectReference self)
    {
        var req = new ShutdownGuestRequestType
        {
            _this = self,
        };

        await this.inner.ShutdownGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ShutdownHost_Task(ManagedObjectReference self, bool force)
    {
        var req = new ShutdownHostRequestType
        {
            _this = self,
            force = force,
        };

        var res = await this.inner.ShutdownHost_TaskAsync(req);

        return res.ShutdownHost_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> StageHostPatch_Task(ManagedObjectReference self, string[]? metaUrls, string[]? bundleUrls, string[]? vibUrls, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var req = new StageHostPatchRequestType
        {
            _this = self,
            metaUrls = metaUrls,
            bundleUrls = bundleUrls,
            vibUrls = vibUrls,
            spec = spec,
        };

        var res = await this.inner.StageHostPatch_TaskAsync(req);

        return res.StageHostPatch_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> StampAllRulesWithUuid_Task(ManagedObjectReference self)
    {
        var req = new StampAllRulesWithUuidRequestType
        {
            _this = self,
        };

        var res = await this.inner.StampAllRulesWithUuid_TaskAsync(req);

        return res.StampAllRulesWithUuid_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task StandbyGuest(ManagedObjectReference self)
    {
        var req = new StandbyGuestRequestType
        {
            _this = self,
        };

        await this.inner.StandbyGuestAsync(req);
    }

    public async System.Threading.Tasks.Task StartDpuFailover(ManagedObjectReference self, string dvsName, string? targetDpuAlias)
    {
        var req = new startDpuFailoverRequestType
        {
            _this = self,
            dvsName = dvsName,
            targetDpuAlias = targetDpuAlias,
        };

        await this.inner.startDpuFailoverAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> StartGuestNetwork_Task(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth)
    {
        var req = new StartGuestNetworkRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
        };

        var res = await this.inner.StartGuestNetwork_TaskAsync(req);

        return res.StartGuestNetwork_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<long> StartProgramInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, GuestProgramSpec spec)
    {
        var req = new StartProgramInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            spec = spec,
        };

        var res = await this.inner.StartProgramInGuestAsync(req);

        return res.StartProgramInGuestResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> StartRecording_Task(ManagedObjectReference self, string name, string? description)
    {
        var req = new StartRecordingRequestType
        {
            _this = self,
            name = name,
            description = description,
        };

        var res = await this.inner.StartRecording_TaskAsync(req);

        return res.StartRecording_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> StartReplaying_Task(ManagedObjectReference self, ManagedObjectReference replaySnapshot)
    {
        var req = new StartReplayingRequestType
        {
            _this = self,
            replaySnapshot = replaySnapshot,
        };

        var res = await this.inner.StartReplaying_TaskAsync(req);

        return res.StartReplaying_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task StartService(ManagedObjectReference self, string id)
    {
        var req = new StartServiceRequestType
        {
            _this = self,
            id = id,
        };

        await this.inner.StartServiceAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> StopRecording_Task(ManagedObjectReference self)
    {
        var req = new StopRecordingRequestType
        {
            _this = self,
        };

        var res = await this.inner.StopRecording_TaskAsync(req);

        return res.StopRecording_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> StopReplaying_Task(ManagedObjectReference self)
    {
        var req = new StopReplayingRequestType
        {
            _this = self,
        };

        var res = await this.inner.StopReplaying_TaskAsync(req);

        return res.StopReplaying_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task StopService(ManagedObjectReference self, string id)
    {
        var req = new StopServiceRequestType
        {
            _this = self,
            id = id,
        };

        await this.inner.StopServiceAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> SuspendVApp_Task(ManagedObjectReference self)
    {
        var req = new SuspendVAppRequestType
        {
            _this = self,
        };

        var res = await this.inner.SuspendVApp_TaskAsync(req);

        return res.SuspendVApp_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> SuspendVM_Task(ManagedObjectReference self)
    {
        var req = new SuspendVMRequestType
        {
            _this = self,
        };

        var res = await this.inner.SuspendVM_TaskAsync(req);

        return res.SuspendVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> TerminateFaultTolerantVM_Task(ManagedObjectReference self, ManagedObjectReference? vm)
    {
        var req = new TerminateFaultTolerantVMRequestType
        {
            _this = self,
            vm = vm,
        };

        var res = await this.inner.TerminateFaultTolerantVM_TaskAsync(req);

        return res.TerminateFaultTolerantVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task TerminateProcessInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth, long pid)
    {
        var req = new TerminateProcessInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
            pid = pid,
        };

        await this.inner.TerminateProcessInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task TerminateSession(ManagedObjectReference self, string[] sessionId)
    {
        var req = new TerminateSessionRequestType
        {
            _this = self,
            sessionId = sessionId,
        };

        await this.inner.TerminateSessionAsync(req);
    }

    public async System.Threading.Tasks.Task TerminateVM(ManagedObjectReference self)
    {
        var req = new TerminateVMRequestType
        {
            _this = self,
        };

        await this.inner.TerminateVMAsync(req);
    }

    public async System.Threading.Tasks.Task<HostDateTimeSystemServiceTestResult?> TestTimeService(ManagedObjectReference self)
    {
        var req = new TestTimeServiceRequestType
        {
            _this = self,
        };

        var res = await this.inner.TestTimeServiceAsync(req);

        return res.TestTimeServiceResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> TurnDiskLocatorLedOff_Task(ManagedObjectReference self, string[] scsiDiskUuids)
    {
        var req = new TurnDiskLocatorLedOffRequestType
        {
            _this = self,
            scsiDiskUuids = scsiDiskUuids,
        };

        var res = await this.inner.TurnDiskLocatorLedOff_TaskAsync(req);

        return res.TurnDiskLocatorLedOff_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> TurnDiskLocatorLedOn_Task(ManagedObjectReference self, string[] scsiDiskUuids)
    {
        var req = new TurnDiskLocatorLedOnRequestType
        {
            _this = self,
            scsiDiskUuids = scsiDiskUuids,
        };

        var res = await this.inner.TurnDiskLocatorLedOn_TaskAsync(req);

        return res.TurnDiskLocatorLedOn_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> TurnOffFaultToleranceForVM_Task(ManagedObjectReference self)
    {
        var req = new TurnOffFaultToleranceForVMRequestType
        {
            _this = self,
        };

        var res = await this.inner.TurnOffFaultToleranceForVM_TaskAsync(req);

        return res.TurnOffFaultToleranceForVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UnassignUserFromGroup(ManagedObjectReference self, string user, string group)
    {
        var req = new UnassignUserFromGroupRequestType
        {
            _this = self,
            user = user,
            group = group,
        };

        await this.inner.UnassignUserFromGroupAsync(req);
    }

    public async System.Threading.Tasks.Task UnbindVnic(ManagedObjectReference self, string iScsiHbaName, string vnicDevice, bool force)
    {
        var req = new UnbindVnicRequestType
        {
            _this = self,
            iScsiHbaName = iScsiHbaName,
            vnicDevice = vnicDevice,
            force = force,
        };

        await this.inner.UnbindVnicAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UninstallHostPatch_Task(ManagedObjectReference self, string[]? bulletinIds, HostPatchManagerPatchManagerOperationSpec? spec)
    {
        var req = new UninstallHostPatchRequestType
        {
            _this = self,
            bulletinIds = bulletinIds,
            spec = spec,
        };

        var res = await this.inner.UninstallHostPatch_TaskAsync(req);

        return res.UninstallHostPatch_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UninstallIoFilter_Task(ManagedObjectReference self, string filterId, ManagedObjectReference compRes)
    {
        var req = new UninstallIoFilterRequestType
        {
            _this = self,
            filterId = filterId,
            compRes = compRes,
        };

        var res = await this.inner.UninstallIoFilter_TaskAsync(req);

        return res.UninstallIoFilter_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UninstallService(ManagedObjectReference self, string id)
    {
        var req = new UninstallServiceRequestType
        {
            _this = self,
            id = id,
        };

        await this.inner.UninstallServiceAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UnmapVmfsVolumeEx_Task(ManagedObjectReference self, string[] vmfsUuid)
    {
        var req = new UnmapVmfsVolumeExRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
        };

        var res = await this.inner.UnmapVmfsVolumeEx_TaskAsync(req);

        return res.UnmapVmfsVolumeEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UnmarkServiceProviderEntities(ManagedObjectReference self, ManagedObjectReference[]? entity)
    {
        var req = new UnmarkServiceProviderEntitiesRequestType
        {
            _this = self,
            entity = entity,
        };

        await this.inner.UnmarkServiceProviderEntitiesAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UnmountDiskMapping_Task(ManagedObjectReference self, VsanHostDiskMapping[] mapping)
    {
        var req = new UnmountDiskMappingRequestType
        {
            _this = self,
            mapping = mapping,
        };

        var res = await this.inner.UnmountDiskMapping_TaskAsync(req);

        return res.UnmountDiskMapping_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UnmountForceMountedVmfsVolume(ManagedObjectReference self, string vmfsUuid)
    {
        var req = new UnmountForceMountedVmfsVolumeRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
        };

        await this.inner.UnmountForceMountedVmfsVolumeAsync(req);
    }

    public async System.Threading.Tasks.Task UnmountToolsInstaller(ManagedObjectReference self)
    {
        var req = new UnmountToolsInstallerRequestType
        {
            _this = self,
        };

        await this.inner.UnmountToolsInstallerAsync(req);
    }

    public async System.Threading.Tasks.Task UnmountVffsVolume(ManagedObjectReference self, string vffsUuid)
    {
        var req = new UnmountVffsVolumeRequestType
        {
            _this = self,
            vffsUuid = vffsUuid,
        };

        await this.inner.UnmountVffsVolumeAsync(req);
    }

    public async System.Threading.Tasks.Task UnmountVmfsVolume(ManagedObjectReference self, string vmfsUuid)
    {
        var req = new UnmountVmfsVolumeRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
        };

        await this.inner.UnmountVmfsVolumeAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UnmountVmfsVolumeEx_Task(ManagedObjectReference self, string[] vmfsUuid)
    {
        var req = new UnmountVmfsVolumeExRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
        };

        var res = await this.inner.UnmountVmfsVolumeEx_TaskAsync(req);

        return res.UnmountVmfsVolumeEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UnregisterAndDestroy_Task(ManagedObjectReference self)
    {
        var req = new UnregisterAndDestroyRequestType
        {
            _this = self,
        };

        var res = await this.inner.UnregisterAndDestroy_TaskAsync(req);

        return res.UnregisterAndDestroy_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UnregisterExtension(ManagedObjectReference self, string extensionKey)
    {
        var req = new UnregisterExtensionRequestType
        {
            _this = self,
            extensionKey = extensionKey,
        };

        await this.inner.UnregisterExtensionAsync(req);
    }

    public async System.Threading.Tasks.Task UnregisterHealthUpdateProvider(ManagedObjectReference self, string providerId)
    {
        var req = new UnregisterHealthUpdateProviderRequestType
        {
            _this = self,
            providerId = providerId,
        };

        await this.inner.UnregisterHealthUpdateProviderAsync(req);
    }

    public async System.Threading.Tasks.Task UnregisterKmsCluster(ManagedObjectReference self, KeyProviderId clusterId)
    {
        var req = new UnregisterKmsClusterRequestType
        {
            _this = self,
            clusterId = clusterId,
        };

        await this.inner.UnregisterKmsClusterAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UnregisterVApp_Task(ManagedObjectReference self)
    {
        var req = new unregisterVAppRequestType
        {
            _this = self,
        };

        var res = await this.inner.unregisterVApp_TaskAsync(req);

        return res.unregisterVApp_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UnregisterVM(ManagedObjectReference self)
    {
        var req = new UnregisterVMRequestType
        {
            _this = self,
        };

        await this.inner.UnregisterVMAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateAnswerFile_Task(ManagedObjectReference self, ManagedObjectReference host, AnswerFileCreateSpec configSpec)
    {
        var req = new UpdateAnswerFileRequestType
        {
            _this = self,
            host = host,
            configSpec = configSpec,
        };

        var res = await this.inner.UpdateAnswerFile_TaskAsync(req);

        return res.UpdateAnswerFile_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpdateAssignableHardwareConfig(ManagedObjectReference self, HostAssignableHardwareConfig config)
    {
        var req = new UpdateAssignableHardwareConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateAssignableHardwareConfigAsync(req);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateAssignedLicense(ManagedObjectReference self, string entity, string licenseKey, string? entityDisplayName)
    {
        var req = new UpdateAssignedLicenseRequestType
        {
            _this = self,
            entity = entity,
            licenseKey = licenseKey,
            entityDisplayName = entityDisplayName,
        };

        var res = await this.inner.UpdateAssignedLicenseAsync(req);

        return res.UpdateAssignedLicenseResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpdateAuthorizationRole(ManagedObjectReference self, int roleId, string newName, string[]? privIds)
    {
        var req = new UpdateAuthorizationRoleRequestType
        {
            _this = self,
            roleId = roleId,
            newName = newName,
            privIds = privIds,
        };

        await this.inner.UpdateAuthorizationRoleAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateBootDevice(ManagedObjectReference self, string key)
    {
        var req = new UpdateBootDeviceRequestType
        {
            _this = self,
            key = key,
        };

        await this.inner.UpdateBootDeviceAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateChildResourceConfiguration(ManagedObjectReference self, ResourceConfigSpec[] spec)
    {
        var req = new UpdateChildResourceConfigurationRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.UpdateChildResourceConfigurationAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateClusterProfile(ManagedObjectReference self, ClusterProfileConfigSpec config)
    {
        var req = new UpdateClusterProfileRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateClusterProfileAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateConfig(ManagedObjectReference self, string? name, ResourceConfigSpec? config)
    {
        var req = new UpdateConfigRequestType
        {
            _this = self,
            name = name,
            config = config,
        };

        await this.inner.UpdateConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateConsoleIpRouteConfig(ManagedObjectReference self, HostIpRouteConfig config)
    {
        var req = new UpdateConsoleIpRouteConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateConsoleIpRouteConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateCounterLevelMapping(ManagedObjectReference self, PerformanceManagerCounterLevelMapping[] counterLevelMap)
    {
        var req = new UpdateCounterLevelMappingRequestType
        {
            _this = self,
            counterLevelMap = counterLevelMap,
        };

        await this.inner.UpdateCounterLevelMappingAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateDateTime(ManagedObjectReference self, DateTime dateTime)
    {
        var req = new UpdateDateTimeRequestType
        {
            _this = self,
            dateTime = dateTime,
        };

        await this.inner.UpdateDateTimeAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateDateTimeConfig(ManagedObjectReference self, HostDateTimeConfig config)
    {
        var req = new UpdateDateTimeConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateDateTimeConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateDefaultPolicy(ManagedObjectReference self, HostFirewallDefaultPolicy defaultPolicy)
    {
        var req = new UpdateDefaultPolicyRequestType
        {
            _this = self,
            defaultPolicy = defaultPolicy,
        };

        await this.inner.UpdateDefaultPolicyAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateDiskPartitions(ManagedObjectReference self, string devicePath, HostDiskPartitionSpec spec)
    {
        var req = new UpdateDiskPartitionsRequestType
        {
            _this = self,
            devicePath = devicePath,
            spec = spec,
        };

        await this.inner.UpdateDiskPartitionsAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateDnsConfig(ManagedObjectReference self, HostDnsConfig config)
    {
        var req = new UpdateDnsConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateDnsConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateDvsCapability(ManagedObjectReference self, DVSCapability capability)
    {
        var req = new UpdateDvsCapabilityRequestType
        {
            _this = self,
            capability = capability,
        };

        await this.inner.UpdateDvsCapabilityAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateDVSHealthCheckConfig_Task(ManagedObjectReference self, DVSHealthCheckConfig[] healthCheckConfig)
    {
        var req = new UpdateDVSHealthCheckConfigRequestType
        {
            _this = self,
            healthCheckConfig = healthCheckConfig,
        };

        var res = await this.inner.UpdateDVSHealthCheckConfig_TaskAsync(req);

        return res.UpdateDVSHealthCheckConfig_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateDVSLacpGroupConfig_Task(ManagedObjectReference self, VMwareDvsLacpGroupSpec[] lacpGroupSpec)
    {
        var req = new UpdateDVSLacpGroupConfigRequestType
        {
            _this = self,
            lacpGroupSpec = lacpGroupSpec,
        };

        var res = await this.inner.UpdateDVSLacpGroupConfig_TaskAsync(req);

        return res.UpdateDVSLacpGroupConfig_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpdateExtension(ManagedObjectReference self, Extension extension)
    {
        var req = new UpdateExtensionRequestType
        {
            _this = self,
            extension = extension,
        };

        await this.inner.UpdateExtensionAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateFlags(ManagedObjectReference self, HostFlagInfo flagInfo)
    {
        var req = new UpdateFlagsRequestType
        {
            _this = self,
            flagInfo = flagInfo,
        };

        await this.inner.UpdateFlagsAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateGraphicsConfig(ManagedObjectReference self, HostGraphicsConfig config)
    {
        var req = new UpdateGraphicsConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateGraphicsConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateHostImageAcceptanceLevel(ManagedObjectReference self, string newAcceptanceLevel)
    {
        var req = new UpdateHostImageAcceptanceLevelRequestType
        {
            _this = self,
            newAcceptanceLevel = newAcceptanceLevel,
        };

        await this.inner.UpdateHostImageAcceptanceLevelAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateHostProfile(ManagedObjectReference self, HostProfileConfigSpec config)
    {
        var req = new UpdateHostProfileRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateHostProfileAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateHostSpecification(ManagedObjectReference self, ManagedObjectReference host, HostSpecification hostSpec)
    {
        var req = new UpdateHostSpecificationRequestType
        {
            _this = self,
            host = host,
            hostSpec = hostSpec,
        };

        await this.inner.UpdateHostSpecificationAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateHostSubSpecification(ManagedObjectReference self, ManagedObjectReference host, HostSubSpecification hostSubSpec)
    {
        var req = new UpdateHostSubSpecificationRequestType
        {
            _this = self,
            host = host,
            hostSubSpec = hostSubSpec,
        };

        await this.inner.UpdateHostSubSpecificationAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateHppMultipathLunPolicy(ManagedObjectReference self, string lunId, HostMultipathInfoHppLogicalUnitPolicy policy)
    {
        var req = new UpdateHppMultipathLunPolicyRequestType
        {
            _this = self,
            lunId = lunId,
            policy = policy,
        };

        await this.inner.UpdateHppMultipathLunPolicyAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAdvancedOptions(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaParamValue[] options)
    {
        var req = new UpdateInternetScsiAdvancedOptionsRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            targetSet = targetSet,
            options = options,
        };

        await this.inner.UpdateInternetScsiAdvancedOptionsAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAlias(ManagedObjectReference self, string iScsiHbaDevice, string iScsiAlias)
    {
        var req = new UpdateInternetScsiAliasRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            iScsiAlias = iScsiAlias,
        };

        await this.inner.UpdateInternetScsiAliasAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiAuthenticationProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaAuthenticationProperties authenticationProperties, HostInternetScsiHbaTargetSet? targetSet)
    {
        var req = new UpdateInternetScsiAuthenticationPropertiesRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            authenticationProperties = authenticationProperties,
            targetSet = targetSet,
        };

        await this.inner.UpdateInternetScsiAuthenticationPropertiesAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDigestProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaTargetSet? targetSet, HostInternetScsiHbaDigestProperties digestProperties)
    {
        var req = new UpdateInternetScsiDigestPropertiesRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            targetSet = targetSet,
            digestProperties = digestProperties,
        };

        await this.inner.UpdateInternetScsiDigestPropertiesAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiDiscoveryProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaDiscoveryProperties discoveryProperties)
    {
        var req = new UpdateInternetScsiDiscoveryPropertiesRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            discoveryProperties = discoveryProperties,
        };

        await this.inner.UpdateInternetScsiDiscoveryPropertiesAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiIPProperties(ManagedObjectReference self, string iScsiHbaDevice, HostInternetScsiHbaIPProperties ipProperties)
    {
        var req = new UpdateInternetScsiIPPropertiesRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            ipProperties = ipProperties,
        };

        await this.inner.UpdateInternetScsiIPPropertiesAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateInternetScsiName(ManagedObjectReference self, string iScsiHbaDevice, string iScsiName)
    {
        var req = new UpdateInternetScsiNameRequestType
        {
            _this = self,
            iScsiHbaDevice = iScsiHbaDevice,
            iScsiName = iScsiName,
        };

        await this.inner.UpdateInternetScsiNameAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateIpConfig(ManagedObjectReference self, HostIpConfig ipConfig)
    {
        var req = new UpdateIpConfigRequestType
        {
            _this = self,
            ipConfig = ipConfig,
        };

        await this.inner.UpdateIpConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateIpmi(ManagedObjectReference self, HostIpmiInfo ipmiInfo)
    {
        var req = new UpdateIpmiRequestType
        {
            _this = self,
            ipmiInfo = ipmiInfo,
        };

        await this.inner.UpdateIpmiAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateIpPool(ManagedObjectReference self, ManagedObjectReference dc, IpPool pool)
    {
        var req = new UpdateIpPoolRequestType
        {
            _this = self,
            dc = dc,
            pool = pool,
        };

        await this.inner.UpdateIpPoolAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteConfig(ManagedObjectReference self, HostIpRouteConfig config)
    {
        var req = new UpdateIpRouteConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateIpRouteConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateIpRouteTableConfig(ManagedObjectReference self, HostIpRouteTableConfig config)
    {
        var req = new UpdateIpRouteTableConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdateIpRouteTableConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateKmipServer(ManagedObjectReference self, KmipServerSpec server)
    {
        var req = new UpdateKmipServerRequestType
        {
            _this = self,
            server = server,
        };

        await this.inner.UpdateKmipServerAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateKmsSignedCsrClientCert(ManagedObjectReference self, KeyProviderId cluster, string certificate)
    {
        var req = new UpdateKmsSignedCsrClientCertRequestType
        {
            _this = self,
            cluster = cluster,
            certificate = certificate,
        };

        await this.inner.UpdateKmsSignedCsrClientCertAsync(req);
    }

    public async System.Threading.Tasks.Task<LicenseManagerLicenseInfo?> UpdateLicense(ManagedObjectReference self, string licenseKey, KeyValue[]? labels)
    {
        var req = new UpdateLicenseRequestType
        {
            _this = self,
            licenseKey = licenseKey,
            labels = labels,
        };

        var res = await this.inner.UpdateLicenseAsync(req);

        return res.UpdateLicenseResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpdateLicenseLabel(ManagedObjectReference self, string licenseKey, string labelKey, string labelValue)
    {
        var req = new UpdateLicenseLabelRequestType
        {
            _this = self,
            licenseKey = licenseKey,
            labelKey = labelKey,
            labelValue = labelValue,
        };

        await this.inner.UpdateLicenseLabelAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateLinkedChildren(ManagedObjectReference self, VirtualAppLinkInfo[]? addChangeSet, ManagedObjectReference[]? removeSet)
    {
        var req = new UpdateLinkedChildrenRequestType
        {
            _this = self,
            addChangeSet = addChangeSet,
            removeSet = removeSet,
        };

        await this.inner.UpdateLinkedChildrenAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateLocalSwapDatastore(ManagedObjectReference self, ManagedObjectReference? datastore)
    {
        var req = new UpdateLocalSwapDatastoreRequestType
        {
            _this = self,
            datastore = datastore,
        };

        await this.inner.UpdateLocalSwapDatastoreAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateLockdownExceptions(ManagedObjectReference self, string[]? users)
    {
        var req = new UpdateLockdownExceptionsRequestType
        {
            _this = self,
            users = users,
        };

        await this.inner.UpdateLockdownExceptionsAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateModuleOptionString(ManagedObjectReference self, string name, string options)
    {
        var req = new UpdateModuleOptionStringRequestType
        {
            _this = self,
            name = name,
            options = options,
        };

        await this.inner.UpdateModuleOptionStringAsync(req);
    }

    public async System.Threading.Tasks.Task<HostNetworkConfigResult?> UpdateNetworkConfig(ManagedObjectReference self, HostNetworkConfig config, string changeMode)
    {
        var req = new UpdateNetworkConfigRequestType
        {
            _this = self,
            config = config,
            changeMode = changeMode,
        };

        var res = await this.inner.UpdateNetworkConfigAsync(req);

        return res.UpdateNetworkConfigResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpdateNetworkResourcePool(ManagedObjectReference self, DVSNetworkResourcePoolConfigSpec[] configSpec)
    {
        var req = new UpdateNetworkResourcePoolRequestType
        {
            _this = self,
            configSpec = configSpec,
        };

        await this.inner.UpdateNetworkResourcePoolAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateOptions(ManagedObjectReference self, OptionValue[] changedValue)
    {
        var req = new UpdateOptionsRequestType
        {
            _this = self,
            changedValue = changedValue,
        };

        await this.inner.UpdateOptionsAsync(req);
    }

    public async System.Threading.Tasks.Task UpdatePassthruConfig(ManagedObjectReference self, HostPciPassthruConfig[] config)
    {
        var req = new UpdatePassthruConfigRequestType
        {
            _this = self,
            config = config,
        };

        await this.inner.UpdatePassthruConfigAsync(req);
    }

    public async System.Threading.Tasks.Task UpdatePerfInterval(ManagedObjectReference self, PerfInterval interval)
    {
        var req = new UpdatePerfIntervalRequestType
        {
            _this = self,
            interval = interval,
        };

        await this.inner.UpdatePerfIntervalAsync(req);
    }

    public async System.Threading.Tasks.Task UpdatePhysicalNicLinkSpeed(ManagedObjectReference self, string device, PhysicalNicLinkInfo? linkSpeed)
    {
        var req = new UpdatePhysicalNicLinkSpeedRequestType
        {
            _this = self,
            device = device,
            linkSpeed = linkSpeed,
        };

        await this.inner.UpdatePhysicalNicLinkSpeedAsync(req);
    }

    public async System.Threading.Tasks.Task UpdatePortGroup(ManagedObjectReference self, string pgName, HostPortGroupSpec portgrp)
    {
        var req = new UpdatePortGroupRequestType
        {
            _this = self,
            pgName = pgName,
            portgrp = portgrp,
        };

        await this.inner.UpdatePortGroupAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateProductLockerLocation_Task(ManagedObjectReference self, string path)
    {
        var req = new UpdateProductLockerLocationRequestType
        {
            _this = self,
            path = path,
        };

        var res = await this.inner.UpdateProductLockerLocation_TaskAsync(req);

        return res.UpdateProductLockerLocation_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpdateProgress(ManagedObjectReference self, int percentDone)
    {
        var req = new UpdateProgressRequestType
        {
            _this = self,
            percentDone = percentDone,
        };

        await this.inner.UpdateProgressAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateReferenceHost(ManagedObjectReference self, ManagedObjectReference? host)
    {
        var req = new UpdateReferenceHostRequestType
        {
            _this = self,
            host = host,
        };

        await this.inner.UpdateReferenceHostAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateRuleset(ManagedObjectReference self, string id, HostFirewallRulesetRulesetSpec spec)
    {
        var req = new UpdateRulesetRequestType
        {
            _this = self,
            id = id,
            spec = spec,
        };

        await this.inner.UpdateRulesetAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateScsiLunDisplayName(ManagedObjectReference self, string lunUuid, string displayName)
    {
        var req = new UpdateScsiLunDisplayNameRequestType
        {
            _this = self,
            lunUuid = lunUuid,
            displayName = displayName,
        };

        await this.inner.UpdateScsiLunDisplayNameAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateSelfSignedClientCert(ManagedObjectReference self, KeyProviderId cluster, string certificate)
    {
        var req = new UpdateSelfSignedClientCertRequestType
        {
            _this = self,
            cluster = cluster,
            certificate = certificate,
        };

        await this.inner.UpdateSelfSignedClientCertAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateServiceConsoleVirtualNic(ManagedObjectReference self, string device, HostVirtualNicSpec nic)
    {
        var req = new UpdateServiceConsoleVirtualNicRequestType
        {
            _this = self,
            device = device,
            nic = nic,
        };

        await this.inner.UpdateServiceConsoleVirtualNicAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateServiceMessage(ManagedObjectReference self, string message)
    {
        var req = new UpdateServiceMessageRequestType
        {
            _this = self,
            message = message,
        };

        await this.inner.UpdateServiceMessageAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateServicePolicy(ManagedObjectReference self, string id, string policy)
    {
        var req = new UpdateServicePolicyRequestType
        {
            _this = self,
            id = id,
            policy = policy,
        };

        await this.inner.UpdateServicePolicyAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateSoftwareInternetScsiEnabled(ManagedObjectReference self, bool enabled)
    {
        var req = new UpdateSoftwareInternetScsiEnabledRequestType
        {
            _this = self,
            enabled = enabled,
        };

        await this.inner.UpdateSoftwareInternetScsiEnabledAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateSystemResources(ManagedObjectReference self, HostSystemResourceInfo resourceInfo)
    {
        var req = new UpdateSystemResourcesRequestType
        {
            _this = self,
            resourceInfo = resourceInfo,
        };

        await this.inner.UpdateSystemResourcesAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateSystemSwapConfiguration(ManagedObjectReference self, HostSystemSwapConfiguration sysSwapConfig)
    {
        var req = new UpdateSystemSwapConfigurationRequestType
        {
            _this = self,
            sysSwapConfig = sysSwapConfig,
        };

        await this.inner.UpdateSystemSwapConfigurationAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateSystemUsers(ManagedObjectReference self, string[]? users)
    {
        var req = new UpdateSystemUsersRequestType
        {
            _this = self,
            users = users,
        };

        await this.inner.UpdateSystemUsersAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateUser(ManagedObjectReference self, HostAccountSpec user)
    {
        var req = new UpdateUserRequestType
        {
            _this = self,
            user = user,
        };

        await this.inner.UpdateUserAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateVAppConfig(ManagedObjectReference self, VAppConfigSpec spec)
    {
        var req = new UpdateVAppConfigRequestType
        {
            _this = self,
            spec = spec,
        };

        await this.inner.UpdateVAppConfigAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVirtualMachineFiles_Task(ManagedObjectReference self, DatastoreMountPathDatastorePair[] mountPathDatastoreMapping)
    {
        var req = new UpdateVirtualMachineFilesRequestType
        {
            _this = self,
            mountPathDatastoreMapping = mountPathDatastoreMapping,
        };

        var res = await this.inner.UpdateVirtualMachineFiles_TaskAsync(req);

        return res.UpdateVirtualMachineFiles_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpdateVirtualNic(ManagedObjectReference self, string device, HostVirtualNicSpec nic)
    {
        var req = new UpdateVirtualNicRequestType
        {
            _this = self,
            device = device,
            nic = nic,
        };

        await this.inner.UpdateVirtualNicAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateVirtualSwitch(ManagedObjectReference self, string vswitchName, HostVirtualSwitchSpec spec)
    {
        var req = new UpdateVirtualSwitchRequestType
        {
            _this = self,
            vswitchName = vswitchName,
            spec = spec,
        };

        await this.inner.UpdateVirtualSwitchAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapBandwidth(ManagedObjectReference self, string vmfsUuid, VmfsUnmapBandwidthSpec unmapBandwidthSpec)
    {
        var req = new UpdateVmfsUnmapBandwidthRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
            unmapBandwidthSpec = unmapBandwidthSpec,
        };

        await this.inner.UpdateVmfsUnmapBandwidthAsync(req);
    }

    public async System.Threading.Tasks.Task UpdateVmfsUnmapPriority(ManagedObjectReference self, string vmfsUuid, string unmapPriority)
    {
        var req = new UpdateVmfsUnmapPriorityRequestType
        {
            _this = self,
            vmfsUuid = vmfsUuid,
            unmapPriority = unmapPriority,
        };

        await this.inner.UpdateVmfsUnmapPriorityAsync(req);
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVsan_Task(ManagedObjectReference self, VsanHostConfigInfo config)
    {
        var req = new UpdateVsanRequestType
        {
            _this = self,
            config = config,
        };

        var res = await this.inner.UpdateVsan_TaskAsync(req);

        return res.UpdateVsan_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVStorageInfrastructureObjectPolicy_Task(ManagedObjectReference self, vslmInfrastructureObjectPolicySpec spec)
    {
        var req = new UpdateVStorageInfrastructureObjectPolicyRequestType
        {
            _this = self,
            spec = spec,
        };

        var res = await this.inner.UpdateVStorageInfrastructureObjectPolicy_TaskAsync(req);

        return res.UpdateVStorageInfrastructureObjectPolicy_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVStorageObjectCrypto_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VirtualMachineProfileSpec[]? profile, DiskCryptoSpec? disksCrypto)
    {
        var req = new UpdateVStorageObjectCryptoRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            profile = profile,
            disksCrypto = disksCrypto,
        };

        var res = await this.inner.UpdateVStorageObjectCrypto_TaskAsync(req);

        return res.UpdateVStorageObjectCrypto_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVStorageObjectPolicy_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, VirtualMachineProfileSpec[]? profile)
    {
        var req = new UpdateVStorageObjectPolicyRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            profile = profile,
        };

        var res = await this.inner.UpdateVStorageObjectPolicy_TaskAsync(req);

        return res.UpdateVStorageObjectPolicy_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpdateVVolVirtualMachineFiles_Task(ManagedObjectReference self, DatastoreVVolContainerFailoverPair[]? failoverPair)
    {
        var req = new UpdateVVolVirtualMachineFilesRequestType
        {
            _this = self,
            failoverPair = failoverPair,
        };

        var res = await this.inner.UpdateVVolVirtualMachineFiles_TaskAsync(req);

        return res.UpdateVVolVirtualMachineFiles_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpgradeIoFilter_Task(ManagedObjectReference self, string filterId, ManagedObjectReference compRes, string vibUrl, IoFilterManagerSslTrust? vibSslTrust)
    {
        var req = new UpgradeIoFilterRequestType
        {
            _this = self,
            filterId = filterId,
            compRes = compRes,
            vibUrl = vibUrl,
            vibSslTrust = vibSslTrust,
        };

        var res = await this.inner.UpgradeIoFilter_TaskAsync(req);

        return res.UpgradeIoFilter_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpgradeTools_Task(ManagedObjectReference self, string? installerOptions)
    {
        var req = new UpgradeToolsRequestType
        {
            _this = self,
            installerOptions = installerOptions,
        };

        var res = await this.inner.UpgradeTools_TaskAsync(req);

        return res.UpgradeTools_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> UpgradeVM_Task(ManagedObjectReference self, string? version)
    {
        var req = new UpgradeVMRequestType
        {
            _this = self,
            version = version,
        };

        var res = await this.inner.UpgradeVM_TaskAsync(req);

        return res.UpgradeVM_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task UpgradeVmfs(ManagedObjectReference self, string vmfsPath)
    {
        var req = new UpgradeVmfsRequestType
        {
            _this = self,
            vmfsPath = vmfsPath,
        };

        await this.inner.UpgradeVmfsAsync(req);
    }

    public async System.Threading.Tasks.Task UpgradeVmLayout(ManagedObjectReference self)
    {
        var req = new UpgradeVmLayoutRequestType
        {
            _this = self,
        };

        await this.inner.UpgradeVmLayoutAsync(req);
    }

    public async System.Threading.Tasks.Task<HostVsanInternalSystemVsanObjectOperationResult[]?> UpgradeVsanObjects(ManagedObjectReference self, string[] uuids, int newVersion)
    {
        var req = new UpgradeVsanObjectsRequestType
        {
            _this = self,
            uuids = uuids,
            newVersion = newVersion,
        };

        var res = await this.inner.UpgradeVsanObjectsAsync(req);

        return res.UpgradeVsanObjectsResponse1;
    }

    public async System.Threading.Tasks.Task UploadClientCert(ManagedObjectReference self, KeyProviderId cluster, string certificate, string privateKey)
    {
        var req = new UploadClientCertRequestType
        {
            _this = self,
            cluster = cluster,
            certificate = certificate,
            privateKey = privateKey,
        };

        await this.inner.UploadClientCertAsync(req);
    }

    public async System.Threading.Tasks.Task UploadKmipServerCert(ManagedObjectReference self, KeyProviderId cluster, string certificate)
    {
        var req = new UploadKmipServerCertRequestType
        {
            _this = self,
            cluster = cluster,
            certificate = certificate,
        };

        await this.inner.UploadKmipServerCertAsync(req);
    }

    public async System.Threading.Tasks.Task ValidateCredentialsInGuest(ManagedObjectReference self, ManagedObjectReference vm, GuestAuthentication auth)
    {
        var req = new ValidateCredentialsInGuestRequestType
        {
            _this = self,
            vm = vm,
            auth = auth,
        };

        await this.inner.ValidateCredentialsInGuestAsync(req);
    }

    public async System.Threading.Tasks.Task<ClusterComputeResourceValidationResultBase[]?> ValidateHCIConfiguration(ManagedObjectReference self, ClusterComputeResourceHCIConfigSpec? hciConfigSpec, ManagedObjectReference[]? hosts)
    {
        var req = new ValidateHCIConfigurationRequestType
        {
            _this = self,
            hciConfigSpec = hciConfigSpec,
            hosts = hosts,
        };

        var res = await this.inner.ValidateHCIConfigurationAsync(req);

        return res.ValidateHCIConfigurationResponse1;
    }

    public async System.Threading.Tasks.Task<OvfValidateHostResult?> ValidateHost(ManagedObjectReference self, string ovfDescriptor, ManagedObjectReference host, OvfValidateHostParams vhp)
    {
        var req = new ValidateHostRequestType
        {
            _this = self,
            ovfDescriptor = ovfDescriptor,
            host = host,
            vhp = vhp,
        };

        var res = await this.inner.ValidateHostAsync(req);

        return res.ValidateHostResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ValidateHostProfileComposition_Task(ManagedObjectReference self, ManagedObjectReference source, ManagedObjectReference[]? targets, HostApplyProfile? toBeMerged, HostApplyProfile? toReplaceWith, HostApplyProfile? toBeDeleted, HostApplyProfile? enableStatusToBeCopied, bool errorOnly, bool errorOnlySpecified)
    {
        var req = new ValidateHostProfileCompositionRequestType
        {
            _this = self,
            source = source,
            targets = targets,
            toBeMerged = toBeMerged,
            toReplaceWith = toReplaceWith,
            toBeDeleted = toBeDeleted,
            enableStatusToBeCopied = enableStatusToBeCopied,
            errorOnly = errorOnly,
            errorOnlySpecified = errorOnlySpecified,
        };

        var res = await this.inner.ValidateHostProfileComposition_TaskAsync(req);

        return res.ValidateHostProfileComposition_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<Event[]?> ValidateMigration(ManagedObjectReference self, ManagedObjectReference[] vm, VirtualMachinePowerState state, bool stateSpecified, string[]? testType, ManagedObjectReference? pool, ManagedObjectReference? host)
    {
        var req = new ValidateMigrationRequestType
        {
            _this = self,
            vm = vm,
            state = state,
            stateSpecified = stateSpecified,
            testType = testType,
            pool = pool,
            host = host,
        };

        var res = await this.inner.ValidateMigrationAsync(req);

        return res.ValidateMigrationResponse1;
    }

    public async System.Threading.Tasks.Task<LocalizedMethodFault?> ValidateStoragePodConfig(ManagedObjectReference self, ManagedObjectReference pod, StorageDrsConfigSpec spec)
    {
        var req = new ValidateStoragePodConfigRequestType
        {
            _this = self,
            pod = pod,
            spec = spec,
        };

        var res = await this.inner.ValidateStoragePodConfigAsync(req);

        return res.ValidateStoragePodConfigResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VCenterUpdateVStorageObjectMetadataEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, KeyValue[]? metadata, string[]? deleteKeys)
    {
        var req = new VCenterUpdateVStorageObjectMetadataExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            metadata = metadata,
            deleteKeys = deleteKeys,
        };

        var res = await this.inner.VCenterUpdateVStorageObjectMetadataEx_TaskAsync(req);

        return res.VCenterUpdateVStorageObjectMetadataEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectCreateSnapshot_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string description)
    {
        var req = new VStorageObjectCreateSnapshotRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            description = description,
        };

        var res = await this.inner.VStorageObjectCreateSnapshot_TaskAsync(req);

        return res.VStorageObjectCreateSnapshot_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectCreateSnapshotEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, string description)
    {
        var req = new VStorageObjectCreateSnapshotExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            description = description,
        };

        var res = await this.inner.VStorageObjectCreateSnapshotEx_TaskAsync(req);

        return res.VStorageObjectCreateSnapshotEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectDeleteSnapshotEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new VStorageObjectDeleteSnapshotExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.VStorageObjectDeleteSnapshotEx_TaskAsync(req);

        return res.VStorageObjectDeleteSnapshotEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectDeleteSnapshotEx2_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId)
    {
        var req = new VStorageObjectDeleteSnapshotEx2RequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
        };

        var res = await this.inner.VStorageObjectDeleteSnapshotEx2_TaskAsync(req);

        return res.VStorageObjectDeleteSnapshotEx2_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> VStorageObjectExtendDiskEx_Task(ManagedObjectReference self, ID id, ManagedObjectReference datastore, long newCapacityInMB)
    {
        var req = new VStorageObjectExtendDiskExRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            newCapacityInMB = newCapacityInMB,
        };

        var res = await this.inner.VStorageObjectExtendDiskEx_TaskAsync(req);

        return res.VStorageObjectExtendDiskEx_TaskResponse.returnval;
    }

    public async System.Threading.Tasks.Task<DiskChangeInfo?> VstorageObjectVCenterQueryChangedDiskAreas(ManagedObjectReference self, ID id, ManagedObjectReference datastore, ID snapshotId, long startOffset, string changeId)
    {
        var req = new VstorageObjectVCenterQueryChangedDiskAreasRequestType
        {
            _this = self,
            id = id,
            datastore = datastore,
            snapshotId = snapshotId,
            startOffset = startOffset,
            changeId = changeId,
        };

        var res = await this.inner.VstorageObjectVCenterQueryChangedDiskAreasAsync(req);

        return res.VstorageObjectVCenterQueryChangedDiskAreasResponse.returnval;
    }

    public async System.Threading.Tasks.Task<UpdateSet?> WaitForUpdates(ManagedObjectReference self, string? version)
    {
        var req = new WaitForUpdatesRequestType
        {
            _this = self,
            version = version,
        };

        var res = await this.inner.WaitForUpdatesAsync(req);

        return res.WaitForUpdatesResponse.returnval;
    }

    public async System.Threading.Tasks.Task<UpdateSet?> WaitForUpdatesEx(ManagedObjectReference self, string? version, WaitOptions? options)
    {
        var req = new WaitForUpdatesExRequestType
        {
            _this = self,
            version = version,
            options = options,
        };

        var res = await this.inner.WaitForUpdatesExAsync(req);

        return res.WaitForUpdatesExResponse.returnval;
    }

    public async System.Threading.Tasks.Task<CustomizationSpecItem?> XmlToCustomizationSpecItem(ManagedObjectReference self, string specItemXml)
    {
        var req = new XmlToCustomizationSpecItemRequestType
        {
            _this = self,
            specItemXml = specItemXml,
        };

        var res = await this.inner.XmlToCustomizationSpecItemAsync(req);

        return res.XmlToCustomizationSpecItemResponse.returnval;
    }

    public async System.Threading.Tasks.Task<ManagedObjectReference?> ZeroFillVirtualDisk_Task(ManagedObjectReference self, string name, ManagedObjectReference? datacenter)
    {
        var req = new ZeroFillVirtualDiskRequestType
        {
            _this = self,
            name = name,
            datacenter = datacenter,
        };

        var res = await this.inner.ZeroFillVirtualDisk_TaskAsync(req);

        return res.ZeroFillVirtualDisk_TaskResponse.returnval;
    }

}

#pragma warning restore IDE0058 // Expression value is never used

namespace CsVmomi;

using System.ServiceModel.Channels;
using PbmService;

#pragma warning disable IDE0058 // Expression value is never used

public class PbmClient : IPbmClient
{
    private readonly PbmPortTypeClient inner;

    internal PbmClient(PbmPortTypeClient inner)
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

    public async System.Threading.Tasks.Task PbmAssignDefaultRequirementProfile(ManagedObjectReference self, PbmProfileId profile, PbmPlacementHub[] datastores)
    {
        var req = new PbmAssignDefaultRequirementProfileRequestType
        {
            _this = self,
            profile = profile,
            datastores = datastores,
        };

        await this.inner.PbmAssignDefaultRequirementProfileAsync(req);
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckCompatibility(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmProfileId profile)
    {
        var req = new PbmCheckCompatibilityRequestType
        {
            _this = self,
            hubsToSearch = hubsToSearch,
            profile = profile,
        };

        var res = await this.inner.PbmCheckCompatibilityAsync(req);

        return res.PbmCheckCompatibilityResponse1;
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckCompatibilityWithSpec(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec profileSpec)
    {
        var req = new PbmCheckCompatibilityWithSpecRequestType
        {
            _this = self,
            hubsToSearch = hubsToSearch,
            profileSpec = profileSpec,
        };

        var res = await this.inner.PbmCheckCompatibilityWithSpecAsync(req);

        return res.PbmCheckCompatibilityWithSpecResponse1;
    }

    public async System.Threading.Tasks.Task<PbmComplianceResult[]?> PbmCheckCompliance(ManagedObjectReference self, PbmServerObjectRef[] entities, PbmProfileId? profile)
    {
        var req = new PbmCheckComplianceRequestType
        {
            _this = self,
            entities = entities,
            profile = profile,
        };

        var res = await this.inner.PbmCheckComplianceAsync(req);

        return res.PbmCheckComplianceResponse1;
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckRequirements(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmServerObjectRef? placementSubjectRef, PbmPlacementRequirement[]? placementSubjectRequirement)
    {
        var req = new PbmCheckRequirementsRequestType
        {
            _this = self,
            hubsToSearch = hubsToSearch,
            placementSubjectRef = placementSubjectRef,
            placementSubjectRequirement = placementSubjectRequirement,
        };

        var res = await this.inner.PbmCheckRequirementsAsync(req);

        return res.PbmCheckRequirementsResponse1;
    }

    public async System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmCheckRollupCompliance(ManagedObjectReference self, PbmServerObjectRef[] entity)
    {
        var req = new PbmCheckRollupComplianceRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.PbmCheckRollupComplianceAsync(req);

        return res.PbmCheckRollupComplianceResponse1;
    }

    public async System.Threading.Tasks.Task<PbmProfileId?> PbmCreate(ManagedObjectReference self, PbmCapabilityProfileCreateSpec createSpec)
    {
        var req = new PbmCreateRequestType
        {
            _this = self,
            createSpec = createSpec,
        };

        var res = await this.inner.PbmCreateAsync(req);

        return res.PbmCreateResponse.returnval;
    }

    public async System.Threading.Tasks.Task<PbmProfileOperationOutcome[]?> PbmDelete(ManagedObjectReference self, PbmProfileId[] profileId)
    {
        var req = new PbmDeleteRequestType
        {
            _this = self,
            profileId = profileId,
        };

        var res = await this.inner.PbmDeleteAsync(req);

        return res.PbmDeleteResponse1;
    }

    public async System.Threading.Tasks.Task<PbmCapabilityMetadataPerCategory[]?> PbmFetchCapabilityMetadata(ManagedObjectReference self, PbmProfileResourceType? resourceType, string? vendorUuid)
    {
        var req = new PbmFetchCapabilityMetadataRequestType
        {
            _this = self,
            resourceType = resourceType,
            vendorUuid = vendorUuid,
        };

        var res = await this.inner.PbmFetchCapabilityMetadataAsync(req);

        return res.PbmFetchCapabilityMetadataResponse1;
    }

    public async System.Threading.Tasks.Task<PbmCapabilitySchema[]?> PbmFetchCapabilitySchema(ManagedObjectReference self, string? vendorUuid, string[]? lineOfService)
    {
        var req = new PbmFetchCapabilitySchemaRequestType
        {
            _this = self,
            vendorUuid = vendorUuid,
            lineOfService = lineOfService,
        };

        var res = await this.inner.PbmFetchCapabilitySchemaAsync(req);

        return res.PbmFetchCapabilitySchemaResponse1;
    }

    public async System.Threading.Tasks.Task<PbmComplianceResult[]?> PbmFetchComplianceResult(ManagedObjectReference self, PbmServerObjectRef[] entities, PbmProfileId? profile)
    {
        var req = new PbmFetchComplianceResultRequestType
        {
            _this = self,
            entities = entities,
            profile = profile,
        };

        var res = await this.inner.PbmFetchComplianceResultAsync(req);

        return res.PbmFetchComplianceResultResponse1;
    }

    public async System.Threading.Tasks.Task<PbmProfileResourceType[]?> PbmFetchResourceType(ManagedObjectReference self)
    {
        var req = new PbmFetchResourceTypeRequestType
        {
            _this = self,
        };

        var res = await this.inner.PbmFetchResourceTypeAsync(req);

        return res.PbmFetchResourceTypeResponse1;
    }

    public async System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmFetchRollupComplianceResult(ManagedObjectReference self, PbmServerObjectRef[] entity)
    {
        var req = new PbmFetchRollupComplianceResultRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.PbmFetchRollupComplianceResultAsync(req);

        return res.PbmFetchRollupComplianceResultResponse1;
    }

    public async System.Threading.Tasks.Task<PbmCapabilityVendorResourceTypeInfo[]?> PbmFetchVendorInfo(ManagedObjectReference self, PbmProfileResourceType? resourceType)
    {
        var req = new PbmFetchVendorInfoRequestType
        {
            _this = self,
            resourceType = resourceType,
        };

        var res = await this.inner.PbmFetchVendorInfoAsync(req);

        return res.PbmFetchVendorInfoResponse1;
    }

    public async System.Threading.Tasks.Task<PbmProfile[]?> PbmFindApplicableDefaultProfile(ManagedObjectReference self, PbmPlacementHub[] datastores)
    {
        var req = new PbmFindApplicableDefaultProfileRequestType
        {
            _this = self,
            datastores = datastores,
        };

        var res = await this.inner.PbmFindApplicableDefaultProfileAsync(req);

        return res.PbmFindApplicableDefaultProfileResponse1;
    }

    public async System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedEntities(ManagedObjectReference self, PbmProfileId[]? profiles)
    {
        var req = new PbmQueryAssociatedEntitiesRequestType
        {
            _this = self,
            profiles = profiles,
        };

        var res = await this.inner.PbmQueryAssociatedEntitiesAsync(req);

        return res.PbmQueryAssociatedEntitiesResponse1;
    }

    public async System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryAssociatedEntity(ManagedObjectReference self, PbmProfileId profile, string? entityType)
    {
        var req = new PbmQueryAssociatedEntityRequestType
        {
            _this = self,
            profile = profile,
            entityType = entityType,
        };

        var res = await this.inner.PbmQueryAssociatedEntityAsync(req);

        return res.PbmQueryAssociatedEntityResponse1;
    }

    public async System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryAssociatedProfile(ManagedObjectReference self, PbmServerObjectRef entity)
    {
        var req = new PbmQueryAssociatedProfileRequestType
        {
            _this = self,
            entity = entity,
        };

        var res = await this.inner.PbmQueryAssociatedProfileAsync(req);

        return res.PbmQueryAssociatedProfileResponse1;
    }

    public async System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedProfiles(ManagedObjectReference self, PbmServerObjectRef[] entities)
    {
        var req = new PbmQueryAssociatedProfilesRequestType
        {
            _this = self,
            entities = entities,
        };

        var res = await this.inner.PbmQueryAssociatedProfilesAsync(req);

        return res.PbmQueryAssociatedProfilesResponse1;
    }

    public async System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryByRollupComplianceStatus(ManagedObjectReference self, string status)
    {
        var req = new PbmQueryByRollupComplianceStatusRequestType
        {
            _this = self,
            status = status,
        };

        var res = await this.inner.PbmQueryByRollupComplianceStatusAsync(req);

        return res.PbmQueryByRollupComplianceStatusResponse1;
    }

    public async System.Threading.Tasks.Task<PbmProfileId?> PbmQueryDefaultRequirementProfile(ManagedObjectReference self, PbmPlacementHub hub)
    {
        var req = new PbmQueryDefaultRequirementProfileRequestType
        {
            _this = self,
            hub = hub,
        };

        var res = await this.inner.PbmQueryDefaultRequirementProfileAsync(req);

        return res.PbmQueryDefaultRequirementProfileResponse.returnval;
    }

    public async System.Threading.Tasks.Task<PbmDefaultProfileInfo[]?> PbmQueryDefaultRequirementProfiles(ManagedObjectReference self, PbmPlacementHub[] datastores)
    {
        var req = new PbmQueryDefaultRequirementProfilesRequestType
        {
            _this = self,
            datastores = datastores,
        };

        var res = await this.inner.PbmQueryDefaultRequirementProfilesAsync(req);

        return res.PbmQueryDefaultRequirementProfilesResponse1;
    }

    public async System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHub(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmProfileId profile)
    {
        var req = new PbmQueryMatchingHubRequestType
        {
            _this = self,
            hubsToSearch = hubsToSearch,
            profile = profile,
        };

        var res = await this.inner.PbmQueryMatchingHubAsync(req);

        return res.PbmQueryMatchingHubResponse1;
    }

    public async System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHubWithSpec(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec createSpec)
    {
        var req = new PbmQueryMatchingHubWithSpecRequestType
        {
            _this = self,
            hubsToSearch = hubsToSearch,
            createSpec = createSpec,
        };

        var res = await this.inner.PbmQueryMatchingHubWithSpecAsync(req);

        return res.PbmQueryMatchingHubWithSpecResponse1;
    }

    public async System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryProfile(ManagedObjectReference self, PbmProfileResourceType resourceType, string? profileCategory)
    {
        var req = new PbmQueryProfileRequestType
        {
            _this = self,
            resourceType = resourceType,
            profileCategory = profileCategory,
        };

        var res = await this.inner.PbmQueryProfileAsync(req);

        return res.PbmQueryProfileResponse1;
    }

    public async System.Threading.Tasks.Task<PbmQueryReplicationGroupResult[]?> PbmQueryReplicationGroups(ManagedObjectReference self, PbmServerObjectRef[]? entities)
    {
        var req = new PbmQueryReplicationGroupsRequestType
        {
            _this = self,
            entities = entities,
        };

        var res = await this.inner.PbmQueryReplicationGroupsAsync(req);

        return res.PbmQueryReplicationGroupsResponse1;
    }

    public async System.Threading.Tasks.Task<PbmDatastoreSpaceStatistics[]?> PbmQuerySpaceStatsForStorageContainer(ManagedObjectReference self, PbmServerObjectRef datastore, PbmProfileId[]? capabilityProfileId)
    {
        var req = new PbmQuerySpaceStatsForStorageContainerRequestType
        {
            _this = self,
            datastore = datastore,
            capabilityProfileId = capabilityProfileId,
        };

        var res = await this.inner.PbmQuerySpaceStatsForStorageContainerAsync(req);

        return res.PbmQuerySpaceStatsForStorageContainerResponse1;
    }

    public async System.Threading.Tasks.Task PbmResetDefaultRequirementProfile(ManagedObjectReference self, PbmProfileId? profile)
    {
        var req = new PbmResetDefaultRequirementProfileRequestType
        {
            _this = self,
            profile = profile,
        };

        await this.inner.PbmResetDefaultRequirementProfileAsync(req);
    }

    public async System.Threading.Tasks.Task PbmResetVSanDefaultProfile(ManagedObjectReference self)
    {
        var req = new PbmResetVSanDefaultProfileRequestType
        {
            _this = self,
        };

        await this.inner.PbmResetVSanDefaultProfileAsync(req);
    }

    public async System.Threading.Tasks.Task<PbmProfile[]?> PbmRetrieveContent(ManagedObjectReference self, PbmProfileId[] profileIds)
    {
        var req = new PbmRetrieveContentRequestType
        {
            _this = self,
            profileIds = profileIds,
        };

        var res = await this.inner.PbmRetrieveContentAsync(req);

        return res.PbmRetrieveContentResponse1;
    }

    public async System.Threading.Tasks.Task<PbmServiceInstanceContent?> PbmRetrieveServiceContent(ManagedObjectReference self)
    {
        var req = new PbmRetrieveServiceContentRequestType
        {
            _this = self,
        };

        var res = await this.inner.PbmRetrieveServiceContentAsync(req);

        return res.PbmRetrieveServiceContentResponse.returnval;
    }

    public async System.Threading.Tasks.Task PbmUpdate(ManagedObjectReference self, PbmProfileId profileId, PbmCapabilityProfileUpdateSpec updateSpec)
    {
        var req = new PbmUpdateRequestType
        {
            _this = self,
            profileId = profileId,
            updateSpec = updateSpec,
        };

        await this.inner.PbmUpdateAsync(req);
    }

}

#pragma warning restore IDE0058 // Expression value is never used

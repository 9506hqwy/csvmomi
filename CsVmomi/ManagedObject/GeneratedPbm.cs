namespace CsVmomi;

using PbmService;

#pragma warning disable IDE0058 // Expression value is never used

public partial class PbmCapabilityMetadataManager : ManagedObject
{
    protected PbmCapabilityMetadataManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class PbmComplianceManager : ManagedObject
{
    protected PbmComplianceManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PbmComplianceResult[]?> PbmCheckCompliance(PbmServerObjectRef[] entities, PbmProfileId? profile)
    {
        return await this.Session.PbmClient!.PbmCheckCompliance(this.PbmReference, entities, profile).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmCheckRollupCompliance(PbmServerObjectRef[] entity)
    {
        return await this.Session.PbmClient!.PbmCheckRollupCompliance(this.PbmReference, entity).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmComplianceResult[]?> PbmFetchComplianceResult(PbmServerObjectRef[] entities, PbmProfileId? profile)
    {
        return await this.Session.PbmClient!.PbmFetchComplianceResult(this.PbmReference, entities, profile).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmFetchRollupComplianceResult(PbmServerObjectRef[] entity)
    {
        return await this.Session.PbmClient!.PbmFetchRollupComplianceResult(this.PbmReference, entity).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryByRollupComplianceStatus(string status)
    {
        return await this.Session.PbmClient!.PbmQueryByRollupComplianceStatus(this.PbmReference, status).ConfigureAwait(false);
    }
}

public partial class PbmPlacementSolver : ManagedObject
{
    protected PbmPlacementSolver(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckCompatibility(PbmPlacementHub[]? hubsToSearch, PbmProfileId profile)
    {
        return await this.Session.PbmClient!.PbmCheckCompatibility(this.PbmReference, hubsToSearch, profile).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckCompatibilityWithSpec(PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec profileSpec)
    {
        return await this.Session.PbmClient!.PbmCheckCompatibilityWithSpec(this.PbmReference, hubsToSearch, profileSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckRequirements(PbmPlacementHub[]? hubsToSearch, PbmServerObjectRef? placementSubjectRef, PbmPlacementRequirement[]? placementSubjectRequirement)
    {
        return await this.Session.PbmClient!.PbmCheckRequirements(this.PbmReference, hubsToSearch, placementSubjectRef, placementSubjectRequirement).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHub(PbmPlacementHub[]? hubsToSearch, PbmProfileId profile)
    {
        return await this.Session.PbmClient!.PbmQueryMatchingHub(this.PbmReference, hubsToSearch, profile).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHubWithSpec(PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec createSpec)
    {
        return await this.Session.PbmClient!.PbmQueryMatchingHubWithSpec(this.PbmReference, hubsToSearch, createSpec).ConfigureAwait(false);
    }
}

public partial class PbmProfileProfileManager : ManagedObject
{
    protected PbmProfileProfileManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task PbmAssignDefaultRequirementProfile(PbmProfileId profile, PbmPlacementHub[] datastores)
    {
        await this.Session.PbmClient!.PbmAssignDefaultRequirementProfile(this.PbmReference, profile, datastores).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfileId?> PbmCreate(PbmCapabilityProfileCreateSpec createSpec)
    {
        return await this.Session.PbmClient!.PbmCreate(this.PbmReference, createSpec).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfileOperationOutcome[]?> PbmDelete(PbmProfileId[] profileId)
    {
        return await this.Session.PbmClient!.PbmDelete(this.PbmReference, profileId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmCapabilityMetadataPerCategory[]?> PbmFetchCapabilityMetadata(PbmProfileResourceType? resourceType, string? vendorUuid)
    {
        return await this.Session.PbmClient!.PbmFetchCapabilityMetadata(this.PbmReference, resourceType, vendorUuid).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmCapabilitySchema[]?> PbmFetchCapabilitySchema(string? vendorUuid, string[]? lineOfService)
    {
        return await this.Session.PbmClient!.PbmFetchCapabilitySchema(this.PbmReference, vendorUuid, lineOfService).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfileResourceType[]?> PbmFetchResourceType()
    {
        return await this.Session.PbmClient!.PbmFetchResourceType(this.PbmReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmCapabilityVendorResourceTypeInfo[]?> PbmFetchVendorInfo(PbmProfileResourceType? resourceType)
    {
        return await this.Session.PbmClient!.PbmFetchVendorInfo(this.PbmReference, resourceType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfile[]?> PbmFindApplicableDefaultProfile(PbmPlacementHub[] datastores)
    {
        return await this.Session.PbmClient!.PbmFindApplicableDefaultProfile(this.PbmReference, datastores).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedEntities(PbmProfileId[]? profiles)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedEntities(this.PbmReference, profiles).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryAssociatedEntity(PbmProfileId profile, string? entityType)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedEntity(this.PbmReference, profile, entityType).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryAssociatedProfile(PbmServerObjectRef entity)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedProfile(this.PbmReference, entity).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedProfiles(PbmServerObjectRef[] entities)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedProfiles(this.PbmReference, entities).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfileId?> PbmQueryDefaultRequirementProfile(PbmPlacementHub hub)
    {
        return await this.Session.PbmClient!.PbmQueryDefaultRequirementProfile(this.PbmReference, hub).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmDefaultProfileInfo[]?> PbmQueryDefaultRequirementProfiles(PbmPlacementHub[] datastores)
    {
        return await this.Session.PbmClient!.PbmQueryDefaultRequirementProfiles(this.PbmReference, datastores).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryProfile(PbmProfileResourceType resourceType, string? profileCategory)
    {
        return await this.Session.PbmClient!.PbmQueryProfile(this.PbmReference, resourceType, profileCategory).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmDatastoreSpaceStatistics[]?> PbmQuerySpaceStatsForStorageContainer(PbmServerObjectRef datastore, PbmProfileId[]? capabilityProfileId)
    {
        return await this.Session.PbmClient!.PbmQuerySpaceStatsForStorageContainer(this.PbmReference, datastore, capabilityProfileId).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task PbmResetDefaultRequirementProfile(PbmProfileId? profile)
    {
        await this.Session.PbmClient!.PbmResetDefaultRequirementProfile(this.PbmReference, profile).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task PbmResetVSanDefaultProfile()
    {
        await this.Session.PbmClient!.PbmResetVSanDefaultProfile(this.PbmReference).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task<PbmProfile[]?> PbmRetrieveContent(PbmProfileId[] profileIds)
    {
        return await this.Session.PbmClient!.PbmRetrieveContent(this.PbmReference, profileIds).ConfigureAwait(false);
    }

    public async System.Threading.Tasks.Task PbmUpdate(PbmProfileId profileId, PbmCapabilityProfileUpdateSpec updateSpec)
    {
        await this.Session.PbmClient!.PbmUpdate(this.PbmReference, profileId, updateSpec).ConfigureAwait(false);
    }
}

public partial class PbmProvider : ManagedObject
{
    protected PbmProvider(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

public partial class PbmReplicationManager : ManagedObject
{
    protected PbmReplicationManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PbmQueryReplicationGroupResult[]?> PbmQueryReplicationGroups(PbmServerObjectRef[]? entities)
    {
        return await this.Session.PbmClient!.PbmQueryReplicationGroups(this.PbmReference, entities).ConfigureAwait(false);
    }
}

public partial class PbmServiceInstance : ManagedObject
{
    protected PbmServiceInstance(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }

    public async System.Threading.Tasks.Task<PbmServiceInstanceContent> GetPropertyContent()
    {
        var obj = await this.GetProperty<PbmServiceInstanceContent>("content").ConfigureAwait(false);
        return obj!;
    }

    public async System.Threading.Tasks.Task<PbmServiceInstanceContent?> PbmRetrieveServiceContent()
    {
        return await this.Session.PbmClient!.PbmRetrieveServiceContent(this.PbmReference).ConfigureAwait(false);
    }
}

public partial class PbmSessionManager : ManagedObject
{
    protected PbmSessionManager(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }
}

#pragma warning restore IDE0058 // Expression value is never used

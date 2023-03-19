namespace CsVmomi;

using PbmService;

#pragma warning disable SA1402 // File may only contain a single type

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
        return await this.Session.PbmClient!.PbmCheckCompliance(this.PbmReference, entities, profile);
    }

    public async System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmCheckRollupCompliance(PbmServerObjectRef[] entity)
    {
        return await this.Session.PbmClient!.PbmCheckRollupCompliance(this.PbmReference, entity);
    }

    public async System.Threading.Tasks.Task<PbmComplianceResult[]?> PbmFetchComplianceResult(PbmServerObjectRef[] entities, PbmProfileId? profile)
    {
        return await this.Session.PbmClient!.PbmFetchComplianceResult(this.PbmReference, entities, profile);
    }

    public async System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmFetchRollupComplianceResult(PbmServerObjectRef[] entity)
    {
        return await this.Session.PbmClient!.PbmFetchRollupComplianceResult(this.PbmReference, entity);
    }

    public async System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryByRollupComplianceStatus(string status)
    {
        return await this.Session.PbmClient!.PbmQueryByRollupComplianceStatus(this.PbmReference, status);
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
        return await this.Session.PbmClient!.PbmCheckCompatibility(this.PbmReference, hubsToSearch, profile);
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckCompatibilityWithSpec(PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec profileSpec)
    {
        return await this.Session.PbmClient!.PbmCheckCompatibilityWithSpec(this.PbmReference, hubsToSearch, profileSpec);
    }

    public async System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckRequirements(PbmPlacementHub[]? hubsToSearch, PbmServerObjectRef? placementSubjectRef, PbmPlacementRequirement[]? placementSubjectRequirement)
    {
        return await this.Session.PbmClient!.PbmCheckRequirements(this.PbmReference, hubsToSearch, placementSubjectRef, placementSubjectRequirement);
    }

    public async System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHub(PbmPlacementHub[]? hubsToSearch, PbmProfileId profile)
    {
        return await this.Session.PbmClient!.PbmQueryMatchingHub(this.PbmReference, hubsToSearch, profile);
    }

    public async System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHubWithSpec(PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec createSpec)
    {
        return await this.Session.PbmClient!.PbmQueryMatchingHubWithSpec(this.PbmReference, hubsToSearch, createSpec);
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
        await this.Session.PbmClient!.PbmAssignDefaultRequirementProfile(this.PbmReference, profile, datastores);
    }

    public async System.Threading.Tasks.Task<PbmProfileId?> PbmCreate(PbmCapabilityProfileCreateSpec createSpec)
    {
        return await this.Session.PbmClient!.PbmCreate(this.PbmReference, createSpec);
    }

    public async System.Threading.Tasks.Task<PbmProfileOperationOutcome[]?> PbmDelete(PbmProfileId[] profileId)
    {
        return await this.Session.PbmClient!.PbmDelete(this.PbmReference, profileId);
    }

    public async System.Threading.Tasks.Task<PbmCapabilityMetadataPerCategory[]?> PbmFetchCapabilityMetadata(PbmProfileResourceType? resourceType, string? vendorUuid)
    {
        return await this.Session.PbmClient!.PbmFetchCapabilityMetadata(this.PbmReference, resourceType, vendorUuid);
    }

    public async System.Threading.Tasks.Task<PbmCapabilitySchema[]?> PbmFetchCapabilitySchema(string? vendorUuid, string[]? lineOfService)
    {
        return await this.Session.PbmClient!.PbmFetchCapabilitySchema(this.PbmReference, vendorUuid, lineOfService);
    }

    public async System.Threading.Tasks.Task<PbmProfileResourceType[]?> PbmFetchResourceType()
    {
        return await this.Session.PbmClient!.PbmFetchResourceType(this.PbmReference);
    }

    public async System.Threading.Tasks.Task<PbmCapabilityVendorResourceTypeInfo[]?> PbmFetchVendorInfo(PbmProfileResourceType? resourceType)
    {
        return await this.Session.PbmClient!.PbmFetchVendorInfo(this.PbmReference, resourceType);
    }

    public async System.Threading.Tasks.Task<PbmProfile[]?> PbmFindApplicableDefaultProfile(PbmPlacementHub[] datastores)
    {
        return await this.Session.PbmClient!.PbmFindApplicableDefaultProfile(this.PbmReference, datastores);
    }

    public async System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedEntities(PbmProfileId[]? profiles)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedEntities(this.PbmReference, profiles);
    }

    public async System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryAssociatedEntity(PbmProfileId profile, string? entityType)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedEntity(this.PbmReference, profile, entityType);
    }

    public async System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryAssociatedProfile(PbmServerObjectRef entity)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedProfile(this.PbmReference, entity);
    }

    public async System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedProfiles(PbmServerObjectRef[] entities)
    {
        return await this.Session.PbmClient!.PbmQueryAssociatedProfiles(this.PbmReference, entities);
    }

    public async System.Threading.Tasks.Task<PbmProfileId?> PbmQueryDefaultRequirementProfile(PbmPlacementHub hub)
    {
        return await this.Session.PbmClient!.PbmQueryDefaultRequirementProfile(this.PbmReference, hub);
    }

    public async System.Threading.Tasks.Task<PbmDefaultProfileInfo[]?> PbmQueryDefaultRequirementProfiles(PbmPlacementHub[] datastores)
    {
        return await this.Session.PbmClient!.PbmQueryDefaultRequirementProfiles(this.PbmReference, datastores);
    }

    public async System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryProfile(PbmProfileResourceType resourceType, string? profileCategory)
    {
        return await this.Session.PbmClient!.PbmQueryProfile(this.PbmReference, resourceType, profileCategory);
    }

    public async System.Threading.Tasks.Task<PbmDatastoreSpaceStatistics[]?> PbmQuerySpaceStatsForStorageContainer(PbmServerObjectRef datastore, PbmProfileId[]? capabilityProfileId)
    {
        return await this.Session.PbmClient!.PbmQuerySpaceStatsForStorageContainer(this.PbmReference, datastore, capabilityProfileId);
    }

    public async System.Threading.Tasks.Task PbmResetDefaultRequirementProfile(PbmProfileId? profile)
    {
        await this.Session.PbmClient!.PbmResetDefaultRequirementProfile(this.PbmReference, profile);
    }

    public async System.Threading.Tasks.Task PbmResetVSanDefaultProfile()
    {
        await this.Session.PbmClient!.PbmResetVSanDefaultProfile(this.PbmReference);
    }

    public async System.Threading.Tasks.Task<PbmProfile[]?> PbmRetrieveContent(PbmProfileId[] profileIds)
    {
        return await this.Session.PbmClient!.PbmRetrieveContent(this.PbmReference, profileIds);
    }

    public async System.Threading.Tasks.Task PbmUpdate(PbmProfileId profileId, PbmCapabilityProfileUpdateSpec updateSpec)
    {
        await this.Session.PbmClient!.PbmUpdate(this.PbmReference, profileId, updateSpec);
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
        return await this.Session.PbmClient!.PbmQueryReplicationGroups(this.PbmReference, entities);
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
        var obj = await this.GetProperty<PbmServiceInstanceContent>("content");
        return obj!;
    }

    public async System.Threading.Tasks.Task<PbmServiceInstanceContent?> PbmRetrieveServiceContent()
    {
        return await this.Session.PbmClient!.PbmRetrieveServiceContent(this.PbmReference);
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

#pragma warning restore SA1402 // File may only contain a single type

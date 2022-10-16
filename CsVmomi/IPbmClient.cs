namespace CsVmomi;

using PbmService;

public interface IPbmClient
{
    public Uri Uri { get; }

    public string? GetCookie(string name);

    System.Net.CookieCollection? GetCookie();

    void SetCookie(System.Net.CookieCollection? cookie);

    System.Threading.Tasks.Task PbmAssignDefaultRequirementProfile(ManagedObjectReference self, PbmProfileId profile, PbmPlacementHub[] datastores);

    System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckCompatibility(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmProfileId profile);

    System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckCompatibilityWithSpec(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec profileSpec);

    System.Threading.Tasks.Task<PbmComplianceResult[]?> PbmCheckCompliance(ManagedObjectReference self, PbmServerObjectRef[] entities, PbmProfileId? profile);

    System.Threading.Tasks.Task<PbmPlacementCompatibilityResult[]?> PbmCheckRequirements(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmServerObjectRef? placementSubjectRef, PbmPlacementRequirement[]? placementSubjectRequirement);

    System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmCheckRollupCompliance(ManagedObjectReference self, PbmServerObjectRef[] entity);

    System.Threading.Tasks.Task<PbmProfileId?> PbmCreate(ManagedObjectReference self, PbmCapabilityProfileCreateSpec createSpec);

    System.Threading.Tasks.Task<PbmProfileOperationOutcome[]?> PbmDelete(ManagedObjectReference self, PbmProfileId[] profileId);

    System.Threading.Tasks.Task<PbmCapabilityMetadataPerCategory[]?> PbmFetchCapabilityMetadata(ManagedObjectReference self, PbmProfileResourceType? resourceType, string? vendorUuid);

    System.Threading.Tasks.Task<PbmCapabilitySchema[]?> PbmFetchCapabilitySchema(ManagedObjectReference self, string? vendorUuid, string[]? lineOfService);

    System.Threading.Tasks.Task<PbmComplianceResult[]?> PbmFetchComplianceResult(ManagedObjectReference self, PbmServerObjectRef[] entities, PbmProfileId? profile);

    System.Threading.Tasks.Task<PbmProfileResourceType[]?> PbmFetchResourceType(ManagedObjectReference self);

    System.Threading.Tasks.Task<PbmRollupComplianceResult[]?> PbmFetchRollupComplianceResult(ManagedObjectReference self, PbmServerObjectRef[] entity);

    System.Threading.Tasks.Task<PbmCapabilityVendorResourceTypeInfo[]?> PbmFetchVendorInfo(ManagedObjectReference self, PbmProfileResourceType? resourceType);

    System.Threading.Tasks.Task<PbmProfile[]?> PbmFindApplicableDefaultProfile(ManagedObjectReference self, PbmPlacementHub[] datastores);

    System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedEntities(ManagedObjectReference self, PbmProfileId[]? profiles);

    System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryAssociatedEntity(ManagedObjectReference self, PbmProfileId profile, string? entityType);

    System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryAssociatedProfile(ManagedObjectReference self, PbmServerObjectRef entity);

    System.Threading.Tasks.Task<PbmQueryProfileResult[]?> PbmQueryAssociatedProfiles(ManagedObjectReference self, PbmServerObjectRef[] entities);

    System.Threading.Tasks.Task<PbmServerObjectRef[]?> PbmQueryByRollupComplianceStatus(ManagedObjectReference self, string status);

    System.Threading.Tasks.Task<PbmProfileId?> PbmQueryDefaultRequirementProfile(ManagedObjectReference self, PbmPlacementHub hub);

    System.Threading.Tasks.Task<PbmDefaultProfileInfo[]?> PbmQueryDefaultRequirementProfiles(ManagedObjectReference self, PbmPlacementHub[] datastores);

    System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHub(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmProfileId profile);

    System.Threading.Tasks.Task<PbmPlacementHub[]?> PbmQueryMatchingHubWithSpec(ManagedObjectReference self, PbmPlacementHub[]? hubsToSearch, PbmCapabilityProfileCreateSpec createSpec);

    System.Threading.Tasks.Task<PbmProfileId[]?> PbmQueryProfile(ManagedObjectReference self, PbmProfileResourceType resourceType, string? profileCategory);

    System.Threading.Tasks.Task<PbmQueryReplicationGroupResult[]?> PbmQueryReplicationGroups(ManagedObjectReference self, PbmServerObjectRef[]? entities);

    System.Threading.Tasks.Task<PbmDatastoreSpaceStatistics[]?> PbmQuerySpaceStatsForStorageContainer(ManagedObjectReference self, PbmServerObjectRef datastore, PbmProfileId[]? capabilityProfileId);

    System.Threading.Tasks.Task PbmResetDefaultRequirementProfile(ManagedObjectReference self, PbmProfileId? profile);

    System.Threading.Tasks.Task PbmResetVSanDefaultProfile(ManagedObjectReference self);

    System.Threading.Tasks.Task<PbmProfile[]?> PbmRetrieveContent(ManagedObjectReference self, PbmProfileId[] profileIds);

    System.Threading.Tasks.Task<PbmServiceInstanceContent?> PbmRetrieveServiceContent(ManagedObjectReference self);

    System.Threading.Tasks.Task PbmUpdate(ManagedObjectReference self, PbmProfileId profileId, PbmCapabilityProfileUpdateSpec updateSpec);
}

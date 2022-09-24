namespace CsVmomi
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceModel;
    using System.ServiceModel.Security;
    using System.Text;
    using VimService;

    public class Session
    {
        private Session(IClient client, ServiceContent serviceContent)
        {
            this.Client = client;
            this.ServiceContent = serviceContent;
        }

        public AboutInfo About => this.ServiceContent.about;

        public HostLocalAccountManager AccountManager => ManagedObject.Create<HostLocalAccountManager>(this.ServiceContent.accountManager, this);

        public AlarmManager AlarmManager => ManagedObject.Create<AlarmManager>(this.ServiceContent.alarmManager, this);

        public AuthorizationManager AuthorizationManager => ManagedObject.Create<AuthorizationManager>(this.ServiceContent.authorizationManager, this);

        public CertificateManager CertificateManager => ManagedObject.Create<CertificateManager>(this.ServiceContent.certificateManager, this);

        public ClusterProfileManager ClusterProfileManager => ManagedObject.Create<ClusterProfileManager>(this.ServiceContent.clusterProfileManager, this);

        public ProfileComplianceManager ComplianceManager => ManagedObject.Create<ProfileComplianceManager>(this.ServiceContent.complianceManager, this);

        public CryptoManager CryptoManager => ManagedObject.Create<CryptoManager>(this.ServiceContent.cryptoManager, this);

        public CustomFieldsManager CustomFieldsManager => ManagedObject.Create<CustomFieldsManager>(this.ServiceContent.customFieldsManager, this);

        public CustomizationSpecManager CustomizationSpecManager => ManagedObject.Create<CustomizationSpecManager>(this.ServiceContent.customizationSpecManager, this);

        public DatastoreNamespaceManager DatastoreNamespaceManager => ManagedObject.Create<DatastoreNamespaceManager>(this.ServiceContent.datastoreNamespaceManager, this);

        public DiagnosticManager DiagnosticManager => ManagedObject.Create<DiagnosticManager>(this.ServiceContent.diagnosticManager, this);

        public DistributedVirtualSwitchManager DvSwitchManager => ManagedObject.Create<DistributedVirtualSwitchManager>(this.ServiceContent.dvSwitchManager, this);

        public EventManager EventManager => ManagedObject.Create<EventManager>(this.ServiceContent.eventManager, this);

        public ExtensionManager ExtensionManager => ManagedObject.Create<ExtensionManager>(this.ServiceContent.extensionManager, this);

        public FailoverClusterConfigurator FailoverClusterConfigurator => ManagedObject.Create<FailoverClusterConfigurator>(this.ServiceContent.failoverClusterConfigurator, this);

        public FailoverClusterManager FailoverClusterManager => ManagedObject.Create<FailoverClusterManager>(this.ServiceContent.failoverClusterManager, this);

        public FileManager FileManager => ManagedObject.Create<FileManager>(this.ServiceContent.fileManager, this);

        public VirtualMachineGuestCustomizationManager GuestCustomizationManager => ManagedObject.Create<VirtualMachineGuestCustomizationManager>(this.ServiceContent.guestCustomizationManager, this);

        public GuestOperationsManager GuestOperationsManager => ManagedObject.Create<GuestOperationsManager>(this.ServiceContent.guestOperationsManager, this);

        public HealthUpdateManager HealthUpdateManager => ManagedObject.Create<HealthUpdateManager>(this.ServiceContent.healthUpdateManager, this);

        public HostProfileManager HostProfileManager => ManagedObject.Create<HostProfileManager>(this.ServiceContent.hostProfileManager, this);

        public HostSpecificationManager HostSpecManager => ManagedObject.Create<HostSpecificationManager>(this.ServiceContent.hostSpecManager, this);

        public IoFilterManager IoFilterManager => ManagedObject.Create<IoFilterManager>(this.ServiceContent.ioFilterManager, this);

        public IpPoolManager IpPoolManager => ManagedObject.Create<IpPoolManager>(this.ServiceContent.ipPoolManager, this);

        public LicenseManager LicenseManager => ManagedObject.Create<LicenseManager>(this.ServiceContent.licenseManager, this);

        public LocalizationManager LocalizationManager => ManagedObject.Create<LocalizationManager>(this.ServiceContent.localizationManager, this);

        public OverheadMemoryManager OverheadMemoryManager => ManagedObject.Create<OverheadMemoryManager>(this.ServiceContent.overheadMemoryManager, this);

        public OvfManager OvfManager => ManagedObject.Create<OvfManager>(this.ServiceContent.ovfManager, this);

        public PerformanceManager PerfManager => ManagedObject.Create<PerformanceManager>(this.ServiceContent.perfManager, this);

        public PropertyCollector PropertyCollector => ManagedObject.Create<PropertyCollector>(this.ServiceContent.propertyCollector, this);

        public Folder RootFolder => ManagedObject.Create<Folder>(this.ServiceContent.rootFolder, this);

        public ScheduledTaskManager ScheduledTaskManager => ManagedObject.Create<ScheduledTaskManager>(this.ServiceContent.scheduledTaskManager, this);

        public SearchIndex SearchIndex => ManagedObject.Create<SearchIndex>(this.ServiceContent.searchIndex, this);

        public ServiceManager ServiceManager => ManagedObject.Create<ServiceManager>(this.ServiceContent.serviceManager, this);

        public SessionManager SessionManager => ManagedObject.Create<SessionManager>(this.ServiceContent.sessionManager, this);

        public OptionManager Setting => ManagedObject.Create<OptionManager>(this.ServiceContent.setting, this);

        public SiteInfoManager SiteInfoManager => ManagedObject.Create<SiteInfoManager>(this.ServiceContent.siteInfoManager, this);

        public HostSnmpSystem SnmpSystem => ManagedObject.Create<HostSnmpSystem>(this.ServiceContent.snmpSystem, this);

        public StorageQueryManager StorageQueryManager => ManagedObject.Create<StorageQueryManager>(this.ServiceContent.storageQueryManager, this);

        public StorageResourceManager StorageResourceManager => ManagedObject.Create<StorageResourceManager>(this.ServiceContent.storageResourceManager, this);

        public TaskManager TaskManager => ManagedObject.Create<TaskManager>(this.ServiceContent.taskManager, this);

        public TenantTenantManager TenantManager => ManagedObject.Create<TenantTenantManager>(this.ServiceContent.tenantManager, this);

        public UserDirectory UserDirectory => ManagedObject.Create<UserDirectory>(this.ServiceContent.userDirectory, this);

        public ViewManager ViewManager => ManagedObject.Create<ViewManager>(this.ServiceContent.viewManager, this);

        public VirtualDiskManager VirtualDiskManager => ManagedObject.Create<VirtualDiskManager>(this.ServiceContent.virtualDiskManager, this);

        public VirtualizationManager VirtualizationManager => ManagedObject.Create<VirtualizationManager>(this.ServiceContent.virtualizationManager, this);

        public VirtualMachineCompatibilityChecker VmCompatibilityChecker => ManagedObject.Create<VirtualMachineCompatibilityChecker>(this.ServiceContent.vmCompatibilityChecker, this);

        public VirtualMachineProvisioningChecker VmProvisioningChecker => ManagedObject.Create<VirtualMachineProvisioningChecker>(this.ServiceContent.vmProvisioningChecker, this);

        public VStorageObjectManagerBase VStorageObjectManager => ManagedObject.Create<VStorageObjectManagerBase>(this.ServiceContent.vStorageObjectManager, this);

        internal IClient Client { get; }

        internal ServiceContent ServiceContent { get; }

        public static async System.Threading.Tasks.Task<Session> Get(Uri url)
        {
            var binding = Session.GetBinding();

            var endpoint = new EndpointAddress(url);

            var inner = new VimPortTypeClient(binding, endpoint);
            inner.ChannelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication
            {
                CertificateValidationMode = X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck,
            };

            return await Session.Get(inner);
        }

        public static async System.Threading.Tasks.Task<Session> Get(VimPortTypeClient inner)
        {
            var client = new Client(inner);

            var mor = new ManagedObjectReference
            {
                type = "ServiceInstance",
                Value = "ServiceInstance",
            };
            var serviceContent = await client.RetrieveServiceContent(mor);

            return new Session(client, serviceContent);
        }

        private static BasicHttpBinding GetBinding()
        {
            return new BasicHttpBinding
            {
                AllowCookies = true,
                BypassProxyOnLocal = true,
                MaxBufferPoolSize = int.MaxValue,
                MaxBufferSize = int.MaxValue,
                MaxReceivedMessageSize = int.MaxValue,
                MessageEncoding = WSMessageEncoding.Text,
                Security = new BasicHttpSecurity
                {
                    Mode = BasicHttpSecurityMode.Transport,
                    Transport = new HttpTransportSecurity
                    {
                        ClientCredentialType = HttpClientCredentialType.None,
                        ProxyCredentialType = HttpProxyCredentialType.None,
                    },
                },
                TextEncoding = Encoding.UTF8,
                TransferMode = TransferMode.Buffered,
                UseDefaultWebProxy = false,

                // タイムアウト
                OpenTimeout = TimeSpan.FromSeconds(300),
                SendTimeout = TimeSpan.FromSeconds(300),
                ReceiveTimeout = TimeSpan.FromSeconds(1800),
                CloseTimeout = TimeSpan.FromSeconds(300),
            };
        }
    }
}

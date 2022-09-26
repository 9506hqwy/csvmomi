namespace CsVmomi
{
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceModel;
    using System.ServiceModel.Security;
    using System.Text;
    using VimService;

    public class Session
    {
        private readonly ServiceContent serviceContent;

        private Session(IClient client, ServiceContent serviceContent)
        {
            this.Client = client;
            this.serviceContent = serviceContent;
        }

        public AboutInfo About => this.serviceContent.about;

        public HostLocalAccountManager AccountManager => ManagedObject.Create<HostLocalAccountManager>(this.serviceContent.accountManager, this);

        public AlarmManager AlarmManager => ManagedObject.Create<AlarmManager>(this.serviceContent.alarmManager, this);

        public AuthorizationManager AuthorizationManager => ManagedObject.Create<AuthorizationManager>(this.serviceContent.authorizationManager, this);

        public CertificateManager CertificateManager => ManagedObject.Create<CertificateManager>(this.serviceContent.certificateManager, this);

        public ClusterProfileManager ClusterProfileManager => ManagedObject.Create<ClusterProfileManager>(this.serviceContent.clusterProfileManager, this);

        public ProfileComplianceManager ComplianceManager => ManagedObject.Create<ProfileComplianceManager>(this.serviceContent.complianceManager, this);

        public CryptoManager CryptoManager => ManagedObject.Create<CryptoManager>(this.serviceContent.cryptoManager, this);

        public CustomFieldsManager CustomFieldsManager => ManagedObject.Create<CustomFieldsManager>(this.serviceContent.customFieldsManager, this);

        public CustomizationSpecManager CustomizationSpecManager => ManagedObject.Create<CustomizationSpecManager>(this.serviceContent.customizationSpecManager, this);

        public DatastoreNamespaceManager DatastoreNamespaceManager => ManagedObject.Create<DatastoreNamespaceManager>(this.serviceContent.datastoreNamespaceManager, this);

        public DiagnosticManager DiagnosticManager => ManagedObject.Create<DiagnosticManager>(this.serviceContent.diagnosticManager, this);

        public DistributedVirtualSwitchManager DvSwitchManager => ManagedObject.Create<DistributedVirtualSwitchManager>(this.serviceContent.dvSwitchManager, this);

        public EventManager EventManager => ManagedObject.Create<EventManager>(this.serviceContent.eventManager, this);

        public ExtensionManager ExtensionManager => ManagedObject.Create<ExtensionManager>(this.serviceContent.extensionManager, this);

        public FailoverClusterConfigurator FailoverClusterConfigurator => ManagedObject.Create<FailoverClusterConfigurator>(this.serviceContent.failoverClusterConfigurator, this);

        public FailoverClusterManager FailoverClusterManager => ManagedObject.Create<FailoverClusterManager>(this.serviceContent.failoverClusterManager, this);

        public FileManager FileManager => ManagedObject.Create<FileManager>(this.serviceContent.fileManager, this);

        public VirtualMachineGuestCustomizationManager GuestCustomizationManager => ManagedObject.Create<VirtualMachineGuestCustomizationManager>(this.serviceContent.guestCustomizationManager, this);

        public GuestOperationsManager GuestOperationsManager => ManagedObject.Create<GuestOperationsManager>(this.serviceContent.guestOperationsManager, this);

        public HealthUpdateManager HealthUpdateManager => ManagedObject.Create<HealthUpdateManager>(this.serviceContent.healthUpdateManager, this);

        public HostProfileManager HostProfileManager => ManagedObject.Create<HostProfileManager>(this.serviceContent.hostProfileManager, this);

        public HostSpecificationManager HostSpecManager => ManagedObject.Create<HostSpecificationManager>(this.serviceContent.hostSpecManager, this);

        public IoFilterManager IoFilterManager => ManagedObject.Create<IoFilterManager>(this.serviceContent.ioFilterManager, this);

        public IpPoolManager IpPoolManager => ManagedObject.Create<IpPoolManager>(this.serviceContent.ipPoolManager, this);

        public LicenseManager LicenseManager => ManagedObject.Create<LicenseManager>(this.serviceContent.licenseManager, this);

        public LocalizationManager LocalizationManager => ManagedObject.Create<LocalizationManager>(this.serviceContent.localizationManager, this);

        public OverheadMemoryManager OverheadMemoryManager => ManagedObject.Create<OverheadMemoryManager>(this.serviceContent.overheadMemoryManager, this);

        public OvfManager OvfManager => ManagedObject.Create<OvfManager>(this.serviceContent.ovfManager, this);

        public PerformanceManager PerfManager => ManagedObject.Create<PerformanceManager>(this.serviceContent.perfManager, this);

        public PropertyCollector PropertyCollector => ManagedObject.Create<PropertyCollector>(this.serviceContent.propertyCollector, this);

        public Folder RootFolder => ManagedObject.Create<Folder>(this.serviceContent.rootFolder, this);

        public ScheduledTaskManager ScheduledTaskManager => ManagedObject.Create<ScheduledTaskManager>(this.serviceContent.scheduledTaskManager, this);

        public SearchIndex SearchIndex => ManagedObject.Create<SearchIndex>(this.serviceContent.searchIndex, this);

        public ServiceManager ServiceManager => ManagedObject.Create<ServiceManager>(this.serviceContent.serviceManager, this);

        public SessionManager SessionManager => ManagedObject.Create<SessionManager>(this.serviceContent.sessionManager, this);

        public OptionManager Setting => ManagedObject.Create<OptionManager>(this.serviceContent.setting, this);

        public SiteInfoManager SiteInfoManager => ManagedObject.Create<SiteInfoManager>(this.serviceContent.siteInfoManager, this);

        public HostSnmpSystem SnmpSystem => ManagedObject.Create<HostSnmpSystem>(this.serviceContent.snmpSystem, this);

        public StorageQueryManager StorageQueryManager => ManagedObject.Create<StorageQueryManager>(this.serviceContent.storageQueryManager, this);

        public StorageResourceManager StorageResourceManager => ManagedObject.Create<StorageResourceManager>(this.serviceContent.storageResourceManager, this);

        public TaskManager TaskManager => ManagedObject.Create<TaskManager>(this.serviceContent.taskManager, this);

        public TenantTenantManager TenantManager => ManagedObject.Create<TenantTenantManager>(this.serviceContent.tenantManager, this);

        public UserDirectory UserDirectory => ManagedObject.Create<UserDirectory>(this.serviceContent.userDirectory, this);

        public ViewManager ViewManager => ManagedObject.Create<ViewManager>(this.serviceContent.viewManager, this);

        public VirtualDiskManager VirtualDiskManager => ManagedObject.Create<VirtualDiskManager>(this.serviceContent.virtualDiskManager, this);

        public VirtualizationManager VirtualizationManager => ManagedObject.Create<VirtualizationManager>(this.serviceContent.virtualizationManager, this);

        public VirtualMachineCompatibilityChecker VmCompatibilityChecker => ManagedObject.Create<VirtualMachineCompatibilityChecker>(this.serviceContent.vmCompatibilityChecker, this);

        public VirtualMachineProvisioningChecker VmProvisioningChecker => ManagedObject.Create<VirtualMachineProvisioningChecker>(this.serviceContent.vmProvisioningChecker, this);

        public VStorageObjectManagerBase VStorageObjectManager => ManagedObject.Create<VStorageObjectManagerBase>(this.serviceContent.vStorageObjectManager, this);

        internal IClient Client { get; }

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
            return await Session.Get(new Client(inner));
        }

        public static async System.Threading.Tasks.Task<Session> Get(IClient client)
        {
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

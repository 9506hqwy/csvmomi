namespace CsVmomi
{
    using System.Linq;
    using System.Threading.Tasks;
    using VimService;

    public partial class PropertyCollector : ManagedObject
    {
        public async Task<T> RetrieveProperties<T>(
            ManagedObject obj,
            string pathSet)
        {
            var content = await this.RetrieveProperties(obj, false, new[] { pathSet }, false);

            var prop = content.propSet.FirstOrDefault(p => p.name == pathSet);

            return (T)prop.val;
        }

        public async Task<ObjectContent> RetrieveProperties(
            ManagedObject obj,
            bool all,
            string[] pathSet,
            bool reportMissingObjectsInResults)
        {
            var objectSet = new ObjectSpec
            {
                obj = obj.Reference,
                selectSet = null,
                skip = false,
                skipSpecified = true,
            };

            var propSet = new PropertySpec
            {
                all = all,
                allSpecified = true,
                pathSet = pathSet,
                type = obj.Reference.type,
            };

            return await this.RetrieveProperties(objectSet, propSet, reportMissingObjectsInResults);
        }

        public async Task<ObjectContent> RetrieveProperties(
            ObjectSpec objectSet,
            PropertySpec propSet,
            bool reportMissingObjectsInResults)
        {
            var specSet = new PropertyFilterSpec
            {
                objectSet = new[] { objectSet },
                propSet = new[] { propSet },
                reportMissingObjectsInResults = reportMissingObjectsInResults,
                reportMissingObjectsInResultsSpecified = true,
            };

            var contents = await this.RetrieveProperties(specSet);

            return contents.First();
        }

        public async Task<ObjectContent[]> RetrieveProperties(PropertyFilterSpec specSet)
        {
            return await this.RetrieveProperties(new[] { specSet });
        }
    }
}

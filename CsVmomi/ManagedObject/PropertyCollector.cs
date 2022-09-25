namespace CsVmomi
{
    using System.Linq;
    using System.Threading.Tasks;
    using VimService;

    public partial class PropertyCollector : ManagedObject
    {
        public async Task<PropertyFilter> CreateFilter(
            ManagedObject obj,
            string pathSet,
            bool partialUpdates)
        {
            var specSet = this.CreatePropertyFilterSpec(obj, pathSet);
            return await this.CreateFilter(specSet, partialUpdates);
        }

        public async Task<PropertyFilter> CreateFilter(
            ManagedObject obj,
            bool all,
            string[] pathSet,
            bool reportMissingObjectsInResults,
            bool partialUpdates)
        {
            var specSet = this.CreatePropertyFilterSpec(obj, all, pathSet, reportMissingObjectsInResults);
            return await this.CreateFilter(specSet, partialUpdates);
        }

        public async Task<PropertyFilter> CreateFilter(
            ObjectSpec objectSet,
            PropertySpec propSet,
            bool reportMissingObjectsInResults,
            bool partialUpdates)
        {
            var specSet = this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
            return await this.CreateFilter(specSet, partialUpdates);
        }

        public async Task<T> RetrieveProperties<T>(
            ManagedObject obj,
            string pathSet)
        {
            var specSet = this.CreatePropertyFilterSpec(obj, pathSet);
            var contents = await this.RetrieveProperties(specSet);
            return contents.First().GetPropertyValue<T>(pathSet);
        }

        public async Task<ObjectContent> RetrieveProperties(
            ManagedObject obj,
            bool all,
            string[] pathSet,
            bool reportMissingObjectsInResults)
        {
            var specSet = this.CreatePropertyFilterSpec(obj, all, pathSet, reportMissingObjectsInResults);
            var contents = await this.RetrieveProperties(specSet);
            return contents.First();
        }

        public async Task<ObjectContent> RetrieveProperties(
            ObjectSpec objectSet,
            PropertySpec propSet,
            bool reportMissingObjectsInResults)
        {
            var specSet = this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
            var contents = await this.RetrieveProperties(specSet);
            return contents.First();
        }

        public async Task<ObjectContent[]> RetrieveProperties(PropertyFilterSpec specSet)
        {
            return await this.RetrieveProperties(new[] { specSet });
        }

        private PropertyFilterSpec CreatePropertyFilterSpec(
            ManagedObject obj,
            string pathSet)
        {
            return this.CreatePropertyFilterSpec(obj, false, new[] { pathSet }, false);
        }

        private PropertyFilterSpec CreatePropertyFilterSpec(
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

            return this.CreatePropertyFilterSpec(objectSet, propSet, reportMissingObjectsInResults);
        }

        private PropertyFilterSpec CreatePropertyFilterSpec(
            ObjectSpec objectSet,
            PropertySpec propSet,
            bool reportMissingObjectsInResults)
        {
            return new PropertyFilterSpec
            {
                objectSet = new[] { objectSet },
                propSet = new[] { propSet },
                reportMissingObjectsInResults = reportMissingObjectsInResults,
                reportMissingObjectsInResultsSpecified = true,
            };
        }
    }
}

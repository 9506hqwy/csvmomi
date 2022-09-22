namespace CsVmomi
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using System.Threading.Tasks;
    using VimService;

    public abstract class ManagedObject
    {
        private static readonly IReadOnlyDictionary<string, Type> ManagedObjectTypes;

        static ManagedObject()
        {
            ManagedObject.ManagedObjectTypes = typeof(ManagedObject).Assembly
                .GetTypes()
                .Where(t => typeof(ManagedObject).IsAssignableFrom(t))
                .ToDictionary(t => t.Name, t => t);
        }

        protected ManagedObject(
            ManagedObjectReference reference,
            Session session)
        {
            this.Reference = reference;
            this.Session = session;
        }

        public ManagedObjectReference Reference { get; }

        protected Session Session { get; }

        public static T Create<T>(
            ManagedObjectReference reference,
            Session session)
            where T : ManagedObject
        {
            if (reference == null)
            {
                return null;
            }

            if (ManagedObject.ManagedObjectTypes.TryGetValue(reference.type, out Type type) &&
                typeof(T).IsAssignableFrom(type))
            {
                return (T)Activator.CreateInstance(
                    type,
                    BindingFlags.Instance | BindingFlags.NonPublic,
                    null,
                    new object[] { reference, session },
                    null);
            }

            throw new NotSupportedException();
        }

        protected async Task<T> GetProperty<T>(string pathSet)
        {
            return await this.Session.PropertyCollector.RetrieveProperties<T>(this, pathSet);
        }
    }
}

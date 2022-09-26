namespace CsVmomi;

using System.Reflection;

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

    public static T? Create<T>(
        ManagedObjectReference? reference,
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

    public async Task<T?> GetProperty<T>(string pathSet)
    {
        return await this.Session.PropertyCollector.RetrieveProperties<T>(this, pathSet);
    }

    public async Task<Tuple<T1?, T2?>> GetProperty<T1, T2>(
        string pathSet1,
        string pathSet2)
    {
        var pathSet = new[] { pathSet1, pathSet2 };
        var content = await this.Session.PropertyCollector.RetrieveProperties(this, false, pathSet, false);
        var obj1 = content.GetPropertyValue<T1>(pathSet1);
        var obj2 = content.GetPropertyValue<T2>(pathSet2);
        return Tuple.Create(obj1, obj2);
    }

    public async Task<Tuple<T1?, T2?, T3?>> GetProperty<T1, T2, T3>(
        string pathSet1,
        string pathSet2,
        string pathSet3)
    {
        var pathSet = new[] { pathSet1, pathSet2, pathSet3 };
        var content = await this.Session.PropertyCollector.RetrieveProperties(this, false, pathSet, false);
        var obj1 = content.GetPropertyValue<T1>(pathSet1);
        var obj2 = content.GetPropertyValue<T2>(pathSet2);
        var obj3 = content.GetPropertyValue<T3>(pathSet3);
        return Tuple.Create(obj1, obj2, obj3);
    }

    public async Task<Tuple<T1?, T2?, T3?, T4?>> GetProperty<T1, T2, T3, T4>(
        string pathSet1,
        string pathSet2,
        string pathSet3,
        string pathSet4)
    {
        var pathSet = new[] { pathSet1, pathSet2, pathSet3, pathSet4 };
        var content = await this.Session.PropertyCollector.RetrieveProperties(this, false, pathSet, false);
        var obj1 = content.GetPropertyValue<T1>(pathSet1);
        var obj2 = content.GetPropertyValue<T2>(pathSet2);
        var obj3 = content.GetPropertyValue<T3>(pathSet3);
        var obj4 = content.GetPropertyValue<T4>(pathSet4);
        return Tuple.Create(obj1, obj2, obj3, obj4);
    }

    public async Task<Tuple<T1?, T2?, T3?, T4?, T5?>> GetProperty<T1, T2, T3, T4, T5>(
        string pathSet1,
        string pathSet2,
        string pathSet3,
        string pathSet4,
        string pathSet5)
    {
        var pathSet = new[] { pathSet1, pathSet2, pathSet3, pathSet4, pathSet5 };
        var content = await this.Session.PropertyCollector.RetrieveProperties(this, false, pathSet, false);
        var obj1 = content.GetPropertyValue<T1>(pathSet1);
        var obj2 = content.GetPropertyValue<T2>(pathSet2);
        var obj3 = content.GetPropertyValue<T3>(pathSet3);
        var obj4 = content.GetPropertyValue<T4>(pathSet4);
        var obj5 = content.GetPropertyValue<T5>(pathSet5);
        return Tuple.Create(obj1, obj2, obj3, obj4, obj5);
    }

    public async Task<Tuple<T1?, T2?, T3?, T4?, T5?, T6?>> GetProperty<T1, T2, T3, T4, T5, T6>(
        string pathSet1,
        string pathSet2,
        string pathSet3,
        string pathSet4,
        string pathSet5,
        string pathSet6)
    {
        var pathSet = new[] { pathSet1, pathSet2, pathSet3, pathSet4, pathSet5, pathSet6 };
        var content = await this.Session.PropertyCollector.RetrieveProperties(this, false, pathSet, false);
        var obj1 = content.GetPropertyValue<T1>(pathSet1);
        var obj2 = content.GetPropertyValue<T2>(pathSet2);
        var obj3 = content.GetPropertyValue<T3>(pathSet3);
        var obj4 = content.GetPropertyValue<T4>(pathSet4);
        var obj5 = content.GetPropertyValue<T5>(pathSet5);
        var obj6 = content.GetPropertyValue<T6>(pathSet6);
        return Tuple.Create(obj1, obj2, obj3, obj4, obj5, obj6);
    }

    public async Task<Tuple<T1?, T2?, T3?, T4?, T5?, T6?, T7?>> GetProperty<T1, T2, T3, T4, T5, T6, T7>(
        string pathSet1,
        string pathSet2,
        string pathSet3,
        string pathSet4,
        string pathSet5,
        string pathSet6,
        string pathSet7)
    {
        var pathSet = new[] { pathSet1, pathSet2, pathSet3, pathSet4, pathSet5, pathSet6, pathSet7 };
        var content = await this.Session.PropertyCollector.RetrieveProperties(this, false, pathSet, false);
        var obj1 = content.GetPropertyValue<T1>(pathSet1);
        var obj2 = content.GetPropertyValue<T2>(pathSet2);
        var obj3 = content.GetPropertyValue<T3>(pathSet3);
        var obj4 = content.GetPropertyValue<T4>(pathSet4);
        var obj5 = content.GetPropertyValue<T5>(pathSet5);
        var obj6 = content.GetPropertyValue<T6>(pathSet6);
        var obj7 = content.GetPropertyValue<T7>(pathSet7);
        return Tuple.Create(obj1, obj2, obj3, obj4, obj5, obj6, obj7);
    }
}

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
        this.EamReference = new EamService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.PbmReference = new PbmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.SmsReference = new SmsService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VimReference = reference;
        this.VslmReference = new VslmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.Session = session;
    }

    protected ManagedObject(
        EamService.ManagedObjectReference reference,
        Session session)
    {
        this.EamReference = reference;
        this.PbmReference = new PbmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.SmsReference = new SmsService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VimReference = new ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VslmReference = new VslmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.Session = session;
    }

    protected ManagedObject(
        PbmService.ManagedObjectReference reference,
        Session session)
    {
        this.EamReference = new EamService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.PbmReference = reference;
        this.SmsReference = new SmsService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VimReference = new ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VslmReference = new VslmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.Session = session;
    }

    protected ManagedObject(
        SmsService.ManagedObjectReference reference,
        Session session)
    {
        this.EamReference = new EamService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.PbmReference = new PbmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.SmsReference = reference;
        this.VimReference = new ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VslmReference = new VslmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.Session = session;
    }

    protected ManagedObject(
        VslmService.ManagedObjectReference reference,
        Session session)
    {
        this.EamReference = new EamService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.PbmReference = new PbmService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.SmsReference = new SmsService.ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VimReference = new ManagedObjectReference
        {
            type = reference.type,
            Value = reference.Value,
        };
        this.VslmReference = reference;
        this.Session = session;
    }

    public EamService.ManagedObjectReference EamReference { get; }

    public PbmService.ManagedObjectReference PbmReference { get; }

    public SmsService.ManagedObjectReference SmsReference { get; }

    public ManagedObjectReference VimReference { get; }

    public VslmService.ManagedObjectReference VslmReference { get; }

    protected Session Session { get; }

    public static T? Create<T>(
        ManagedObjectReference? reference,
        Session session)
        where T : ManagedObject
    {
        return ManagedObject.Create<T>(reference, reference?.type, session);
    }

    public static T? Create<T>(
        EamService.ManagedObjectReference? reference,
        Session session)
        where T : ManagedObject
    {
        return ManagedObject.Create<T>(reference, reference?.type, session);
    }

    public static T? Create<T>(
        PbmService.ManagedObjectReference? reference,
        Session session)
        where T : ManagedObject
    {
        return ManagedObject.Create<T>(reference, reference?.type, session);
    }

    public static T? Create<T>(
        SmsService.ManagedObjectReference? reference,
        Session session)
        where T : ManagedObject
    {
        return ManagedObject.Create<T>(reference, reference?.type, session);
    }

    public static T? Create<T>(
        VslmService.ManagedObjectReference? reference,
        Session session)
        where T : ManagedObject
    {
        return ManagedObject.Create<T>(reference, reference?.type, session);
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

    private static T? Create<T>(object? reference, string? objType, Session session)
        where T : ManagedObject
    {
        return reference == null || objType == null
            ? null
            : ManagedObject.ManagedObjectTypes.TryGetValue(objType, out Type type) && typeof(T).IsAssignableFrom(type)
            ? (T)Activator.CreateInstance(
                type,
                BindingFlags.Instance | BindingFlags.NonPublic,
                null,
                [reference, session],
                null)
            : throw new NotSupportedException();
    }
}

using System.Reflection;
using CsVmomi;
using VimService;

try
{
    Work(args);
}
catch (Exception e)
{
    Console.Error.WriteLine(string.Format("{0}", e));
}

void Work(string[] args)
{
    var operations = typeof(VimPortTypeClient).GetMethods()
        .Where(o => o.DeclaringType == typeof(VimPortTypeClient))
        .Where(o => !o.IsVirtual)
        .ToArray();
    var clientMethod = typeof(Client).GetMethods();

    foreach (var operation in operations)
    {
        var wrapper = clientMethod.FirstOrDefault(
            // clientMethod' name is Upper Camel Case, operation's name is Upper or lower camel Case.
            m => $"{m.Name}Async".ToLowerInvariant() == operation.Name.ToLowerInvariant());
        if (wrapper == null)
        {
            Console.Error.WriteLine($"Not found wrapper metthod `{operation.Name}`.");
            continue;
        }

        CheckMethodParameter(operation, wrapper);

        CheckMethodReturn(operation, wrapper);
    }
}

void CheckMethodParameter(MethodInfo operation, MethodInfo wrapper)
{
    var requests = operation.GetParameters();
    if (requests.Length != 1)
    {
        Console.Error.WriteLine($"Unexpected number of parameter `{operation.Name}:{requests.Length}`");
        return;
    }

    var parameters = requests[0].ParameterType.GetProperties();
    var clientParams = wrapper.GetParameters();

    foreach (var parameter in parameters)
    {
        var paramName = parameter.Name;
        if (paramName == "_this")
        {
            // clientMethod's first parameter is `self`, operation's first parameter is `_this`.
            paramName = "self";
        }

        var param = clientParams.FirstOrDefault(p => p.Name == paramName);
        if (param == null)
        {
            Console.Error.WriteLine($"Not found wrapper parameter `{operation.Name}({parameter.Name})`");
            continue;
        }

        if (parameter.PropertyType != param.ParameterType)
        {
            Console.Error.WriteLine($"Not match wrapper parameter type `{operation.Name}({parameter.PropertyType.Name} {parameter.Name})`");
            continue;
        }
    }

}

void CheckMethodReturn(MethodInfo operation, MethodInfo wrapper)
{
    var operationTypes = operation.ReturnType.GenericTypeArguments;
    if (operationTypes.Length != 1)
    {
        Console.Error.WriteLine($"Unexpected number of return `{operation.Name}`");
        return;
    }

    var clientTypes = wrapper.ReturnType.GenericTypeArguments;
    if (clientTypes.Length != 0)
    {
        // no check. compile success is enough.
        return;
    }

    var r = operationTypes.First().GetFields().Single();
    var members = r.FieldType.GetMembers()
        .Where(m => m.MemberType == MemberTypes.Field || m.MemberType == MemberTypes.Property)
        .ToArray();
    if (members.Length != 0)
    {
        Console.Error.WriteLine($"Not match wrapper return type `{operation.Name}`");
        return;
    }
}

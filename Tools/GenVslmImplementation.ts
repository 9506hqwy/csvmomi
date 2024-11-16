import {
  convertType,
  csStructureTypes,
  excludeManagedObjectMethod,
  findMethod,
  getCls,
  getManagedMethodRefs1,
  toCapitalCase,
} from "./Common.ts";

const directory = Deno.args[0];

function writeManagedObjectMethod(method: ManagedObjectMethod) {
  const methodName = toCapitalCase(method.name);
  const params = writeManagedObjectMethodParameter(method);
  const reqType = method.name.endsWith("_Task")
    ? method.name.slice(0, -5)
    : method.name;
  const constructors = writeManagedObjectMethodConstructor(method);

  let methodDeclare = "";
  if (method.returnTy == null) {
    // START
    methodDeclare = `
    public async System.Threading.Tasks.Task ${methodName}(${params.join(", ")})
    {
        var req = new ${reqType}RequestType
        {
            ${constructors.join("\n            ")}
        };

        await this.inner.${method.name}Async(req);
    }`;
    // END
  } else {
    // START
    let returnTy = convertType(method.returnTy.remote);
    if (!csStructureTypes.includes(returnTy)) {
      returnTy += "?";
    }

    const returnAcc = method.returnTy.remote.slice(-2) == "[]"
      ? `${method.name}Response1`
      : `${method.name}Response.returnval`;

    methodDeclare = `
    public async System.Threading.Tasks.Task<${returnTy}> ${methodName}(${
      params.join(", ")
    })
    {
        var req = new ${reqType}RequestType
        {
            ${constructors.join("\n            ")}
        };

        var res = await this.inner.${method.name}Async(req);

        return res.${returnAcc};
    }`;
    // END
  }

  console.log(methodDeclare);
}

function writeManagedObjectMethodParameter(
  method: ManagedObjectMethod,
): string[] {
  const params = [];
  for (const param of method.parameters) {
    const ty = convertType(param.ty.remote);

    let paramTy = ty;
    if (!param.mandatory && !csStructureTypes.includes(paramTy)) {
      paramTy += "?";
    }

    let paramName = param.name;
    if (paramName == "_this") {
      paramName = "self";
    }

    params.push(`${paramTy} ${paramName}`);

    if (!param.mandatory) {
      if (csStructureTypes.includes(ty)) {
        params.push(`bool ${paramName}Specified`);
      }
    }
  }
  return params;
}

function writeManagedObjectMethodConstructor(
  method: ManagedObjectMethod,
): string[] {
  const constructors = ["_this = self,"];
  for (const param of method.parameters) {
    if (param.name == "_this") {
      continue;
    }

    constructors.push(`${param.name} = ${param.name},`);

    if (!param.mandatory) {
      const ty = convertType(param.ty.remote);
      if (csStructureTypes.includes(ty)) {
        constructors.push(`${param.name}Specified = ${param.name}Specified,`);
      }
    }
  }
  return constructors;
}

const methods = await getManagedMethodRefs1(directory);
const cls = await getCls(directory, methods);

console.log(`namespace CsVmomi;

using System.ServiceModel.Channels;
using VslmService;

#pragma warning disable IDE0058 // Expression value is never used

public class VslmClient : IVslmClient
{
    private readonly VslmPortTypeClient inner;

    internal VslmClient(VslmPortTypeClient inner)
    {
        this.inner = inner;
    }

    public Uri Uri => this.inner.Endpoint.Address.Uri;

    public string? GetCookie(string name)
    {
        return this.GetCookie()?
            .OfType<System.Net.Cookie>()
            .FirstOrDefault(c => c.Name == name)?
            .Value;
    }

    public System.Net.CookieCollection? GetCookie()
    {
        return this.inner.InnerChannel.GetProperty<IHttpCookieContainerManager>()?
            .CookieContainer
            .GetCookies(this.Uri);
    }

    public void SetCookie(System.Net.CookieCollection? cookie)
    {
        var container = this.inner.InnerChannel
            .GetProperty<IHttpCookieContainerManager>()!
            .CookieContainer;

        foreach (var c in cookie.OfType<System.Net.Cookie>())
        {
            container.Add(new System.Net.Cookie(c.Name, c.Value, this.Uri.AbsolutePath, this.Uri.Host));
        }
    }`);
for (const ref of methods) {
  if (excludeManagedObjectMethod.includes(ref.id)) {
    continue;
  }

  if (!ref.clsName.startsWith('vslm')) {
    continue;
  }

  const method = findMethod(ref, cls[ref.clsName]);
  writeManagedObjectMethod(method);
}
console.log(`
}

#pragma warning restore IDE0058 // Expression value is never used`);

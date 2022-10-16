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

  let methodDeclare = "";
  if (method.returnTy == null) {
    // START
    methodDeclare = `
    System.Threading.Tasks.Task ${methodName}(${params.join(", ")});`;
    // END
  } else {
    let returnTy = convertType(method.returnTy.remote);
    if (!csStructureTypes.includes(returnTy)) {
      returnTy += "?";
    }

    // START
    methodDeclare = `
    System.Threading.Tasks.Task<${returnTy}> ${methodName}(${
      params.join(", ")
    });`;
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

const methods = await getManagedMethodRefs1(directory);
const cls = await getCls(directory, methods);

console.log(`namespace CsVmomi;

using SmsService;

public interface ISmsClient
{
    public Uri Uri { get; }

    public string? GetCookie(string name);

    System.Net.CookieCollection? GetCookie();

    void SetCookie(System.Net.CookieCollection? cookie);`);
for (const ref of methods) {
  if (excludeManagedObjectMethod.includes(ref.id)) {
    continue;
  }

  if (!ref.clsName.startsWith('sms')) {
    continue;
  }

  const method = findMethod(ref, cls[ref.clsName]);
  writeManagedObjectMethod(method);
}
console.log(`
}`);

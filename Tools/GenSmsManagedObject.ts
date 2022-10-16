import {
  convertType,
  csStructureTypes,
  excludeManagedObjectMethod,
  getManagedMethodRefs2,
  getManagedObjects,
  toCapitalCase,
} from "./Common.ts";

const directory = Deno.args[0];

function writeManagedObject(obj: ManagedObject) {
  const className = obj.name;
  const baseTy = obj.baseTy == null ? "ManagedObject" : obj.baseTy;

  let propDeclare = "";
  for (const property of obj.properties) {
    const propName = property.name;
    const methodSuffix = toCapitalCase(property.name);
    const returnTy = convertType(property.ty.local);

    if (
      property.ty.remote == "ManagedObjectReference"
    ) {
      let ty = returnTy;
      if (ty == "ManagedObjectReference") {
        ty = "ManagedObject";
      }
      if (!property.mandatory) {
        ty += "?";
      }
      const q = property.mandatory ? "!" : "";
      // START
      propDeclare += `

    public async System.Threading.Tasks.Task<${ty}> GetProperty${methodSuffix}()
    {
        var ${propName} = await this.GetProperty<ManagedObjectReference>("${propName}");
        return ManagedObject.Create<${returnTy}>(${propName}, this.Session)${q};
    }`;
      // END
    } else if (
      property.ty.remote == "ManagedObjectReference[]"
    ) {
      let ty = returnTy;
      if (ty == "ManagedObjectReference[]") {
        ty = "ManagedObject[]";
      }
      const unitReturnTy = ty.slice(0, -2);
      if (!property.mandatory) {
        ty += "?";
      }
      const q = property.mandatory ? "!" : "?";
      // START
      propDeclare += `

    public async System.Threading.Tasks.Task<${ty}> GetProperty${methodSuffix}()
    {
        var ${propName} = await this.GetProperty<ManagedObjectReference[]>("${propName}");
        return ${propName}${q}
            .Select(r => ManagedObject.Create<${unitReturnTy}>(r, this.Session)!)
            .ToArray();
    }`;
      // END
    } else {
      let ty = returnTy;
      if (!property.mandatory && !csStructureTypes.includes(returnTy)) {
        ty += "?";
      }
      const q = property.mandatory ? "!" : "";

      // START
      propDeclare += `

    public async System.Threading.Tasks.Task<${ty}> GetProperty${methodSuffix}()
    {
        var obj = await this.GetProperty<${returnTy}>("${propName}");
        return obj${q};
    }`;
      // END
    }
  }

  let methodDeclare = "";
  for (const method of obj.methods) {
    const methodName = toCapitalCase(method.name);
    const params = writeManagedObjectMethodParameter(method);
    const args = writeManagedObjectMethodArgument(method);

    if (method.returnTy == null) {
      // START
      methodDeclare += `

    public async System.Threading.Tasks.Task ${methodName}(${params.join(", ")})
    {
        await this.Session.SmsClient!.${methodName}(${args.join(", ")});
    }`;
      // END
    } else {
      if (method.returnTy.remote == "ManagedObjectReference") {
        let localTy = convertType(method.returnTy.local);
        if (localTy == "ManagedObjectReference") {
          localTy = "ManagedObject";
        }

        let returnTy = localTy;
        if (!csStructureTypes.includes(returnTy)) {
          returnTy += "?";
        }

        // START
        methodDeclare += `

    public async System.Threading.Tasks.Task<${returnTy}> ${methodName}(${
          params.join(", ")
        })
    {
        var res = await this.Session.SmsClient!.${methodName}(${args.join(", ")});
        return ManagedObject.Create<${localTy}>(res, this.Session);
    }`;
        // END
      } else if (method.returnTy.remote == "ManagedObjectReference[]") {
        let localTy = convertType(method.returnTy.local);
        if (localTy == "ManagedObjectReference[]") {
          localTy = "ManagedObject[]";
        }
        const unitReturnTy = localTy.slice(0, -2);

        let returnTy = localTy;
        if (!csStructureTypes.includes(returnTy)) {
          returnTy += "?";
        }

        // START
        methodDeclare += `

    public async System.Threading.Tasks.Task<${returnTy}> ${methodName}(${
          params.join(", ")
        })
    {
        var res = await this.Session.SmsClient!.${methodName}(${args.join(", ")});
        return res?.Select(r => ManagedObject.Create<${unitReturnTy}>(r, this.Session)!).ToArray();
    }`;
        // END
      } else if (method.returnTy.local != method.returnTy.remote) {
        throw `Not supported type, ${method.returnTy.remote}`;
      } else {
        let returnTy = convertType(method.returnTy.remote);
        if (!csStructureTypes.includes(returnTy)) {
          returnTy += "?";
        }

        // START
        methodDeclare += `

    public async System.Threading.Tasks.Task<${returnTy}> ${methodName}(${
          params.join(", ")
        })
    {
        return await this.Session.SmsClient!.${methodName}(${args.join(", ")});
    }`;
        // END
      }
    }
  }

  // START
  const classDeclare = `
public partial class ${className} : ${baseTy}
{
    protected ${className}(
        ManagedObjectReference reference,
        Session session)
        : base(reference, session)
    {
    }${propDeclare}${methodDeclare}
}`;
  // END

  console.log(classDeclare);
}

function writeManagedObjectMethodArgument(
  method: ManagedObjectMethod,
): string[] {
  const args = ["this.SmsReference"];
  for (const param of method.parameters) {
    if (param.name == "_this") {
      continue;
    }

    let argName = param.name;

    let ty = convertType(param.ty.local);
    if (!param.mandatory && csStructureTypes.includes(ty)) {
      args.push(`${argName} ?? default`);
      args.push(`${argName}.HasValue`);
    } else if (param.ty.local != param.ty.remote) {
      if (param.ty.remote == "ManagedObjectReference") {
        const q = param.mandatory ? "" : "?";
        args.push(`${argName}${q}.SmsReference`);
      } else if (param.ty.remote == "ManagedObjectReference[]") {
        const q = param.mandatory ? "" : "?";
        args.push(`${argName}${q}.Select(m => m.SmsReference).ToArray()`);
      } else {
        throw `Not supported type, ${param.ty.remote}`;
      }
    } else if (param.ty.local == "ManagedObjectReference") {
      const q = param.mandatory ? "" : "?";
      args.push(`${argName}${q}.SmsReference`);
    } else if (param.ty.local == "ManagedObjectReference[]") {
      const q = param.mandatory ? "" : "?";
      args.push(`${argName}${q}.Select(m => m.SmsReference).ToArray()`);
    } else {
      args.push(argName);
    }
  }
  return args;
}

function writeManagedObjectMethodParameter(
  method: ManagedObjectMethod,
): string[] {
  const params = [];
  for (const param of method.parameters) {
    if (param.name == "_this") {
      continue;
    }

    let ty = convertType(param.ty.local);

    if (param.ty.local == "ManagedObjectReference") {
      ty = "ManagedObject";
    } else if (param.ty.local == "ManagedObjectReference[]") {
      ty = "ManagedObject[]";
    }

    if (!param.mandatory) {
      ty += "?";
    }

    params.push(`${ty} ${param.name}`);
  }
  return params;
}

const methods = await getManagedMethodRefs2(directory);
const objs = await getManagedObjects(directory, methods);

console.log(`namespace CsVmomi;

using SmsService;

#pragma warning disable SA1402 // File may only contain a single type`);
for (const obj of objs) {
  if (!obj.name.startsWith('Sms') && obj.name != 'VasaProvider') {
    continue;
  }

  writeManagedObject(obj);
}
console.log(`
#pragma warning restore SA1402 // File may only contain a single type`);

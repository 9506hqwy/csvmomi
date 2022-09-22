import { readLines } from "https://deno.land/std/io/mod.ts?s=readLines";
import { BufWriter } from "https://deno.land/std/io/buffer.ts?s=BufWriter";

const SKIP1 = "[System.Xml.Serialization.XmlIncludeAttribute(";
const SKIP2 = "[System.ServiceModel.ServiceKnownTypeAttribute(";

const APPEND1 = "[System.ServiceModel.ServiceContractAttribute(";

const encoder = new TextEncoder();

const source = Deno.args[0];
const destination = Deno.args[1];

const sourceFile = await Deno.open(source, { read: true });
const destinationFile = await Deno.open(destination, {
  write: true,
  create: true,
  truncate: true,
});
const writer = new BufWriter(destinationFile);

for await (const line of readLines(sourceFile)) {
  if (line.trimStart().startsWith(SKIP1)) {
    continue;
  }

  if (line.trimStart().startsWith(SKIP2)) {
    continue;
  }

  if (line.trimStart().startsWith(APPEND1)) {
    await writer.write(
      encoder.encode(
        "    [System.Xml.Serialization.XmlSerializerAssemblyAttribute]\n",
      ),
    );
    await writer.flush();
  }

  await writer.write(encoder.encode(line + "\n"));
  await writer.flush();
}

writer.flush();

Deno.close(sourceFile.rid);
Deno.close(destinationFile.rid);

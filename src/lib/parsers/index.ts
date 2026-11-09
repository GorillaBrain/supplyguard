import YAML from "yaml";
import { XMLParser } from "fast-xml-parser";
import {
  DependencyEdge,
  DependencyNode,
  Ecosystem,
} from "@/types/security";

export interface ParsedDependencyGraph {
  ecosystems: Ecosystem[];
  dependencies: DependencyNode[];
  edges: DependencyEdge[];
  registryConfigs: {
    filePath: string;
    ecosystem: Ecosystem;
    content: string;
  }[];
  unsupportedFiles: { fileName: string; reason: string }[];
  parsedFiles: string[];
}

export function normalizeVersion(rawVersion: string): string {
  if (!rawVersion) return "0.0.0";
  const cleaned = rawVersion
    .trim()
    .replace(/^[~^>=<v=\s]+/, "")
    .split(/\s+/)[0]
    .replace(/['"]/g, "");
  return cleaned || "0.0.0";
}

function makeNodeId(ecosystem: Ecosystem, name: string, version: string): string {
  return `${ecosystem}:${name}@${version}`;
}

/**
 * Parses `package.json` manifest files.
 */
export function parsePackageJson(
  content: string,
  filePath: string
): {
  directNames: Set<string>;
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  rootScripts: Record<string, string>;
} {
  const parsed = JSON.parse(content);
  const deps: Record<string, string> = {
    ...(parsed.dependencies ?? {}),
    ...(parsed.devDependencies ?? {}),
    ...(parsed.optionalDependencies ?? {}),
  };
  const rootScripts: Record<string, string> = parsed.scripts ?? {};
  const hasLifecycleScript = Boolean(
    rootScripts.preinstall || rootScripts.install || rootScripts.postinstall
  );
  const scriptCombined = [
    rootScripts.preinstall,
    rootScripts.install,
    rootScripts.postinstall,
  ]
    .filter(Boolean)
    .join(" && ");

  const directNames = new Set<string>(Object.keys(deps));
  const nodes: DependencyNode[] = [];
  const edges: DependencyEdge[] = [];

  for (const [name, rawVer] of Object.entries(deps)) {
    const version = normalizeVersion(String(rawVer));
    const id = makeNodeId("npm", name, version);
    nodes.push({
      id,
      name,
      version,
      ecosystem: "npm",
      scope: "direct",
      depth: 1,
      license: typeof parsed.license === "string" ? undefined : undefined,
      hasInstallScripts: hasLifecycleScript && nodes.length === 0 ? true : false,
      installScriptContent:
        hasLifecycleScript && nodes.length === 0 ? scriptCombined : undefined,
      parents: ["root"],
      children: [],
      sourceFile: filePath,
    });
    edges.push({
      id: `root->${id}`,
      source: "root",
      target: id,
      scope: "direct",
    });
  }

  return { directNames, nodes, edges, rootScripts };
}

/**
 * Parses `package-lock.json` or `npm-shrinkwrap.json` (supports lockfileVersion 1, 2, and 3).
 */
export function parsePackageLockJson(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const parsed = JSON.parse(content);
  const nodesMap = new Map<string, DependencyNode>();
  const edges: DependencyEdge[] = [];
  const directDepNames = new Set<string>();

  // Identify direct dependencies from root package entry in v2/v3
  if (parsed.packages && parsed.packages[""]) {
    const rootPkg = parsed.packages[""];
    const allRootDeps = {
      ...(rootPkg.dependencies ?? {}),
      ...(rootPkg.devDependencies ?? {}),
      ...(rootPkg.optionalDependencies ?? {}),
    };
    Object.keys(allRootDeps).forEach((d) => directDepNames.add(d));
  }

  if (parsed.packages && typeof parsed.packages === "object") {
    // lockfileVersion 2 / 3
    const pkgEntries = Object.entries(parsed.packages) as [string, Record<string, unknown>][];
    const nameToNodeId = new Map<string, string>();

    for (const [pkgPath, meta] of pkgEntries) {
      if (pkgPath === "") continue;
      // Extract package name from path like "node_modules/express" or "node_modules/a/node_modules/@scope/pkg"
      const parts = pkgPath.split("node_modules/").filter(Boolean);
      const rawName = (meta.name as string) || parts[parts.length - 1]?.replace(/\/$/, "");
      if (!rawName) continue;
      const version = normalizeVersion(String(meta.version ?? "0.0.0"));
      const depth = parts.length;
      const isDirect = depth === 1 && (directDepNames.size === 0 || directDepNames.has(rawName));
      const scope = isDirect ? "direct" : "transitive";
      const id = makeNodeId("npm", rawName, version);

      const scripts = meta.scripts as Record<string, string> | undefined;
      const scriptText = scripts
        ? [scripts.preinstall, scripts.install, scripts.postinstall]
            .filter(Boolean)
            .join(" && ")
        : undefined;

      if (!nodesMap.has(id)) {
        nodesMap.set(id, {
          id,
          name: rawName,
          version,
          ecosystem: "npm",
          scope,
          depth,
          license: typeof meta.license === "string" ? meta.license : undefined,
          resolvedUrl: typeof meta.resolved === "string" ? meta.resolved : undefined,
          integrity: typeof meta.integrity === "string" ? meta.integrity : undefined,
          hasInstallScripts: Boolean(meta.hasInstallScript || scriptText),
          installScriptContent: scriptText,
          parents: isDirect ? ["root"] : [],
          children: [],
          sourceFile: filePath,
        });
      }
      if (!nameToNodeId.has(rawName) || isDirect) {
        nameToNodeId.set(rawName, id);
      }
    }

    // Wire dependency relationships
    for (const [pkgPath, meta] of pkgEntries) {
      if (pkgPath === "") continue;
      const parts = pkgPath.split("node_modules/").filter(Boolean);
      const rawName = (meta.name as string) || parts[parts.length - 1]?.replace(/\/$/, "");
      const version = normalizeVersion(String(meta.version ?? "0.0.0"));
      const sourceId = makeNodeId("npm", rawName, version);
      const sourceNode = nodesMap.get(sourceId);
      if (!sourceNode) continue;

      if (sourceNode.scope === "direct") {
        edges.push({
          id: `root->${sourceId}`,
          source: "root",
          target: sourceId,
          scope: "direct",
        });
      }

      const subDeps = {
        ...((meta.dependencies as Record<string, string>) ?? {}),
        ...((meta.optionalDependencies as Record<string, string>) ?? {}),
      };
      for (const childName of Object.keys(subDeps)) {
        const targetId = nameToNodeId.get(childName);
        if (targetId && targetId !== sourceId) {
          const targetNode = nodesMap.get(targetId);
          if (targetNode) {
            if (!sourceNode.children.includes(targetId)) {
              sourceNode.children.push(targetId);
            }
            if (!targetNode.parents.includes(sourceId)) {
              targetNode.parents.push(sourceId);
            }
            edges.push({
              id: `${sourceId}->${targetId}`,
              source: sourceId,
              target: targetId,
              scope: "transitive",
            });
          }
        }
      }
    }
  } else if (parsed.dependencies && typeof parsed.dependencies === "object") {
    // lockfileVersion 1
    const walkV1 = (
      depsObj: Record<string, Record<string, unknown>>,
      parentId: string,
      depth: number
    ) => {
      for (const [name, meta] of Object.entries(depsObj)) {
        const version = normalizeVersion(String(meta.version ?? "0.0.0"));
        const id = makeNodeId("npm", name, version);
        const scope = depth === 1 ? "direct" : "transitive";
        if (!nodesMap.has(id)) {
          nodesMap.set(id, {
            id,
            name,
            version,
            ecosystem: "npm",
            scope,
            depth,
            resolvedUrl: typeof meta.resolved === "string" ? meta.resolved : undefined,
            integrity: typeof meta.integrity === "string" ? meta.integrity : undefined,
            parents: [parentId],
            children: [],
            sourceFile: filePath,
          });
        } else {
          const existing = nodesMap.get(id)!;
          if (!existing.parents.includes(parentId)) {
            existing.parents.push(parentId);
          }
        }
        edges.push({
          id: `${parentId}->${id}`,
          source: parentId,
          target: id,
          scope,
        });
        if (meta.requires && typeof meta.requires === "object") {
          for (const [reqName, reqVer] of Object.entries(
            meta.requires as Record<string, string>
          )) {
            const topMatch = (parsed.dependencies as Record<string, Record<string, unknown>>)[reqName];
            const resolvedVer = topMatch
              ? normalizeVersion(String(topMatch.version ?? reqVer))
              : normalizeVersion(reqVer);
            const childId = makeNodeId("npm", reqName, resolvedVer);
            const parentNode = nodesMap.get(id);
            if (parentNode && !parentNode.children.includes(childId)) {
              parentNode.children.push(childId);
            }
          }
        }
        if (meta.dependencies && typeof meta.dependencies === "object") {
          walkV1(
            meta.dependencies as Record<string, Record<string, unknown>>,
            id,
            depth + 1
          );
        }
      }
    };
    walkV1(parsed.dependencies as Record<string, Record<string, unknown>>, "root", 1);
  }

  return { nodes: Array.from(nodesMap.values()), edges };
}

/**
 * Parses `yarn.lock` (v1 & Berry syntax).
 */
export function parseYarnLock(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const nodesMap = new Map<string, DependencyNode>();
  const edges: DependencyEdge[] = [];
  const nameToId = new Map<string, string>();
  const pendingChildren: { sourceId: string; childNames: string[] }[] = [];

  const blocks = content.split(/\n{2,}/);
  for (const block of blocks) {
    const lines = block
      .split(/\r?\n/)
      .map((l) => l.trimRight())
      .filter((l) => l && !l.startsWith("#"));
    if (lines.length < 2) continue;

    const header = lines[0];
    if (!header.endsWith(":")) continue;

    // Extract package name from e.g. `"@babel/core@^7.0.0", "@babel/core@^7.1.0":`
    const firstSpec = header.replace(/:$/, "").split(",")[0].trim().replace(/^"|"$/g, "");
    const atIndex = firstSpec.lastIndexOf("@");
    if (atIndex <= 0) continue;
    const pkgName = firstSpec.slice(0, atIndex).replace(/^npm:/, "");

    let version = "";
    let resolvedUrl: string | undefined;
    const childNames: string[] = [];
    let inDeps = false;

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      const verMatch = line.match(/^\s*version[:\s]+"?([^"\s]+)"?/);
      if (verMatch) {
        version = normalizeVersion(verMatch[1]);
        inDeps = false;
        continue;
      }
      const resMatch = line.match(/^\s*resolved\s+"([^"]+)"/);
      if (resMatch) {
        resolvedUrl = resMatch[1];
        inDeps = false;
        continue;
      }
      if (/^\s*dependencies:?$/.test(line)) {
        inDeps = true;
        continue;
      }
      if (inDeps) {
        if (/^\s{4,}/.test(line)) {
          const depMatch = line.trim().match(/^"?([^"\s:]+)"?\s+/);
          if (depMatch) {
            childNames.push(depMatch[1]);
          }
        } else {
          inDeps = false;
        }
      }
    }

    if (!pkgName || !version) continue;
    const id = makeNodeId("npm", pkgName, version);
    if (!nodesMap.has(id)) {
      nodesMap.set(id, {
        id,
        name: pkgName,
        version,
        ecosystem: "npm",
        scope: "direct", // refined once edges are computed
        depth: 1,
        resolvedUrl,
        parents: [],
        children: [],
        sourceFile: filePath,
      });
    }
    nameToId.set(pkgName, id);
    if (childNames.length > 0) {
      pendingChildren.push({ sourceId: id, childNames });
    }
  }

  const hasIncomingParent = new Set<string>();
  for (const { sourceId, childNames } of pendingChildren) {
    const sourceNode = nodesMap.get(sourceId);
    if (!sourceNode) continue;
    for (const cName of childNames) {
      const targetId = nameToId.get(cName);
      if (targetId && targetId !== sourceId) {
        hasIncomingParent.add(targetId);
        const targetNode = nodesMap.get(targetId)!;
        if (!sourceNode.children.includes(targetId)) sourceNode.children.push(targetId);
        if (!targetNode.parents.includes(sourceId)) targetNode.parents.push(sourceId);
        edges.push({
          id: `${sourceId}->${targetId}`,
          source: sourceId,
          target: targetId,
          scope: "transitive",
        });
      }
    }
  }

  for (const node of nodesMap.values()) {
    if (hasIncomingParent.has(node.id)) {
      node.scope = "transitive";
      node.depth = 2;
    } else {
      node.scope = "direct";
      node.depth = 1;
      node.parents.push("root");
      edges.push({
        id: `root->${node.id}`,
        source: "root",
        target: node.id,
        scope: "direct",
      });
    }
  }

  return { nodes: Array.from(nodesMap.values()), edges };
}

/**
 * Parses `pnpm-lock.yaml`.
 */
export function parsePnpmLock(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const doc = YAML.parse(content) as Record<string, unknown>;
  const nodesMap = new Map<string, DependencyNode>();
  const edges: DependencyEdge[] = [];
  const directNames = new Set<string>();

  const collectDirect = (section: unknown) => {
    if (section && typeof section === "object") {
      Object.keys(section as Record<string, unknown>).forEach((k) => directNames.add(k));
    }
  };
  collectDirect(doc.dependencies);
  collectDirect(doc.devDependencies);
  if (doc.importers && typeof doc.importers === "object") {
    const rootImporter = (doc.importers as Record<string, Record<string, unknown>>)["."];
    if (rootImporter) {
      collectDirect(rootImporter.dependencies);
      collectDirect(rootImporter.devDependencies);
    }
  }

  const packagesSection = (doc.packages ?? doc.snapshots ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  for (const [specKey, meta] of Object.entries(packagesSection)) {
    const cleanedKey = specKey.replace(/^\//, "").split("(")[0];
    const atIdx = cleanedKey.lastIndexOf("@");
    let name = "";
    let version = "";
    if (atIdx > 0) {
      name = cleanedKey.slice(0, atIdx);
      version = normalizeVersion(cleanedKey.slice(atIdx + 1));
    } else {
      const slashIdx = cleanedKey.lastIndexOf("/");
      if (slashIdx > 0) {
        name = cleanedKey.slice(0, slashIdx);
        version = normalizeVersion(cleanedKey.slice(slashIdx + 1));
      }
    }
    if (!name || !version) continue;
    const isDirect = directNames.size === 0 || directNames.has(name);
    const id = makeNodeId("npm", name, version);
    if (!nodesMap.has(id)) {
      nodesMap.set(id, {
        id,
        name,
        version,
        ecosystem: "npm",
        scope: isDirect ? "direct" : "transitive",
        depth: isDirect ? 1 : 2,
        hasInstallScripts: Boolean(meta?.requiresBuild),
        parents: isDirect ? ["root"] : [],
        children: [],
        sourceFile: filePath,
      });
      if (isDirect) {
        edges.push({
          id: `root->${id}`,
          source: "root",
          target: id,
          scope: "direct",
        });
      }
    }
  }

  return { nodes: Array.from(nodesMap.values()), edges };
}

/**
 * Parses Python `requirements.txt`.
 */
export function parseRequirementsTxt(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const nodes: DependencyNode[] = [];
  const edges: DependencyEdge[] = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].split(";")[0].trim();
    if (!line || line.startsWith("-")) continue;

    const match = line.match(/^([a-zA-Z0-9._-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=|<=|>|<)\s*([^\s,]+)/);
    if (match) {
      const name = match[1].toLowerCase();
      const version = normalizeVersion(match[2]);
      const id = makeNodeId("PyPI", name, version);
      nodes.push({
        id,
        name,
        version,
        ecosystem: "PyPI",
        scope: "direct",
        depth: 1,
        parents: ["root"],
        children: [],
        sourceFile: filePath,
      });
      edges.push({
        id: `root->${id}`,
        source: "root",
        target: id,
        scope: "direct",
      });
    }
  }

  return { nodes, edges };
}

/**
 * Parses Python `Pipfile.lock`.
 */
export function parsePipfileLock(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const parsed = JSON.parse(content);
  const nodes: DependencyNode[] = [];
  const edges: DependencyEdge[] = [];

  const sections = [parsed.default ?? {}, parsed.develop ?? {}];
  for (const section of sections) {
    for (const [rawName, meta] of Object.entries(
      section as Record<string, Record<string, unknown>>
    )) {
      const name = rawName.toLowerCase();
      const version = normalizeVersion(String(meta.version ?? "0.0.0"));
      const id = makeNodeId("PyPI", name, version);
      if (nodes.some((n) => n.id === id)) continue;
      nodes.push({
        id,
        name,
        version,
        ecosystem: "PyPI",
        scope: "direct",
        depth: 1,
        parents: ["root"],
        children: [],
        sourceFile: filePath,
      });
      edges.push({
        id: `root->${id}`,
        source: "root",
        target: id,
        scope: "direct",
      });
    }
  }

  return { nodes, edges };
}

/**
 * Parses Python `poetry.lock`.
 */
export function parsePoetryLock(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const nodesMap = new Map<string, DependencyNode>();
  const edges: DependencyEdge[] = [];
  const nameToId = new Map<string, string>();
  const depLinks: { parentName: string; childName: string }[] = [];

  const blocks = content.split(/\[\[package\]\]/g).slice(1);
  for (const block of blocks) {
    const nameMatch = block.match(/^\s*name\s*=\s*"([^"]+)"/m);
    const verMatch = block.match(/^\s*version\s*=\s*"([^"]+)"/m);
    if (!nameMatch || !verMatch) continue;
    const name = nameMatch[1].toLowerCase();
    const version = normalizeVersion(verMatch[1]);
    const id = makeNodeId("PyPI", name, version);
    nodesMap.set(id, {
      id,
      name,
      version,
      ecosystem: "PyPI",
      scope: "direct",
      depth: 1,
      parents: [],
      children: [],
      sourceFile: filePath,
    });
    nameToId.set(name, id);

    const depSectionMatch = block.match(/\[package\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
    if (depSectionMatch) {
      const depLines = depSectionMatch[1].split(/\r?\n/);
      for (const dLine of depLines) {
        const dMatch = dLine.trim().match(/^([a-zA-Z0-9._-]+)\s*=/);
        if (dMatch) {
          depLinks.push({ parentName: name, childName: dMatch[1].toLowerCase() });
        }
      }
    }
  }

  const hasIncoming = new Set<string>();
  for (const { parentName, childName } of depLinks) {
    const sourceId = nameToId.get(parentName);
    const targetId = nameToId.get(childName);
    if (sourceId && targetId && sourceId !== targetId) {
      hasIncoming.add(targetId);
      const sNode = nodesMap.get(sourceId)!;
      const tNode = nodesMap.get(targetId)!;
      if (!sNode.children.includes(targetId)) sNode.children.push(targetId);
      if (!tNode.parents.includes(sourceId)) tNode.parents.push(sourceId);
      edges.push({
        id: `${sourceId}->${targetId}`,
        source: sourceId,
        target: targetId,
        scope: "transitive",
      });
    }
  }

  for (const node of nodesMap.values()) {
    if (hasIncoming.has(node.id)) {
      node.scope = "transitive";
      node.depth = 2;
    } else {
      node.scope = "direct";
      node.depth = 1;
      node.parents.push("root");
      edges.push({
        id: `root->${node.id}`,
        source: "root",
        target: node.id,
        scope: "direct",
      });
    }
  }

  return { nodes: Array.from(nodesMap.values()), edges };
}

/**
 * Parses Ruby `Gemfile.lock`.
 */
export function parseGemfileLock(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const nodesMap = new Map<string, DependencyNode>();
  const edges: DependencyEdge[] = [];
  const nameToId = new Map<string, string>();
  const directGems = new Set<string>();
  const childRelations: { parentName: string; childName: string }[] = [];

  const depBlockMatch = content.match(/DEPENDENCIES\r?\n([\s\S]*?)(?:\r?\n\r?\n|$)/);
  if (depBlockMatch) {
    for (const line of depBlockMatch[1].split(/\r?\n/)) {
      const m = line.trim().match(/^([a-zA-Z0-9._-]+)!?/);
      if (m) directGems.add(m[1]);
    }
  }

  const lines = content.split(/\r?\n/);
  let inSpecs = false;
  let currentGem: string | null = null;

  for (const line of lines) {
    if (/^\s{2}specs:$/.test(line)) {
      inSpecs = true;
      continue;
    }
    if (inSpecs && /^\S/.test(line)) {
      inSpecs = false;
      currentGem = null;
      continue;
    }
    if (inSpecs) {
      const gemMatch = line.match(/^\s{4}([a-zA-Z0-9._-]+)\s+\(([^)]+)\)$/);
      if (gemMatch) {
        currentGem = gemMatch[1];
        const version = normalizeVersion(gemMatch[2].split("-")[0]);
        const id = makeNodeId("RubyGems", currentGem, version);
        const isDirect = directGems.size === 0 || directGems.has(currentGem);
        nodesMap.set(id, {
          id,
          name: currentGem,
          version,
          ecosystem: "RubyGems",
          scope: isDirect ? "direct" : "transitive",
          depth: isDirect ? 1 : 2,
          parents: isDirect ? ["root"] : [],
          children: [],
          sourceFile: filePath,
        });
        nameToId.set(currentGem, id);
        if (isDirect) {
          edges.push({
            id: `root->${id}`,
            source: "root",
            target: id,
            scope: "direct",
          });
        }
        continue;
      }
      const subGemMatch = line.match(/^\s{6}([a-zA-Z0-9._-]+)/);
      if (subGemMatch && currentGem) {
        childRelations.push({ parentName: currentGem, childName: subGemMatch[1] });
      }
    }
  }

  for (const { parentName, childName } of childRelations) {
    const sId = nameToId.get(parentName);
    const tId = nameToId.get(childName);
    if (sId && tId && sId !== tId) {
      const sNode = nodesMap.get(sId)!;
      const tNode = nodesMap.get(tId)!;
      if (!sNode.children.includes(tId)) sNode.children.push(tId);
      if (!tNode.parents.includes(sId)) tNode.parents.push(sId);
      edges.push({
        id: `${sId}->${tId}`,
        source: sId,
        target: tId,
        scope: "transitive",
      });
    }
  }

  return { nodes: Array.from(nodesMap.values()), edges };
}

/**
 * Parses Java Maven `pom.xml`.
 */
export function parsePomXml(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const parser = new XMLParser({
    ignoreAttributes: false,
    parseTagValue: false,
  });
  const doc = parser.parse(content);
  const project = doc?.project ?? doc;
  const properties: Record<string, string> = {
    ...(project?.properties ?? {}),
  };

  const resolveProp = (val: string): string => {
    if (!val) return "0.0.0";
    return val.replace(/\$\{([^}]+)\}/g, (_, key) => properties[key] ?? "0.0.0");
  };

  const rawDeps =
    project?.dependencies?.dependency ??
    project?.dependencyManagement?.dependencies?.dependency ??
    [];
  const depArray = Array.isArray(rawDeps) ? rawDeps : [rawDeps].filter(Boolean);

  const nodes: DependencyNode[] = [];
  const edges: DependencyEdge[] = [];

  for (const dep of depArray) {
    const groupId = String(dep.groupId ?? "").trim();
    const artifactId = String(dep.artifactId ?? "").trim();
    if (!groupId || !artifactId) continue;
    const rawVersion = resolveProp(String(dep.version ?? "0.0.0").trim());
    const version = normalizeVersion(rawVersion);
    const name = `${groupId}:${artifactId}`;
    const id = makeNodeId("Maven", name, version);

    nodes.push({
      id,
      name,
      version,
      ecosystem: "Maven",
      scope: "direct",
      depth: 1,
      parents: ["root"],
      children: [],
      sourceFile: filePath,
    });
    edges.push({
      id: `root->${id}`,
      source: "root",
      target: id,
      scope: "direct",
    });
  }

  return { nodes, edges };
}

/**
 * Parses CycloneDX or SPDX JSON SBOM files.
 */
export function parseSbomJson(
  content: string,
  filePath: string
): { nodes: DependencyNode[]; edges: DependencyEdge[] } {
  const parsed = JSON.parse(content);
  const nodesMap = new Map<string, DependencyNode>();
  const edges: DependencyEdge[] = [];
  const bomRefToId = new Map<string, string>();

  const inferEcosystemFromPurl = (purl?: string): Ecosystem => {
    if (!purl) return "npm";
    if (purl.startsWith("pkg:npm/")) return "npm";
    if (purl.startsWith("pkg:pypi/")) return "PyPI";
    if (purl.startsWith("pkg:gem/")) return "RubyGems";
    if (purl.startsWith("pkg:maven/")) return "Maven";
    return "npm";
  };

  if (parsed.bomFormat === "CycloneDX" || Array.isArray(parsed.components)) {
    for (const comp of parsed.components ?? []) {
      const name = comp.group ? `${comp.group}/${comp.name}` : String(comp.name ?? "");
      const version = normalizeVersion(String(comp.version ?? "0.0.0"));
      if (!name) continue;
      const ecosystem = inferEcosystemFromPurl(comp.purl);
      const id = makeNodeId(ecosystem, name, version);

      let license: string | undefined;
      if (Array.isArray(comp.licenses) && comp.licenses[0]) {
        license = comp.licenses[0].license?.id ?? comp.licenses[0].license?.name;
      }

      nodesMap.set(id, {
        id,
        name,
        version,
        ecosystem,
        scope: "direct",
        depth: 1,
        license,
        parents: ["root"],
        children: [],
        sourceFile: filePath,
      });
      if (comp["bom-ref"]) {
        bomRefToId.set(String(comp["bom-ref"]), id);
      }
      edges.push({
        id: `root->${id}`,
        source: "root",
        target: id,
        scope: "direct",
      });
    }

    if (Array.isArray(parsed.dependencies)) {
      for (const rel of parsed.dependencies) {
        const sourceId = bomRefToId.get(String(rel.ref));
        if (sourceId && Array.isArray(rel.dependsOn)) {
          for (const depRef of rel.dependsOn) {
            const targetId = bomRefToId.get(String(depRef));
            if (targetId && targetId !== sourceId) {
              edges.push({
                id: `${sourceId}->${targetId}`,
                source: sourceId,
                target: targetId,
                scope: "transitive",
              });
            }
          }
        }
      }
    }
  } else if (parsed.spdxVersion || Array.isArray(parsed.packages)) {
    for (const pkg of parsed.packages ?? []) {
      const name = String(pkg.name ?? "");
      const version = normalizeVersion(String(pkg.versionInfo ?? "0.0.0"));
      if (!name) continue;
      const extRef = (pkg.externalRefs ?? []).find(
        (r: Record<string, string>) => r.referenceType === "purl"
      );
      const ecosystem = inferEcosystemFromPurl(extRef?.referenceLocator);
      const id = makeNodeId(ecosystem, name, version);
      const license =
        pkg.licenseDeclared && pkg.licenseDeclared !== "NOASSERTION"
          ? String(pkg.licenseDeclared)
          : undefined;

      nodesMap.set(id, {
        id,
        name,
        version,
        ecosystem,
        scope: "direct",
        depth: 1,
        license,
        parents: ["root"],
        children: [],
        sourceFile: filePath,
      });
      edges.push({
        id: `root->${id}`,
        source: "root",
        target: id,
        scope: "direct",
      });
    }
  }

  return { nodes: Array.from(nodesMap.values()), edges };
}

/**
 * Orchestrates parsing across all supplied project files, prioritizing lockfiles over manifests.
 */
export function parseProjectFiles(
  files: { name: string; content: string }[]
): ParsedDependencyGraph {
  const ecosystems = new Set<Ecosystem>();
  const nodesMap = new Map<string, DependencyNode>();
  const edgesMap = new Map<string, DependencyEdge>();
  const registryConfigs: { filePath: string; ecosystem: Ecosystem; content: string }[] = [];
  const unsupportedFiles: { fileName: string; reason: string }[] = [];
  const parsedFiles: string[] = [];

  const hasNpmLockfile = files.some((f) =>
    /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/i.test(
      f.name
    )
  );
  const hasPythonLockfile = files.some((f) =>
    /(?:^|\/)(?:poetry\.lock|Pipfile\.lock)$/i.test(f.name)
  );

  // Sort lockfiles first so resolved versions take precedence
  const sortedFiles = [...files].sort((a, b) => {
    const aIsLock = /lock|shrinkwrap/i.test(a.name) ? 0 : 1;
    const bIsLock = /lock|shrinkwrap/i.test(b.name) ? 0 : 1;
    return aIsLock - bIsLock;
  });

  for (const file of sortedFiles) {
    const fileName = file.name;
    const baseName = fileName.split("/").pop() ?? fileName;

    try {
      if (/^(?:package-lock\.json|npm-shrinkwrap\.json)$/i.test(baseName)) {
        const res = parsePackageLockJson(file.content, fileName);
        ecosystems.add("npm");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => nodesMap.set(n.id, n));
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (/^yarn\.lock$/i.test(baseName)) {
        const res = parseYarnLock(file.content, fileName);
        ecosystems.add("npm");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => nodesMap.set(n.id, n));
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (/^pnpm-lock\.yaml$/i.test(baseName)) {
        const res = parsePnpmLock(file.content, fileName);
        ecosystems.add("npm");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => nodesMap.set(n.id, n));
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (/^package\.json$/i.test(baseName)) {
        const res = parsePackageJson(file.content, fileName);
        ecosystems.add("npm");
        parsedFiles.push(fileName);
        if (!hasNpmLockfile) {
          res.nodes.forEach((n) => nodesMap.set(n.id, n));
          res.edges.forEach((e) => edgesMap.set(e.id, e));
        } else {
          // Enrich lockfile nodes with direct scope and root install scripts if present
          for (const node of nodesMap.values()) {
            if (node.ecosystem === "npm" && res.directNames.has(node.name)) {
              node.scope = "direct";
              node.depth = 1;
            }
          }
          // Also include any direct deps from package.json that weren't in lockfile
          for (const pNode of res.nodes) {
            const alreadyResolved = Array.from(nodesMap.values()).some(
              (existing) => existing.ecosystem === "npm" && existing.name === pNode.name
            );
            if (!alreadyResolved) {
              nodesMap.set(pNode.id, pNode);
              edgesMap.set(`root->${pNode.id}`, {
                id: `root->${pNode.id}`,
                source: "root",
                target: pNode.id,
                scope: "direct",
              });
            }
          }
        }
      } else if (/^poetry\.lock$/i.test(baseName)) {
        const res = parsePoetryLock(file.content, fileName);
        ecosystems.add("PyPI");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => nodesMap.set(n.id, n));
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (/^Pipfile\.lock$/i.test(baseName)) {
        const res = parsePipfileLock(file.content, fileName);
        ecosystems.add("PyPI");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => nodesMap.set(n.id, n));
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (/^requirements(?:-[a-z0-9_]+)?\.txt$/i.test(baseName)) {
        const res = parseRequirementsTxt(file.content, fileName);
        ecosystems.add("PyPI");
        parsedFiles.push(fileName);
        if (!hasPythonLockfile) {
          res.nodes.forEach((n) => nodesMap.set(n.id, n));
          res.edges.forEach((e) => edgesMap.set(e.id, e));
        }
      } else if (/^Gemfile\.lock$/i.test(baseName)) {
        const res = parseGemfileLock(file.content, fileName);
        ecosystems.add("RubyGems");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => nodesMap.set(n.id, n));
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (/^pom\.xml$/i.test(baseName)) {
        const res = parsePomXml(file.content, fileName);
        ecosystems.add("Maven");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => nodesMap.set(n.id, n));
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (
        /(?:bom|cdx|spdx).*\.(?:json)$/i.test(baseName) ||
        file.content.includes('"bomFormat"') ||
        file.content.includes('"spdxVersion"')
      ) {
        const res = parseSbomJson(file.content, fileName);
        ecosystems.add("SBOM");
        parsedFiles.push(fileName);
        res.nodes.forEach((n) => {
          nodesMap.set(n.id, n);
          ecosystems.add(n.ecosystem);
        });
        res.edges.forEach((e) => edgesMap.set(e.id, e));
      } else if (/^\.npmrc$/i.test(baseName)) {
        registryConfigs.push({
          filePath: fileName,
          ecosystem: "npm",
          content: file.content,
        });
        parsedFiles.push(fileName);
      } else if (/^pip\.conf$/i.test(baseName)) {
        registryConfigs.push({
          filePath: fileName,
          ecosystem: "PyPI",
          content: file.content,
        });
        parsedFiles.push(fileName);
      } else if (
        /\.(?:ya?ml|env.*|js|ts|py|rb|java|sh|properties)$/i.test(baseName) ||
        baseName === "Jenkinsfile"
      ) {
        // CI/CD or source file for static secret & workflow scanning
        parsedFiles.push(fileName);
      } else {
        unsupportedFiles.push({
          fileName,
          reason: `Unsupported file format ('${baseName}'). SupplyGuard analyzes npm, PyPI, RubyGems, Maven manifests/lockfiles, CycloneDX/SPDX SBOMs, and GitHub Actions / GitLab CI / Jenkins workflow files.`,
        });
      }
    } catch (err) {
      unsupportedFiles.push({
        fileName,
        reason: `Failed to parse '${baseName}': ${
          err instanceof Error ? err.message : "Malformed syntax"
        }`,
      });
    }
  }

  return {
    ecosystems: Array.from(ecosystems),
    dependencies: Array.from(nodesMap.values()),
    edges: Array.from(edgesMap.values()),
    registryConfigs,
    unsupportedFiles,
    parsedFiles,
  };
}

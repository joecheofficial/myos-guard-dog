// Node 22 (the All Sorted install default) and Node 24 (the pinned runtime) are
// supported. Node 26 changed behaviour the nightly depends on and is refused.
const SUPPORTED_NODE_MAJORS = [22, 24];

export function assertSupportedNodeVersion(version = process.versions.node) {
  const major = Number.parseInt(String(version).split('.')[0], 10);
  if (SUPPORTED_NODE_MAJORS.includes(major)) return;
  const error = new Error(`Node.js 22.x or 24.x is required; current runtime is ${version}. Use the pinned .nvmrc or .node-version before running MyOS Guard Dog.`);
  error.code = 'ERR_UNSUPPORTED_NODE_VERSION';
  throw error;
}

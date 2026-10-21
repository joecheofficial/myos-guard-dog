import { createHash } from 'node:crypto';
// Original lightweight heuristics, not AST/taint analysis or an antivirus database.
export const RULESET_VERSION = '1';
const source=/(?:^|\/)\.env(?:\.[^/]+)?$|\.(?:[cm]?[jt]sx?|py|sh|bash|zsh|ps1|rb|php|go|ya?ml|json|toml|ini|conf)$/i;
export function isTextPath(file) {return source.test(file)||/(?:^|\/)\.(?:npmrc|pypirc|env)(?:\.[^/]+)?$|\.(?:pem|key|tf|properties|xml|config)$/i.test(file);}
const ci=/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i;
const secretFix='Revoke or rotate the credential, remove it from source and review repository history. Values are never included in this report.';
const reviewFix='Review the code path and its inputs before execution; replace it with a constrained, verified operation.';
function rule(id,category,severity,confidence,pattern,message,remediation=reviewFix,files) {
 return {id,category,severity,confidence,pattern,message,remediation,files};
}
export const RULES = [
 rule('GD-SECRET-GITHUB','secrets','high','high',/\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,'Possible GitHub credential in a file.',secretFix),
 rule('GD-SECRET-AWS','secrets','high','medium',/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,'Possible AWS access key identifier. Confirm whether a matching secret is exposed.',secretFix),
 rule('GD-SECRET-PRIVATE-KEY','secrets','high','high',/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,'Private key material marker found.',secretFix),
 rule('GD-SECRET-SLACK','secrets','high','high',/\bxox[baprs]-[A-Za-z0-9-]{20,200}\b/g,'Possible Slack credential.',secretFix),
 rule('GD-SECRET-STRIPE','secrets','high','high',/\b(?:sk|rk)_live_[A-Za-z0-9]{20,200}\b/g,'Possible live payment API credential.',secretFix),
 rule('GD-SECRET-GOOGLE','secrets','high','medium',/\bAIza[A-Za-z0-9_-]{35}\b/g,'Possible Google API key. Verify API and origin restrictions.',secretFix),
 rule('GD-SECRET-NPM','secrets','high','high',/\bnpm_[A-Za-z0-9]{36}\b/g,'Possible npm publish credential.',secretFix),
 rule('GD-SECRET-PYPI','secrets','high','high',/\bpypi-[A-Za-z0-9_-]{50,400}\b/g,'Possible PyPI publish credential.',secretFix),
 rule('GD-SECRET-OPENAI','secrets','high','medium',/\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,200}\b/g,'Possible API credential.',secretFix),
 rule('GD-SECRET-ASSIGNMENT','secrets','medium','low',/\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*["'][A-Za-z0-9_+\/.=-]{20,200}["']/gi,'Possible hardcoded secret assignment; may be synthetic or public configuration.',secretFix,source),
 rule('GD-DOWNLOAD-EXEC','source','high','high',/\b(?:curl|wget)\b(?:[^\r\n|]|\\\r?\n){1,500}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/g,'Downloaded content is piped directly to a shell.','Download separately, verify a pinned checksum/signature, then review before executing.',source),
 rule('GD-POWERSHELL-ENCODED','source','high','medium',/\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,150}\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/gi,'Encoded PowerShell command requires review.',reviewFix,source),
 rule('GD-ENCODED-EVAL','source','high','medium',/\b(?:eval|exec)\s*\(\s*(?:atob\s*\(|base64\.b64decode\s*\(|Buffer\.from\s*\()/g,'Decoded input is passed to dynamic execution.',reviewFix,source),
 rule('GD-JS-REQUEST-EXEC','source','high','medium',/\b(?:exec|execSync|eval)\s*\(\s*(?:req|request)\.(?:body|query|params)\b/g,'Request input appears to reach a code or shell execution function.','Remove dynamic execution of request data; use a fixed operation and validated arguments.',/\.[cm]?[jt]sx?$/i),
 rule('GD-PYTHON-PICKLE-INPUT','source','high','medium',/\bpickle\.loads?\s*\(\s*(?:request|req)\./g,'Request data appears to be deserialized with pickle.','Use a data-only serialization format with schema validation.',/\.py$/i),
 rule('GD-PYTHON-SHELL','source','medium','medium',/\bshell\s*=\s*True\b/g,'Python shell execution is enabled; inspect command construction.',reviewFix,/\.py$/i),
 rule('GD-TLS-DISABLED','configuration','high','high',/\bNODE_TLS_REJECT_UNAUTHORIZED["']?\s*[:=]?\s*["']?0\b/g,'Node TLS certificate verification is disabled.','Restore certificate validation and configure the correct trust store.',source),
 rule('GD-TLS-REJECT-FALSE','configuration','medium','high',/\brejectUnauthorized\s*:\s*false\b/g,'TLS certificate verification is disabled for a connection.','Enable certificate verification and configure trusted certificates.',source),
 rule('GD-NPM-TLS-DISABLED','configuration','high','high',/^\s*strict-ssl\s*=\s*false\s*$/gm,'npm TLS verification is disabled.','Remove this setting; configure the registry CA instead.',/(?:^|\/)\.npmrc$/),
 rule('GD-DOCKER-SOCKET','configuration','high','high',/\/var\/run\/docker\.sock/g,'Docker socket access can grant host control.','Remove the socket mount or isolate this explicitly trusted administrative workload.',/(?:docker|compose)[^/]*\.(?:ya?ml|json)$/i),
 rule('GD-CONTAINER-PRIVILEGED','configuration','high','high',/\bprivileged\s*:\s*true\b/gi,'Container privileged mode is enabled.','Use only the required capabilities and a restricted security context.',/\.ya?ml$/i),
 rule('GD-TERRAFORM-PUBLIC-SSH','configuration','medium','low',/(?:0\.0\.0\.0\/0|::\/0)/g,'Infrastructure includes an unrestricted network CIDR. Verify exposed ports.','Restrict administrative access to intended sources; assess public service exceptions.',/\.tf$/i),
 rule('GD-CI-WRITE-ALL','ci','medium','high',/\bpermissions\s*:\s*write-all\b/g,'Workflow grants all write permissions.','Set minimum token permissions per job.',ci),
 rule('GD-CI-PRIVILEGED-PR','ci','medium','medium',/\bpull_request_target\b/g,'Privileged pull-request workflow needs trust-boundary review.','Do not execute untrusted pull-request code with repository secrets or write tokens.',ci),
 rule('GD-CI-UNTRUSTED-EXPRESSION','ci','high','medium',/\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body)[^}\r\n]{0,200}\}\}/g,'Untrusted event expression appears in workflow text. Review shell/script interpolation.','Pass event data through an environment variable and quote it; never interpolate it directly into scripts.',ci),
 rule('GD-CI-MUTABLE-ACTION','ci','low','medium',/^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@(?![a-f0-9]{40}\s*(?:#.*)?$)[^\s#]+/gm,'Workflow action reference is not pinned to a full commit SHA.','Pin third-party actions to reviewed immutable commits.',ci),
 rule('GD-AGENT-APPROVAL-BYPASS','agent','medium','medium',/\b(?:dangerously-skip-permissions|approval_policy["']?\s*[:=]\s*["']never["']|sandbox_mode["']?\s*[:=]\s*["']danger-full-access["'])/g,'Coding-agent configuration disables an approval or sandbox boundary.','Confirm this is intentional and use the narrowest permissions appropriate to the project.',/(?:^|\/)(?:\.claude|\.codex|\.vscode)\/|(?:^|\/)\.mcp\.json$/),
 rule('GD-MALWARE-EICAR','malware','high','high',/EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/g,'Antivirus test signature found. This is a test marker, not proof of real malware.','Confirm this is an intentional scanner fixture; remove unintended copies.')
];
function scriptInterpolation(text, index) {
 const lines=text.slice(0,index).split('\n');
 const current=lines.at(-1);
 if(/^\s*-?\s*(?:run|script):/.test(current))return true;
 const indent=current.match(/^ */)[0].length;
 for(let i=lines.length-2;i>=0;i--) {
  if(!lines[i].trim())continue;
  const prior=lines[i].match(/^ */)[0].length;
  if(prior<indent && /^\s*-?\s*[A-Za-z_][\w-]*:/.test(lines[i])) return /^\s*-?\s*(?:run|script):\s*[|>][-+]?\s*(?:#.*)?$/.test(lines[i]);
 }
 return false;
}
export function inspectText(text, file, {binary=false,deadline=Infinity}={}) {
 const findings=[];
 for(const rule of RULES) {
  if(Date.now()>=deadline)return {findings,truncated:false,timedOut:true};
  if(binary && rule.category!=='malware') continue;
  if(rule.files && !rule.files.test(file)) continue;
  rule.pattern.lastIndex=0;
  for(const match of text.matchAll(rule.pattern)) {
   if(Date.now()>=deadline)return {findings,truncated:false,timedOut:true};
   const prefix=text.slice(text.lastIndexOf('\n',match.index-1)+1,match.index);
   if(rule.category!=='secrets' && /^\s*(?:#|\/\/)/.test(prefix))continue;
   if(rule.id==='GD-CI-UNTRUSTED-EXPRESSION' && !scriptInterpolation(text,match.index))continue;
   if(rule.id==='GD-TERRAFORM-PUBLIC-SSH' && !/\b(?:from_port|to_port)\s*=\s*22\b/.test(text))continue;
   if(rule.id==='GD-SECRET-AWS' && match[0]==='AKIAIOSFODNN7EXAMPLE')continue;
   if(rule.id==='GD-SECRET-ASSIGNMENT' && /placeholder|example|change_?me|your[_-](?:key|token|secret)/i.test(match[0]))continue;
   const keyEnd=rule.id==='GD-SECRET-PRIVATE-KEY'?text.indexOf('-----END ',match.index+match[0].length):-1;
   const evidence=rule.id==='GD-SECRET-PRIVATE-KEY'?text.slice(match.index,keyEnd>=0?keyEnd:text.length):match[0];
   const evidenceHash=createHash('sha256').update(evidence).digest('hex');
   findings.push({evidenceHash,ruleId:rule.id,category:rule.category,severity:rule.severity,confidence:rule.confidence,path:file,line:text.slice(0,match.index).split('\n').length,message:rule.message,remediation:rule.remediation,engine:'native'});
   if(findings.length>=200)return {findings,truncated:true};
  }
 }
 return {findings,truncated:false};
}

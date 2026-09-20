import { rmSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { coreRoot, getContext, evaluate, verifyReport } from './harness.mjs';
import { runScenario } from './scenarios.mjs';

const reportPath = join(coreRoot, 'eval/report.json');
rmSync(reportPath, { force: true });
rmSync(reportPath + '.tmp', { force: true });
try {
  // Rebuild only after stale results are removed; direct invocation is safe too.
  execFileSync('pnpm', ['build'], { cwd: coreRoot, stdio: 'inherit', timeout: 120_000 });
  const api = await import('../../dist/index.js');
  const { createRuntime, loadPolicyFromString } = api;
  const context = getContext();
  const report = await evaluate(context, async item => {
    // Fresh state per case prevents rate limits and previous prompts affecting decisions.
    const policy = loadPolicyFromString(context.policyText);
    if (item.scenario) return runScenario(item, policy, api);
    const runtime = createRuntime({ policy, mode: 'enforce', enableLogging: false });
    return runtime.pre([{ role: 'user', content: item.prompt }], { sessionId: item.id });
  });
  writeFileSync(reportPath + '.tmp', JSON.stringify(report, null, 2) + '\n');
  renameSync(reportPath + '.tmp', reportPath);
  console.log(JSON.stringify(report.summary, null, 2));
  console.log(`Report: ${reportPath}`);
  verifyReport(report, context);
} catch (error) {
  rmSync(reportPath + '.tmp', { force: true });
  console.error(`Evaluation failed: ${error.message}`);
  process.exitCode = 1;
}

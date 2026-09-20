import { rmSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { coreRoot, getContext, evaluate, verifyReport } from './harness.mjs';

const reportPath = join(coreRoot, 'eval/report.json');
rmSync(reportPath, { force: true });
try {
  const { createRuntime, loadPolicyFromString } = await import('../../dist/index.js');
  const context = getContext();
  const report = await evaluate(context, async item => {
    // Fresh state per case prevents rate limits and previous prompts affecting decisions.
    const policy = loadPolicyFromString(context.policyText);
    const runtime = createRuntime({ policy, mode: 'enforce', enableLogging: false });
    return runtime.pre([{ role: 'user', content: item.prompt }], { sessionId: item.id });
  });
  writeFileSync(reportPath + '.tmp', JSON.stringify(report, null, 2) + '\n');
  renameSync(reportPath + '.tmp', reportPath);
  console.log(JSON.stringify(report.summary, null, 2));
  console.log(`Report: ${reportPath}`);
  verifyReport(report, context);
} catch (error) {
  console.error(`Evaluation failed: ${error.message}`);
  process.exitCode = 1;
}

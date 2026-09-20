import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { coreRoot, getContext, verifyReport } from './harness.mjs';

try {
  const report = JSON.parse(readFileSync(join(coreRoot, 'eval/report.json'), 'utf8'));
  verifyReport(report, getContext());
  console.log('Complete input-screening report meets configured targets.');
} catch (error) {
  console.error(`Report verification failed: ${error.message}`);
  process.exitCode = 1;
}

/**
 * Custom Vitest Reporter for AuthKit Test Suite.
 * Automatically logs structured test execution details (files, suites, individual test cases,
 * pass/fail statuses, assertion errors, and stack traces) into logs/%DATE%-tests.log.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { Reporter, Vitest } from 'vitest/node';

export default class TestLoggerReporter implements Reporter {
  private ctx!: Vitest;

  onInit(ctx: Vitest) {
    this.ctx = ctx;
  }

  onTestRunEnd() {
    const targetFiles = (this.ctx?.state?.getFiles() as any[]) || [];
    this.writeReport(targetFiles);
  }

  onFinished(files?: any[]) {
    const targetFiles =
      files && files.length > 0 ? files : (this.ctx?.state?.getFiles() as any[]) || [];
    this.writeReport(targetFiles);
  }

  onTestRunFinished(files?: any[]) {
    const targetFiles =
      files && files.length > 0 ? files : (this.ctx?.state?.getFiles() as any[]) || [];
    this.writeReport(targetFiles);
  }

  private getLogFilePath(): string {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const dateStr = `${year}-${month}-${day}`;
    const logsDir = path.resolve(process.cwd(), 'logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
    return path.join(logsDir, `${dateStr}-tests.log`);
  }

  private writeReport(files: any[]) {
    const logPath = this.getLogFilePath();
    const timestamp = new Date().toLocaleString();

    let output = `\n========================================================================\n`;
    output += `TEST SUITE EXECUTION REPORT - ${timestamp}\n`;
    output += `========================================================================\n\n`;

    if (!files || files.length === 0) {
      output += `No test files reported.\n\n`;
      fs.appendFileSync(logPath, output, 'utf8');
      return;
    }

    let totalTests = 0;
    let passedTests = 0;
    let failedTests = 0;
    let skippedTests = 0;

    for (const file of files) {
      const fileStatus = (file.result?.state ?? 'unknown').toUpperCase();
      output += `FILE: ${file.name} [STATUS: ${fileStatus}]\n`;

      if (file.tasks) {
        for (const task of file.tasks) {
          this.processTask(
            task,
            '  ',
            line => {
              output += line + '\n';
            },
            counts => {
              totalTests += counts.total;
              passedTests += counts.passed;
              failedTests += counts.failed;
              skippedTests += counts.skipped;
            }
          );
        }
      }
      output += `\n`;
    }

    output += `------------------------------------------------------------------------\n`;
    output += `SUMMARY: Total: ${totalTests} | Passed: ${passedTests} | Failed: ${failedTests} | Skipped: ${skippedTests}\n`;
    output += `========================================================================\n\n`;

    fs.appendFileSync(logPath, output, 'utf8');
  }

  private processTask(
    task: any,
    indent: string,
    print: (line: string) => void,
    updateCounts: (counts: {
      total: number;
      passed: number;
      failed: number;
      skipped: number;
    }) => void
  ) {
    if (task.type === 'suite') {
      print(`${indent}▼ SUITE: ${task.name}`);
      if (task.tasks) {
        for (const childTask of task.tasks) {
          this.processTask(childTask, `${indent}  `, print, updateCounts);
        }
      }
    } else if (task.type === 'test') {
      const state = task.result?.state ?? 'pending';
      const duration = task.result?.duration ? ` (${task.result.duration}ms)` : '';

      if (state === 'pass') {
        print(`${indent}✓ [PASS] ${task.name}${duration}`);
        updateCounts({ total: 1, passed: 1, failed: 0, skipped: 0 });
      } else if (state === 'fail') {
        print(`${indent}✗ [FAIL] ${task.name}${duration}`);
        updateCounts({ total: 1, passed: 0, failed: 1, skipped: 0 });

        if (task.result?.errors && task.result.errors.length > 0) {
          for (const err of task.result.errors) {
            const errObj = err as any;
            print(`${indent}    └─ ERROR: ${errObj.message || errObj}`);
            if (errObj.stack) {
              const formattedStack = String(errObj.stack)
                .split('\n')
                .slice(0, 8)
                .map((l: string) => `${indent}       ${l}`)
                .join('\n');
              print(`${indent}    └─ STACK:\n${formattedStack}`);
            }
          }
        }
      } else {
        print(`${indent}- [SKIPPED] ${task.name}`);
        updateCounts({ total: 1, passed: 0, failed: 0, skipped: 1 });
      }
    }
  }
}

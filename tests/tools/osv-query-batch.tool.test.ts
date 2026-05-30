/**
 * @fileoverview Tests for osv_query_batch tool.
 * @module tests/tools/osv-query-batch.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { osvQueryBatch } from '@/mcp-server/tools/definitions/osv-query-batch.tool.js';
import * as canvasModule from '@/services/canvas/canvas-accessor.js';
import * as osvApiModule from '@/services/osv-api/osv-api-service.js';

/** Build a minimal batch result row. */
function makeResult(
  name: string,
  ecosystem: string,
  version: string,
  vulns: Array<{
    id: string;
    summary: string;
    aliases: string[];
    severityLabel: string | null;
    fixedVersions: string[];
  }> = [],
  error: string | null = null,
) {
  return { name, ecosystem, version, vulns, error };
}

describe('osvQueryBatch', () => {
  const mockService = { queryBatch: vi.fn() };

  beforeEach(() => {
    vi.spyOn(osvApiModule, 'getOsvApiService').mockReturnValue(
      mockService as unknown as ReturnType<typeof osvApiModule.getOsvApiService>,
    );
    vi.spyOn(canvasModule, 'getCanvas').mockReturnValue(undefined);
    mockService.queryBatch.mockReset();
  });

  it('returns per-package results with summary stats', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500'],
          severityLabel: 'MODERATE',
          fixedVersions: ['4.17.21'],
        },
      ]),
      makeResult('express', 'npm', '4.18.0'),
    ]);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    expect(result.results).toHaveLength(2);
    expect(result.results[0]!.vulnerable).toBe(true);
    expect(result.results[0]!.vulnCount).toBe(1);
    expect(result.results[0]!.vulns[0]!.aliases).toEqual(['CVE-2020-28500']);
    expect(result.results[1]!.vulnerable).toBe(false);
    expect(result.summary.totalPackages).toBe(2);
    expect(result.summary.vulnerableCount).toBe(1);
    expect(result.summary.cleanCount).toBe(1);
    expect(result.summary.errorCount).toBe(0);
    expect(result.summary.totalVulns).toBe(1);
    expect(result.summary.worstSeverity).toBe('MODERATE');
  });

  it('throws invalid_ecosystem for unrecognized ecosystem strings', async () => {
    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'NPM', version: '4.17.1' }, // NPM != npm
      ],
    });
    await expect(osvQueryBatch.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_ecosystem' },
    });
    // Service should NOT have been called
    expect(mockService.queryBatch).not.toHaveBeenCalled();
  });

  it('handles per-package errors without aborting the batch', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [], 'Network error'),
      makeResult('express', 'npm', '4.18.0'),
    ]);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    expect(result.summary.errorCount).toBe(1);
    expect(result.results[0]!.error).toBe('Network error');
    expect(result.results[0]!.vulnerable).toBe(false);
    expect(result.results[1]!.error).toBeNull();
  });

  it('computes null worstSeverity when all vulns have null severity', async () => {
    mockService.queryBatch.mockResolvedValue([
      makeResult('pkg', 'npm', '1.0.0', [
        { id: 'PYSEC-1', summary: 'Test', aliases: [], severityLabel: null, fixedVersions: [] },
      ]),
    ]);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [{ name: 'pkg', ecosystem: 'npm', version: '1.0.0' }],
    });
    const result = await osvQueryBatch.handler(input, ctx);
    expect(result.summary.worstSeverity).toBeNull();
  });

  it('skips canvas when package count < 200 and no canvas_id', async () => {
    mockService.queryBatch.mockResolvedValue([makeResult('lodash', 'npm', '4.17.1')]);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [{ name: 'lodash', ecosystem: 'npm', version: '4.17.1' }],
    });
    const result = await osvQueryBatch.handler(input, ctx);
    expect(result.canvas_id).toBeUndefined();
  });

  it('partial success: mix of vulnerable, clean, and per-package error', async () => {
    // The service returns inline errors for per-package failures (not a throw).
    // This tests the tool-level aggregation of a realistic mixed batch.
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500'],
          severityLabel: 'HIGH',
          fixedVersions: ['4.17.21'],
        },
      ]),
      makeResult('express', 'npm', '4.18.0'), // clean
      makeResult('requests', 'PyPI', '2.28.0', [], 'Invalid ecosystem.'), // per-package error
    ]);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
        { name: 'requests', ecosystem: 'PyPI', version: '2.28.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    // Positional results
    expect(result.results[0]!.vulnerable).toBe(true);
    expect(result.results[0]!.error).toBeNull();
    expect(result.results[1]!.vulnerable).toBe(false);
    expect(result.results[1]!.error).toBeNull();
    expect(result.results[2]!.vulnerable).toBe(false);
    expect(result.results[2]!.error).toBeTruthy();

    // Summary aggregation
    expect(result.summary.totalPackages).toBe(3);
    expect(result.summary.vulnerableCount).toBe(1);
    expect(result.summary.cleanCount).toBe(1);
    expect(result.summary.errorCount).toBe(1);
    expect(result.summary.totalVulns).toBe(1);
    expect(result.summary.worstSeverity).toBe('HIGH');
  });

  it('aliases from fan-out are surfaced per-package in batch results', async () => {
    // Key correctness check: the parallel per-package query approach gives full records
    // (including aliases), unlike /v1/querybatch which only returns {id, modified}.
    mockService.queryBatch.mockResolvedValue([
      makeResult('lodash', 'npm', '4.17.1', [
        {
          id: 'GHSA-29mw-wpgm-hmr9',
          summary: 'Prototype Pollution',
          aliases: ['CVE-2020-28500', 'CVE-2020-28501'],
          severityLabel: 'MODERATE',
          fixedVersions: ['4.17.21'],
        },
        {
          id: 'GHSA-jf85-cpcp-j695',
          summary: 'Command Injection',
          aliases: ['CVE-2021-23337'],
          severityLabel: 'HIGH',
          fixedVersions: ['4.17.21'],
        },
      ]),
      makeResult('express', 'npm', '4.18.0'), // no aliases expected
    ]);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
        { name: 'express', ecosystem: 'npm', version: '4.18.0' },
      ],
    });
    const result = await osvQueryBatch.handler(input, ctx);

    const lodashResult = result.results[0]!;
    expect(lodashResult.vulns).toHaveLength(2);
    // First vuln has two CVE aliases
    expect(lodashResult.vulns[0]!.aliases).toContain('CVE-2020-28500');
    expect(lodashResult.vulns[0]!.aliases).toContain('CVE-2020-28501');
    // Second vuln also has an alias
    expect(lodashResult.vulns[1]!.aliases).toContain('CVE-2021-23337');
    // Clean package has no vulns at all
    expect(result.results[1]!.vulns).toHaveLength(0);

    // worstSeverity from two findings
    expect(result.summary.worstSeverity).toBe('HIGH');
    expect(result.summary.totalVulns).toBe(2);
  });

  it('triggers DataCanvas spillover when package count reaches 200', async () => {
    const packages = Array.from({ length: 200 }, (_, i) => ({
      name: `pkg${i}`,
      ecosystem: 'npm',
      version: '1.0.0',
    }));

    // All clean — just need enough packages to cross the threshold
    mockService.queryBatch.mockResolvedValue(
      packages.map((p) => makeResult(p.name, p.ecosystem, p.version)),
    );

    const CANVAS_ID = 'canvas-abc123';
    const mockRegisterTable = vi
      .fn()
      .mockResolvedValue({ rowCount: 200, tableName: 'osv_batch_results', columns: [] });
    const mockInstance = { canvasId: CANVAS_ID, registerTable: mockRegisterTable };
    const mockAcquire = vi.fn().mockResolvedValue(mockInstance);
    vi.spyOn(canvasModule, 'getCanvas').mockReturnValue({
      acquire: mockAcquire,
    } as unknown as ReturnType<typeof canvasModule.getCanvas>);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({ packages });
    const result = await osvQueryBatch.handler(input, ctx);

    // Canvas was acquired and table was registered
    expect(mockAcquire).toHaveBeenCalledOnce();
    expect(mockRegisterTable).toHaveBeenCalledWith('osv_batch_results', expect.any(Array));
    // Registered rows are one-per-package
    const registeredRows = mockRegisterTable.mock.calls[0]![1] as unknown[];
    expect(registeredRows).toHaveLength(200);
    // canvas_id is returned
    expect(result.canvas_id).toBe(CANVAS_ID);
    expect(result.summary.totalPackages).toBe(200);
  });

  it('uses provided canvas_id when explicitly passed, even for small batches', async () => {
    mockService.queryBatch.mockResolvedValue([makeResult('lodash', 'npm', '4.17.1')]);

    const CANVAS_ID = 'existing-canvas';
    const mockRegisterTable = vi
      .fn()
      .mockResolvedValue({ rowCount: 1, tableName: 'osv_batch_results', columns: [] });
    const mockInstance = { canvasId: CANVAS_ID, registerTable: mockRegisterTable };
    const mockAcquire = vi.fn().mockResolvedValue(mockInstance);
    vi.spyOn(canvasModule, 'getCanvas').mockReturnValue({
      acquire: mockAcquire,
    } as unknown as ReturnType<typeof canvasModule.getCanvas>);

    const ctx = createMockContext({ errors: osvQueryBatch.errors });
    const input = osvQueryBatch.input.parse({
      packages: [{ name: 'lodash', ecosystem: 'npm', version: '4.17.1' }],
      canvas_id: CANVAS_ID,
    });
    const result = await osvQueryBatch.handler(input, ctx);

    // Canvas is acquired with the provided ID
    expect(mockAcquire).toHaveBeenCalledWith(CANVAS_ID, ctx);
    expect(result.canvas_id).toBe(CANVAS_ID);
  });

  it('rejects empty packages array at schema parse', () => {
    expect(() => osvQueryBatch.input.parse({ packages: [] })).toThrow();
  });

  it('rejects packages array over 1000 at schema parse', () => {
    const pkgs = Array.from({ length: 1001 }, (_, i) => ({
      name: `pkg${i}`,
      ecosystem: 'npm',
      version: '1.0.0',
    }));
    expect(() => osvQueryBatch.input.parse({ packages: pkgs })).toThrow();
  });

  it('formats batch output with vulnerable packages section', () => {
    const output = {
      results: [
        {
          name: 'lodash',
          ecosystem: 'npm',
          version: '4.17.1',
          vulnerable: true,
          error: null,
          vulnCount: 1,
          vulns: [
            {
              id: 'GHSA-29mw-wpgm-hmr9',
              summary: 'Prototype Pollution',
              aliases: ['CVE-2020-28500'],
              severityLabel: 'MODERATE',
              fixedVersions: ['4.17.21'],
            },
          ],
        },
        {
          name: 'express',
          ecosystem: 'npm',
          version: '4.18.0',
          vulnerable: false,
          error: null,
          vulnCount: 0,
          vulns: [],
        },
      ],
      summary: {
        totalPackages: 2,
        vulnerableCount: 1,
        cleanCount: 1,
        errorCount: 0,
        totalVulns: 1,
        worstSeverity: 'MODERATE',
      },
    };
    const blocks = osvQueryBatch.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('MODERATE');
    expect(text).toContain('lodash');
    expect(text).toContain('CVE-2020-28500');
    expect(text).toContain('4.17.21');
    expect(text).toContain('GHSA-29mw-wpgm-hmr9');
  });

  it('formats canvas_id in output when present', () => {
    const output = {
      results: [],
      summary: {
        totalPackages: 0,
        vulnerableCount: 0,
        cleanCount: 0,
        errorCount: 0,
        totalVulns: 0,
        worstSeverity: null,
      },
      canvas_id: 'abc1234567',
    };
    const blocks = osvQueryBatch.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('abc1234567');
    expect(text).toContain('osv_batch_results');
  });
});

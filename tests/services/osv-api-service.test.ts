/**
 * @fileoverview Tests for OsvApiService — HTTP fetch, normalization, and error handling.
 * @module tests/services/osv-api-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OsvApiService } from '@/services/osv-api/osv-api-service.js';

// ---------------------------------------------------------------------------
// Fixture responses
// ---------------------------------------------------------------------------

const QUERY_RESPONSE_WITH_VULN = {
  vulns: [
    {
      id: 'GHSA-29mw-wpgm-hmr9',
      summary: 'Prototype Pollution in lodash',
      details: 'lodash before 4.17.21 allows prototype pollution.',
      aliases: ['CVE-2020-28500'],
      published: '2022-01-06T20:30:46Z',
      modified: '2025-09-29T21:12:31Z',
      schema_version: '1.7.3',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }],
      database_specific: {
        severity: 'MODERATE',
        cwe_ids: ['CWE-1333'],
      },
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash' },
          ranges: [
            {
              type: 'SEMVER',
              events: [{ introduced: '0' }, { fixed: '4.17.21' }],
            },
          ],
        },
      ],
      references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-28500' }],
    },
  ],
};

const EMPTY_QUERY_RESPONSE = {}; // OSV returns {} (not { vulns: [] }) when nothing found

const INVALID_ECOSYSTEM_RESPONSE = { code: 3, message: 'Invalid ecosystem.' };

const VULN_DETAIL_RESPONSE = QUERY_RESPONSE_WITH_VULN.vulns[0]!;

const VULN_NOT_FOUND_RESPONSE = { code: 5, message: 'Bug not found.' };

// ---------------------------------------------------------------------------
// Fetch mock helper
// ---------------------------------------------------------------------------

function mockFetch(responses: Array<{ status: number; body: unknown }>) {
  let callIndex = 0;
  return vi.fn().mockImplementation(() => {
    const res = responses[callIndex++];
    if (!res) throw new Error('Unexpected fetch call');
    return Promise.resolve({
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      text: () => Promise.resolve(JSON.stringify(res.body)),
    });
  });
}

describe('OsvApiService', () => {
  let service: OsvApiService;

  beforeEach(() => {
    service = new OsvApiService(5000);
    vi.restoreAllMocks();
  });

  describe('queryPackage', () => {
    it('returns normalized vulns for a vulnerable package', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: QUERY_RESPONSE_WITH_VULN }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'npm', '4.17.1', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;
      expect(result.vulns).toHaveLength(1);
      const vuln = result.vulns[0]!;
      expect(vuln.id).toBe('GHSA-29mw-wpgm-hmr9');
      expect(vuln.aliases).toEqual(['CVE-2020-28500']);
      expect(vuln.severityLabel).toBe('MODERATE');
      expect(vuln.fixedVersions).toEqual(['4.17.21']);
      expect(vuln.cweIds).toEqual(['CWE-1333']);
    });

    it('returns empty vulns array when OSV returns {} (no vulns key)', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: EMPTY_QUERY_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'npm', '99.99.99', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;
      expect(result.vulns).toHaveLength(0);
    });

    it('returns invalid: true for HTTP 400 (invalid ecosystem)', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 400, body: INVALID_ECOSYSTEM_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'NPM', '4.17.1', ctx);

      expect(result.invalid).toBe(true);
      if (!result.invalid) return;
      expect(result.message).toBe('Invalid ecosystem.');
    });

    it('extracts affected ranges correctly', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: QUERY_RESPONSE_WITH_VULN }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('lodash', 'npm', '4.17.1', ctx);

      if (result.invalid) return;
      const vuln = result.vulns[0]!;
      expect(vuln.affectedRanges).toHaveLength(1);
      expect(vuln.affectedRanges[0]!.rangeType).toBe('SEMVER');
      expect(vuln.affectedRanges[0]!.introduced).toBe('0');
      expect(vuln.affectedRanges[0]!.fixed).toBe('4.17.21');
    });
  });

  describe('getVulnerability', () => {
    it('returns normalized full record for a known ID', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: VULN_DETAIL_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.getVulnerability('GHSA-29mw-wpgm-hmr9', ctx);

      expect(result).not.toBeNull();
      expect(result!.id).toBe('GHSA-29mw-wpgm-hmr9');
      expect(result!.aliases).toEqual(['CVE-2020-28500']);
    });

    it('returns null for HTTP 404 (vuln not found)', async () => {
      vi.stubGlobal('fetch', mockFetch([{ status: 404, body: VULN_NOT_FOUND_RESPONSE }]));
      const ctx = createMockContext();
      const result = await service.getVulnerability('GHSA-xxxx-xxxx-xxxx', ctx);
      expect(result).toBeNull();
    });
  });

  describe('queryBatch', () => {
    it('returns partial-success results across packages', async () => {
      vi.stubGlobal(
        'fetch',
        mockFetch([
          { status: 200, body: QUERY_RESPONSE_WITH_VULN }, // lodash
          { status: 200, body: EMPTY_QUERY_RESPONSE }, // express (clean)
          { status: 400, body: INVALID_ECOSYSTEM_RESPONSE }, // bad ecosystem
        ]),
      );

      const ctx = createMockContext();
      const results = await service.queryBatch(
        [
          { name: 'lodash', ecosystem: 'npm', version: '4.17.1' },
          { name: 'express', ecosystem: 'npm', version: '4.18.0' },
          { name: 'requests', ecosystem: 'NPM', version: '2.0.0' },
        ],
        ctx,
      );

      expect(results).toHaveLength(3);
      expect(results[0]!.vulns).toHaveLength(1);
      expect(results[0]!.error).toBeNull();
      expect(results[1]!.vulns).toHaveLength(0);
      expect(results[1]!.error).toBeNull();
      // Third package got invalid ecosystem error surfaced inline
      expect(results[2]!.vulns).toHaveLength(0);
      expect(results[2]!.error).toBeTruthy();
    });

    it('surfaces CVE aliases in batch brief from full per-package query', async () => {
      // /v1/querybatch returns only {id, modified} — no aliases.
      // The implementation uses parallel /v1/query calls to get full records including aliases.
      // This test verifies aliases flow through queryBatch → toBrief.
      vi.stubGlobal(
        'fetch',
        mockFetch([
          { status: 200, body: QUERY_RESPONSE_WITH_VULN }, // lodash with CVE alias
        ]),
      );

      const ctx = createMockContext();
      const results = await service.queryBatch(
        [{ name: 'lodash', ecosystem: 'npm', version: '4.17.1' }],
        ctx,
      );

      expect(results[0]!.vulns).toHaveLength(1);
      expect(results[0]!.vulns[0]!.aliases).toEqual(['CVE-2020-28500']);
      expect(results[0]!.error).toBeNull();
    });
  });

  describe('normalization', () => {
    it('normalizes lastAffected range event (no fix exists)', async () => {
      const responseWithLastAffected = {
        vulns: [
          {
            id: 'RUSTSEC-2024-0001',
            summary: 'No fix available',
            details: '',
            aliases: [],
            published: '2024-01-01T00:00:00Z',
            modified: '2024-01-10T00:00:00Z',
            schema_version: '1.7.3',
            severity: [],
            affected: [
              {
                package: { name: 'unsafe-lib', ecosystem: 'crates.io' },
                ranges: [
                  {
                    type: 'SEMVER',
                    events: [{ introduced: '0' }, { last_affected: '1.2.3' }],
                  },
                ],
              },
            ],
            references: [],
          },
        ],
      };

      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: responseWithLastAffected }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('unsafe-lib', 'crates.io', '1.2.0', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;

      const vuln = result.vulns[0]!;
      expect(vuln.fixedVersions).toHaveLength(0); // no fix
      const range = vuln.affectedRanges[0]!;
      expect(range.lastAffected).toBe('1.2.3');
      expect(range.fixed).toBeUndefined();
      expect(range.introduced).toBe('0');
    });

    it('handles sparse upstream vuln with no affected, no severity, no aliases', async () => {
      const sparseResponse = {
        vulns: [
          {
            id: 'PYSEC-2024-999',
            summary: 'Sparse record',
            // No: details, aliases, severity, affected, references, database_specific, schema_version
          },
        ],
      };

      vi.stubGlobal('fetch', mockFetch([{ status: 200, body: sparseResponse }]));
      const ctx = createMockContext();
      const result = await service.queryPackage('some-pkg', 'PyPI', '1.0.0', ctx);

      expect(result.invalid).toBe(false);
      if (result.invalid) return;

      const vuln = result.vulns[0]!;
      expect(vuln.id).toBe('PYSEC-2024-999');
      expect(vuln.aliases).toEqual([]);
      expect(vuln.severity).toEqual([]);
      expect(vuln.severityLabel).toBeNull();
      expect(vuln.affectedRanges).toEqual([]);
      expect(vuln.fixedVersions).toEqual([]);
      expect(vuln.cweIds).toEqual([]);
      expect(vuln.references).toEqual([]);
      expect(vuln.details).toBe('');
      expect(vuln.schemaVersion).toBe('');
    });
  });
});

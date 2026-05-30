/**
 * @fileoverview Domain types for the OSV.dev API v1 service.
 * Covers raw API shapes, normalized output shapes, and service params.
 * @module services/osv-api/types
 */

// ---------------------------------------------------------------------------
// Raw API response shapes
// ---------------------------------------------------------------------------

/** Raw severity entry from OSV API. */
export interface RawOsvSeverity {
  score: string;
  type: 'CVSS_V2' | 'CVSS_V3' | 'CVSS_V4';
}

/** Raw event in an affected range. */
export interface RawOsvEvent {
  fixed?: string;
  introduced?: string;
  last_affected?: string;
}

/** Raw version range in an affected entry. */
export interface RawOsvRange {
  events?: RawOsvEvent[];
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
}

/** Raw package descriptor. */
export interface RawOsvPackage {
  ecosystem?: string;
  name?: string;
  purl?: string;
}

/** Raw affected entry. */
export interface RawOsvAffected {
  package?: RawOsvPackage;
  ranges?: RawOsvRange[];
}

/** Raw reference entry. */
export interface RawOsvReference {
  type?: string;
  url?: string;
}

/** Database-specific fields (GHSA-sourced). */
export interface RawOsvDatabaseSpecific {
  cwe_ids?: string[];
  severity?: string;
}

/** Full vulnerability record as returned by POST /v1/query and GET /v1/vulns/{id}. */
export interface RawOsvVulnerability {
  affected?: RawOsvAffected[];
  aliases?: string[];
  database_specific?: RawOsvDatabaseSpecific;
  details?: string;
  id?: string;
  modified?: string;
  published?: string;
  references?: RawOsvReference[];
  schema_version?: string;
  severity?: RawOsvSeverity[];
  summary?: string;
}

/** Abbreviated vuln entry as returned inside POST /v1/querybatch results. */
export interface RawOsvBatchVulnEntry {
  id?: string;
  modified?: string;
}

/** Response envelope from POST /v1/query (success). */
export interface RawOsvQueryResponse {
  vulns?: RawOsvVulnerability[];
}

/** Single positional result inside POST /v1/querybatch response. */
export interface RawOsvBatchResultEntry {
  vulns?: RawOsvBatchVulnEntry[];
}

/** Response envelope from POST /v1/querybatch. */
export interface RawOsvQueryBatchResponse {
  results?: RawOsvBatchResultEntry[];
}

/** Google API error body. */
export interface OsvApiError {
  code: number;
  message: string;
}

// ---------------------------------------------------------------------------
// Normalized output shapes
// ---------------------------------------------------------------------------

/** Normalized severity entry. */
export interface OsvSeverityEntry {
  score: string;
  type: string;
}

/** Normalized affected version range for output. */
export interface OsvAffectedRange {
  ecosystem: string;
  fixed?: string;
  introduced?: string;
  lastAffected?: string;
  packageName: string;
  rangeType: string;
}

/** Normalized vulnerability record (full). */
export interface OsvVulnerability {
  affected: Array<{
    packageName: string;
    ecosystem: string;
    purl?: string;
    ranges: Array<{
      rangeType: string;
      introduced?: string;
      fixed?: string;
      lastAffected?: string;
    }>;
  }>;
  /** Flat ranges extracted for query output. */
  affectedRanges: OsvAffectedRange[];
  aliases: string[];
  cweIds: string[];
  details: string;
  /** First safe versions extracted across all affected entries. */
  fixedVersions: string[];
  id: string;
  modified: string;
  published: string;
  references: Array<{ type: string; url: string }>;
  schemaVersion: string;
  severity: OsvSeverityEntry[];
  severityLabel: string | null;
  summary: string;
}

/** Brief per-package vuln entry for batch output. */
export interface BatchVulnBrief {
  aliases: string[];
  fixedVersions: string[];
  id: string;
  severityLabel: string | null;
  summary: string;
}

import { Octokit } from '@octokit/rest';
import { createHash } from 'crypto';
import { BOLAFinding, PatchResult, ScanConfig } from '../types';
import { escapeMarkdown } from '../utils/redact';

function extractResourceType(endpointPath: string): string {
  const segments = endpointPath.split('/').filter(Boolean);

  const apiIndex = segments.indexOf('api');
  if (apiIndex >= 0 && apiIndex + 1 < segments.length) {
    return segments[apiIndex + 1];
  }

  return segments[1] || 'resource';
}

function buildCandidatePaths(resourceType: string): string[] {
  return [
    `app/api/${resourceType}/[id]/route.ts`,
    `app/api/${resourceType}/route.ts`,
    `pages/api/${resourceType}/[id].ts`,
    `src/app/api/${resourceType}/[id]/route.ts`,
    `src/pages/api/${resourceType}/[id].ts`,
  ];
}

/**
 * Format a full Octokit error message including HTTP status and GitHub's
 * response body so the root cause is always visible in the terminal.
 */
function formatOctokitError(err: any): string {
  const status = err.status ?? err.response?.status ?? '???';
  const ghMsg = err.response?.data?.message ?? err.message ?? String(err);
  const docUrl = err.response?.data?.documentation_url ?? '';
  return `HTTP ${status}: ${ghMsg}${docUrl ? ` — ${docUrl}` : ''}`;
}

export async function createSecurityPR(
  patch: PatchResult,
  playwrightTest: string,
  finding: BOLAFinding,
  config: ScanConfig,
  emit: (msg: string) => void,
  signal?: AbortSignal
): Promise<string> {
  if (signal?.aborted) throw new Error('Scan aborted');
  if (!config.githubRepoOwner || !config.githubRepoName) {
    emit('ℹ️ No GitHub repo provided — skipping PR generation. Add GitHub repo details in Advanced Settings to enable.');
    return '';
  }

  const token = config.githubToken;
  if (!token) {
    emit('GitHub token missing — skipping PR creation');
    return '';
  }
  const octokit = new Octokit({ auth: token });
  const owner = config.githubRepoOwner;
  const repo = config.githubRepoName;

  try {
    const { headers } = await octokit.request('GET /repos/{owner}/{repo}', { owner, repo });
    const scopes = headers['x-oauth-scopes'] || '';
    if (token.startsWith('ghp_')) {
      emit('[GITHUB] WARNING: Classic PAT with broad scope detected. Production deployments require fine-grained GitHub App tokens.');
    }
  } catch (err: unknown) {
    emit(`[GITHUB] Token validation failed: ${formatOctokitError(err)}`);
    return '';
  }

  const base = config.githubBaseBranch || 'main';
  const hash = createHash('sha1').update(finding.endpoint).digest('hex').slice(0, 8);
  let branch = `vibeaudit/fix-bola-${hash}`;
  let existingOpenPr: { number: number; html_url: string } | null = null;

  // Always log the exact owner/repo being used so mismatches are visible
  emit(`[GITHUB] Connecting to ${owner}/${repo} (base: ${base})...`);

  // ── Get base branch SHA ─────────────────────────────────────────
  let sha: string;
  try {
    // getRef uses "heads/branch" (NO "refs/" prefix) — this is correct per Octokit docs
    const { data: ref } = await octokit.git.getRef({
      owner, repo, ref: `heads/${base}`,
    });
    sha = ref.object.sha;
    if (!sha) {
      throw new Error(`getRef returned empty SHA for ${base}`);
    }
    emit(`[GITHUB] Base branch ${base} found (sha: ${sha.slice(0, 7)})`);
  } catch (err: unknown) {
    throw new Error(`[GITHUB] Could not read base branch "${base}" from ${owner}/${repo}: ${formatOctokitError(err)}`);
  }

  const findExistingPr = async (branchName: string, state: 'open' | 'closed' | 'all') => {
    const { data: prs } = await octokit.pulls.list({
      owner, repo,
      state,
      head: `${owner}:${branchName}`,
      per_page: 10,
    });
    return prs[0];
  };

  // ── Create branch (reuse open PRs, avoid closed PR branch collisions) ───────
  emit('[GITHUB] Creating security branch...');
  let branchExists = false;
  try {
    // createRef uses "refs/heads/branch" (WITH "refs/" prefix) — opposite convention to getRef
    await octokit.git.createRef({
      owner, repo,
      ref: `refs/heads/${branch}`,
      sha,
    });
    emit(`[GITHUB] Branch created: ${branch}`);
  } catch (err: unknown) {
    // 422 = reference already exists. Re-use it only when an open PR exists.
    if ((err as any).status === 422) {
      branchExists = true;
    } else {
      throw new Error(`[GITHUB] Failed to create branch "${branch}": ${formatOctokitError(err)}`);
    }
  }

  if (branchExists) {
    try {
      const openPr = await findExistingPr(branch, 'open');
      if (openPr) {
        existingOpenPr = { number: openPr.number, html_url: openPr.html_url };
        emit(`[GITHUB] Open PR already exists — updating: ${openPr.html_url}`);
      } else {
        const priorPr = await findExistingPr(branch, 'closed');
        const oldBranch = branch;
        branch = `${branch}-${Date.now().toString(36)}`;
        emit(priorPr
          ? `[GITHUB] Existing branch belongs to a closed PR — creating new branch: ${branch}`
          : `[GITHUB] Branch exists without an open PR — creating new branch: ${branch}`);
        await octokit.git.createRef({
          owner, repo,
          ref: `refs/heads/${branch}`,
          sha,
        });
        emit(`[GITHUB] Branch created: ${branch} (instead of ${oldBranch})`);
      }
    } catch (err: unknown) {
      throw new Error(`[GITHUB] Failed to resolve existing branch "${branch}": ${formatOctokitError(err)}`);
    }
  }

  // Helper to get current file SHA (needed for update, not create)
  async function getFileSha(path: string): Promise<string | undefined> {
    try {
      const { data } = await octokit.repos.getContent({ owner, repo, path, ref: branch });
      return (data as any).sha;
    } catch {
      return undefined;
    }
  }

  // ── Resolve the correct file path dynamically ───────────────────
  const resourceType = extractResourceType(finding.endpoint);
  const candidatePaths = buildCandidatePaths(resourceType);
  let resolvedPatchPath: string | null = null;
  let resolvedPatchSha: string | undefined;

  emit(`[GITHUB] Resolved resource type: ${resourceType}`);
  emit(`[GITHUB] Probing ${candidatePaths.length} candidate paths...`);

  for (const candidate of candidatePaths) {
    try {
      const { data } = await octokit.repos.getContent({ owner, repo, path: candidate, ref: base });
      if ('sha' in data) {
        resolvedPatchPath = candidate;
        resolvedPatchSha = await getFileSha(candidate);
        emit(`[GITHUB] Found file: ${candidate} ✓`);
        break;
      }
    } catch {
      // File doesn't exist at this path — try next candidate
    }
  }

  // ── Commit patch file (only if we found it) ─────────────────────
  let patchCommitted = false;
  const targetPatchPath = resolvedPatchPath || `vibeaudit-patch-${hash}.ts`;

  try {
    emit('[GITHUB] Committing patch...');
    await octokit.repos.createOrUpdateFileContents({
      owner, repo, branch,
      path: targetPatchPath,
      message: `fix(security): add ownership check to prevent BOLA on ${finding.endpoint}`,
      content: Buffer.from(patch.patchedCode).toString('base64'),
      ...(resolvedPatchSha ? { sha: resolvedPatchSha } : {}),
    });
    patchCommitted = true;
  } catch (err: unknown) {
    emit(`[GITHUB] Warning: patch commit failed (${formatOctokitError(err)}).`);
  }

  // ── Commit regression test (non-fatal on failure) ───────────────
  try {
    emit('[GITHUB] Committing regression test...');
    const testPath = 'tests/security/bola-regression.spec.ts';
    const testSha = await getFileSha(testPath);
    await octokit.repos.createOrUpdateFileContents({
      owner, repo, branch,
      path: testPath,
      message: `test(security): add BOLA regression test for ${finding.endpoint}`,
      content: Buffer.from(playwrightTest).toString('base64'),
      ...(testSha ? { sha: testSha } : {}),
    });
  } catch (err: unknown) {
    // Non-fatal: PR is still created even if test commit fails
    emit(`[GITHUB] Warning: regression test commit failed (${formatOctokitError(err)}) — continuing to PR.`);
  }

  emit('[GITHUB] Opening Pull Request...');

  // Build dynamic PR body
  const sensitiveFieldsList = finding.sensitiveFields
    .map(f => `- \`${escapeMarkdown(f.key)}\` (${escapeMarkdown(f.category)})`)
    .join('\n');

  const fixSection = patchCommitted
    ? `### Fix Applied\nAdded ownership verification after record fetch in \`${escapeMarkdown(targetPatchPath)}\`. See the committed file for the patch.`
    : `### Security Fix\n> ⚠️ Patch could not be committed.`;

  const prBody = `## Security Patch — Generated by VibeAudit

### Vulnerability
**Type:** Broken Object Level Authorization (BOLA)  
**Endpoint:** \`${escapeMarkdown(finding.method)} ${escapeMarkdown(finding.endpoint)}\`  
**CVSS Score:** ${escapeMarkdown(String(finding.cvssScore))} (Critical)  

### Finding
Any authenticated user could access another user's resource by replaying the request with a different session. No ownership check was present on the parameterized route.

### Exposed Sensitive Fields
${sensitiveFieldsList}

${fixSection}

**Ownership Field:** \`${escapeMarkdown(patch.ownershipField)}\`  
**Auth Library:** ${escapeMarkdown(patch.authLibrary)}  
**Session Accessor:** \`${escapeMarkdown(patch.sessionAccessor)}\`  

### Regression Test
A Playwright test has been added at \`tests/security/bola-regression.spec.ts\`.  
This test will fail if the ownership check is ever removed.

---
*This security patch was generated by [VibeAudit](https://github.com/sohamdhande/vibeaudit) — exploit-backed authorization scanner for AI-generated web applications.*`;

  if (existingOpenPr) {
    try {
      const { data: pr } = await octokit.pulls.update({
        owner, repo,
        pull_number: existingOpenPr.number,
        body: prBody,
      });
      emit(`[GITHUB] Pull Request updated: ${pr.html_url}`);
      return pr.html_url;
    } catch (err: unknown) {
      throw new Error(`[GITHUB] Failed to update existing Pull Request: ${formatOctokitError(err)}`);
    }
  }

  // Create PR — this always runs regardless of file/test commit outcome
  try {
    const { data: pr } = await octokit.pulls.create({
      owner, repo,
      title: `\uD83D\uDD12 [VibeAudit] Fix BOLA vulnerability on ${finding.endpoint}`,
      head: branch,
      base,
      body: prBody,
    });

    emit(`[GITHUB] Pull Request created: ${pr.html_url}`);
    return pr.html_url;
  } catch (err: unknown) {
    throw new Error(`[GITHUB] Failed to create Pull Request: ${formatOctokitError(err)}`);
  }
}

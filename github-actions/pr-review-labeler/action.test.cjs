const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const actionScript = new AsyncFunction('github', 'context', 'core', 'process', embeddedScript(path.join(__dirname, 'action.yml')));
const core = {info() {}};
const reviewLabels = ['ready for review', 'ready for final review', 'ready for merge', 'changes required'];
const env = {
  PULL_REQUEST_NUMBER: '17', REQUIRED_APPROVALS: '2', CURRENT_HEAD_ONLY: 'true', CREATE_LABELS: 'true',
  READY_FOR_REVIEW_LABEL: reviewLabels[0], READY_FOR_FINAL_REVIEW_LABEL: reviewLabels[1],
  READY_FOR_MERGE_LABEL: reviewLabels[2], CHANGES_REQUIRED_LABEL: reviewLabels[3],
  READY_FOR_REVIEW_COLOR: '0E8A16', READY_FOR_FINAL_REVIEW_COLOR: 'FBCA04',
  READY_FOR_MERGE_COLOR: '1D76DB', CHANGES_REQUIRED_COLOR: 'D93F0B',
};
const scenarios = [
  {name: 'unreviewed PR awaits its first review', expected: 'ready for review'},
  {name: 'one approval awaits final review', reviews: [review('alice')], expected: 'ready for final review'},
  {name: 'two eligible approvals are ready to merge', reviews: [review('alice'), review('bob')], expected: 'ready for merge'},
  {name: 'three-approval policy is respected', approvals: '3', reviews: [review('alice'), review('bob')], expected: 'ready for final review'},
  {name: 'three approvals satisfy the higher policy', approvals: '3', reviews: [review('alice'), review('bob'), review('carol')], expected: 'ready for merge'},
  {name: 'one-approval policy is respected', approvals: '1', reviews: [review('alice')], expected: 'ready for merge'},
  {name: 'GitHub review requirement overrides approval count', decision: 'REVIEW_REQUIRED', reviews: [review('alice'), review('bob')], expected: 'ready for final review'},
  {name: 'GitHub changes-requested decision takes precedence', decision: 'CHANGES_REQUESTED', expected: 'changes required'},
  {name: 'changes requested survive a new head', reviews: [review('alice', 'CHANGES_REQUESTED', 'old')], expected: 'changes required'},
  {name: 'non-current approvals do not count', reviews: [review('alice', 'APPROVED', 'old')], expected: 'ready for review'},
  {name: 'read-only reviewer does not count', permissions: {alice: 'read'}, reviews: [review('alice')], expected: 'ready for review'},
  {name: 'read-only changes requested do not block', permissions: {alice: 'read'}, reviews: [review('alice', 'CHANGES_REQUESTED')], expected: 'ready for review'},
  {name: 'author review does not count', reviews: [review('author')], expected: 'ready for review'},
  {name: 'multiple reviews by one person count once', reviews: [review('alice'), review('alice', 'APPROVED', 'head', 2)], expected: 'ready for final review'},
  {name: 'comment does not replace an approval', reviews: [review('alice'), review('alice', 'COMMENTED', 'head', 2)], expected: 'ready for final review'},
  {name: 'dismissal clears the previous opinion', reviews: [review('alice', 'CHANGES_REQUESTED'), review('alice', 'DISMISSED', 'head', 2)], expected: 'ready for review'},
  {name: 'later approval replaces requested changes', reviews: [review('alice', 'CHANGES_REQUESTED'), review('alice', 'APPROVED', 'head', 2)], expected: 'ready for final review'},
  {name: 'draft removes canonical and legacy review labels', draft: true, labels: [...reviewLabels, 'ready for 2nd review', 'review in progress', 'keep-open'], expected: null},
  {name: 'legacy review states are replaced', labels: ['review in progress', 'ready for 2nd review', 'keep-open'], expected: 'ready for review'},
  {name: 'unchanged labels cause no PR writes', labels: ['ready for review', 'keep-open'], expected: 'ready for review', writes: 0},
  {name: 'closed PR from a queued refresh is untouched', state: 'closed', labels: ['ready for merge', 'keep-open'], expected: 'ready for merge', writes: 0},
  {name: 'missing label definitions are created', missingLabels: true, expected: 'ready for review', created: 4},
  {name: 'stale event uses live head', eventHead: 'old', reviews: [review('alice', 'APPROVED', 'head')], expected: 'ready for final review'},
  {name: 'permission lookup failure does not relabel PR', permissionError: 503, reviews: [review('alice')], labels: ['ready for merge'], error: /permission lookup failed/},
  {name: 'invalid approval input fails before mutation', approvals: '0', error: /positive integer/},
];

for (const scenario of scenarios) {
  test(scenario.name, async () => {
    // Arrange: keep the API boundary in memory so the production decision code runs unchanged.
    const state = fixture(scenario);
    const run = () => actionScript(state.github, state.context, core, {env: {...env, REQUIRED_APPROVALS: scenario.approvals || '2'}});
    // Act and assert.
    if (scenario.error) {
      await assert.rejects(run, scenario.error);
      assert.equal(state.writes.length, 0);
      return;
    }
    await run();
    const managed = [...state.labels].filter(label => reviewLabels.includes(label));
    assert.deepEqual(managed, scenario.expected ? [scenario.expected] : []);
    if (scenario.labels?.includes('keep-open')) assert(state.labels.has('keep-open'));
    if (scenario.state !== 'closed') {
      assert(!state.labels.has('review in progress'));
      assert(!state.labels.has('ready for 2nd review'));
    }
    if (scenario.writes !== undefined) assert.equal(state.writes.length, scenario.writes);
    if (scenario.created !== undefined) assert.equal(state.created.length, scenario.created);
  });
}

const workflowDir = path.resolve(__dirname, '../../.github/workflows');
const targetScript = new AsyncFunction('github', 'context', embeddedScript(path.join(workflowDir, 'pull-request-review-labels.yml')));
for (const scenario of [
  {name: 'PR event selects only its PR', payload: {pull_request: {number: 17}}, pulls: [], expected: [17], calls: 0},
  {name: 'manual refresh selects all paginated open PRs', payload: {}, pulls: [{number: 17}, {number: 21}], expected: [17, 21], calls: 1},
  {name: 'empty repository emits no matrix jobs', payload: {}, pulls: [], expected: [], calls: 1},
]) {
  test(scenario.name, async () => {
    let calls = 0;
    const github = {rest: {pulls: {list() {}}}, paginate: async (_method, args) => {
      calls++;
      assert.equal(args.state, 'open');
      assert.equal(args.per_page, 100);
      return scenario.pulls;
    }};
    const numbers = await targetScript(github, {repo: {owner: 'example', repo: 'example'}, payload: scenario.payload});
    assert.deepEqual(numbers, scenario.expected);
    assert.equal(calls, scenario.calls);
  });
}

const staleScript = new AsyncFunction('github', 'context', 'core', embeddedScript(path.join(workflowDir, 'stale-pull-requests.yml')));
for (const scenario of [
  {name: 'stale dry run does not create missing labels', eventName: 'workflow_dispatch', inputs: {dry_run: 'true'}, expected: 0},
  {name: 'omitted stale dry-run input is non-mutating', eventName: 'workflow_dispatch', inputs: {}, expected: 0},
  {name: 'live stale run creates required labels', eventName: 'schedule', inputs: {}, expected: 2},
  {name: 'explicit live manual stale run creates labels', eventName: 'workflow_dispatch', inputs: {dry_run: 'false'}, expected: 2},
]) {
  test(scenario.name, async () => {
    const created = [];
    const github = {rest: {issues: {
      getLabel: async () => {throw Object.assign(new Error('missing'), {status: 404});},
      createLabel: async label => {created.push(label.name);},
    }}};
    await staleScript(github, {repo: {owner: 'example', repo: 'example'}, eventName: scenario.eventName, payload: {inputs: scenario.inputs}}, core);
    assert.equal(created.length, scenario.expected);
  });
}

function embeddedScript(file) {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const start = lines.findIndex(line => /^\s+script: \|\s*$/.test(line));
  assert(start >= 0, `missing JavaScript script in ${file}`);
  const indentation = lines[start].match(/^\s*/)[0].length;
  const output = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() && line.match(/^\s*/)[0].length <= indentation) break;
    output.push(line.slice(indentation + 2));
  }
  return output.join('\n');
}

function review(login, state = 'APPROVED', commit = 'head', sequence = 1) {
  return {user: {login, id: login}, state, commit_id: commit, submitted_at: `2026-09-01T00:00:0${sequence}Z`};
}

function fixture(scenario) {
  const labels = new Set(scenario.labels || []);
  const writes = [];
  const created = [];
  const pull = {number: 17, state: scenario.state || 'open', draft: scenario.draft || false, user: {login: 'author'}, head: {sha: 'head'}};
  const issues = {
    getLabel: async () => {if (scenario.missingLabels) throw Object.assign(new Error('missing'), {status: 404});},
    createLabel: async args => {created.push(args.name);},
    listLabelsOnIssue() {},
    removeLabel: async args => {labels.delete(args.name); writes.push(args);},
    addLabels: async args => {args.labels.forEach(label => labels.add(label)); writes.push(args);},
  };
  const pulls = {get: async () => ({data: pull}), listReviews() {}};
  const github = {
    rest: {issues, pulls, repos: {getCollaboratorPermissionLevel: async args => {
      if (scenario.permissionError) throw Object.assign(new Error('permission lookup failed'), {status: scenario.permissionError});
      return {data: {permission: scenario.permissions?.[args.username] || 'write'}};
    }}},
    graphql: async () => ({repository: {pullRequest: {reviewDecision: scenario.decision ?? 'APPROVED'}}}),
    paginate: async method => {
      if (method === pulls.listReviews) return scenario.reviews || [];
      if (method === issues.listLabelsOnIssue) return [...labels].map(name => ({name}));
      throw new Error('unexpected pagination method');
    },
  };
  const context = {repo: {owner: 'example', repo: 'example'}, payload: {pull_request: {number: 17, head: {sha: scenario.eventHead || 'head'}}}};
  return {github, context, labels, writes, created};
}

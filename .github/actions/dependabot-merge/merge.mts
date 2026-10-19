import { appendFileSync, readFileSync } from 'node:fs';
import { api, content } from './api.mts';
import { object, array, text } from './policy.mts';
import { merge } from './orchestrate.mts';
const repository = process.env.GITHUB_REPOSITORY ?? '';
if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) throw Error('Invalid owner repository');
const prefix = `repos/${repository}`;
const event = object(JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH!, 'utf8')) as unknown);
let numbers: number[] = [];
const input = process.env.PR_NUMBER;
if (input && /^[1-9]\d*$/.test(input)) numbers = [Number(input)];
else if (event.workflow_run) {
  const run = object(event.workflow_run);
  if (run.event === 'pull_request' && run.conclusion === 'success') {
    numbers = array(run.pull_requests).map(value => Number(object(value).number));
    if (!numbers.length && /^dependabot\//.test(text(run.head_branch))) {
      const pulls = await api(`${prefix}/pulls?state=open&base=main&head=${encodeURIComponent(repository.split('/')[0] + ':' + text(run.head_branch))}&per_page=100`);
      numbers = array(pulls).map(value => Number(object(value).number));
    }
  }
}

for (const number of [...new Set(numbers)].slice(0, 10)) {
  const result = await merge(repository, number, api, content);
  console.log(`#${number}: ${result}`);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `- #${number}: ${result}\n`);
}

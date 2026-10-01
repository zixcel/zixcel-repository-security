"""Local inspection CLI. Configuration and private dictionaries stay local."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import base64
import csv
import json
import os
import subprocess
from pathlib import Path
from .scanner import canonical, digest, read_source, scan_repository


def load(path):
    return json.loads(Path(path).read_text())


def private_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('scan', 'scan-inventory', 'prepare-snapshot'):
        item = sub.add_parser(command)
        item.add_argument('--config', required=True)
        item.add_argument('--output', required=True)
        if command == 'scan-inventory':
            item.add_argument('--inventory', required=True)
            item.add_argument('--workspace', required=True)
            item.add_argument('--jobs', type=int, choices=range(1,5), default=4)
        else:
            item.add_argument('--root', required=True)
        if command == 'prepare-snapshot':
            item.add_argument('--branch', default='main')
            item.add_argument('--message', required=True)
    args = parser.parse_args()
    try:
        config = load(args.config)
        allowed = {'repository_id', 'gitleaks', 'private_dictionary_file', 'exceptions_file'}
        if set(config) - allowed or not isinstance(config.get('repository_id'), str):
            raise ValueError('invalid configuration')
        terms = load(config['private_dictionary_file']) if config.get('private_dictionary_file') else []
        exceptions = load(config['exceptions_file']) if config.get('exceptions_file') else []
        roots = [(Path(args.root), config['repository_id'])] if args.command != 'scan-inventory' else [
            (Path(args.workspace) / row['relative_path'], row['name'])
            for row in csv.DictReader(Path(args.inventory).open(encoding='utf-8-sig', newline=''))]
        def inspect(entry):
            root, name = entry
            local = {**config, 'repository_id': name}
            try:
                return scan_repository(root, local, terms, exceptions)
            except (ValueError, OSError, TimeoutError, subprocess.SubprocessError) as error:
                # Error details and engine stdout may contain source data; never echo them.
                return {'repository_id': name, 'status': 'incomplete', 'error': type(error).__name__}
        with ThreadPoolExecutor(max_workers=getattr(args, 'jobs', 1)) as executor:
            results = list(executor.map(inspect, roots))
        if args.command == 'prepare-snapshot':
            receipt = results[0]
            if receipt['status'] != 'passed':
                raise ValueError('snapshot requires a passing current disclosure scan')
            if not args.branch or args.branch.startswith(('/', '-')) or any(x in args.branch for x in ('..', '@{', '//', '\\', ' ', '~', '^', ':', '?', '*', '[')) or args.branch.endswith(('/', '.', '.lock')):
                raise ValueError('invalid branch')
            if not args.message.strip() or len(args.message.encode()) > 512:
                raise ValueError('invalid commit message')
            files = []
            total = 0
            for item in receipt['inventory']:
                data, mode = read_source(Path(args.root), item['path'])
                if digest(data) != item['sha256'] or mode != item['mode'] or len(data) > 1024 * 1024:
                    raise ValueError('snapshot changed or exceeds transport bound')
                total += len(data)
                files.append({'path': item['path'], 'mode': mode, 'content_base64': base64.b64encode(data).decode()})
            if len(files) > 4096 or total > 8 * 1024 * 1024:
                raise ValueError('snapshot exceeds transport bound')
            artifact = {'schema': 'zixcel://github/source-snapshot-artifact/v1', 'branch': args.branch, 'message': args.message, 'files': files}
            private_write(args.output, artifact)
            print(json.dumps({'status': 'prepared', 'artifact_digest_sha256': digest(Path(args.output).read_bytes()), 'source_digest_sha256': receipt['source_digest_sha256']}))
            return 0
        private_write(args.output, results if args.command == 'scan-inventory' else results[0])
        print(json.dumps({'repositories': len(results), 'passed': sum(r['status'] == 'passed' for r in results), 'findings': sum(r['status'] == 'findings' for r in results), 'incomplete': sum(r['status'] == 'incomplete' for r in results)}))
        return 0 if all(r['status'] == 'passed' for r in results) else 1
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({'status': 'error', 'message': 'invalid local configuration or preparation precondition'}))
        return 2

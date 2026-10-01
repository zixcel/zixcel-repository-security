"""Read-only, bounded source inspection; no source text is emitted in receipts."""
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath

SCHEMA = 'zixcel://repository-security/receipt/v1'
RULESET = 'source-secret-disclosure/v1'
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILES = 20000
RULES = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'email-address': re.compile(r'\b[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63})\b'),
    'telephone': re.compile(r'(?<!\d)0[789]0[- ]\d{4}[- ]\d{4}(?!\d)'),
    'private-classified-record': re.compile(r'(?:confidentiality|classification)\s*[:=]\s*[\"\'](?:customer-confidential|personal-confidential)[\"\']'),
    'personal-profile-value': re.compile(r'(?:date_of_birth|birth_date|birthday|phone_number|postal_address)\s*[\"\']?\s*[:=]\s*[\"\'][^\"\']+'),
    'machine-home-path': re.compile(r'(?:/home/[A-Za-z0-9_.-]+/|/Users/[A-Za-z0-9_.-]+/|[A-Z]:\\Users\\[A-Za-z0-9_.-]+\\)'),
}
TEST_DOMAINS = {'example.com', 'example.org', 'example.net', 'example.test', 'example.co.jp', 'mail.example.co.jp'}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalize(value):
    return unicodedata.normalize('NFKC', value).casefold()


def git_files(root):
    """Include tracked files even if newly ignored; ignore rules do not erase history."""
    with tempfile.TemporaryDirectory(prefix='zixcel-git-observe-') as temp:
        if (root / '.git').exists():
            git = ['git', '-c', 'core.excludesFile=/dev/null']
        else:
            subprocess.run(['git', 'init', '-q', temp], check=True, capture_output=True)
            git = ['git', '-c', 'core.excludesFile=/dev/null', '--git-dir=' + temp + '/.git', '--work-tree=' + str(root)]
        result = subprocess.run(git + ['ls-files', '-c', '-o', '--exclude-standard', '-z'],
                                cwd=root, capture_output=True, check=True)
        files = sorted(set(os.fsdecode(name) for name in result.stdout.split(b'\0') if name))
        if len(files) > MAX_FILES:
            raise ValueError('repository file bound exceeded')
        if not files:
            return [], set()
        check = subprocess.run(git + ['check-ignore', '--no-index', '--stdin', '-z'], cwd=root,
                               input=b'\0'.join(os.fsencode(name) for name in files) + b'\0', capture_output=True)
        if check.returncode not in (0, 1):
            raise ValueError('ignore observation failed')
        ignored = {os.fsdecode(name) for name in check.stdout.split(b'\0') if name}
        return files, ignored


def read_source(root, name):
    parts = PurePosixPath(name).parts
    if not parts or name.startswith('/') or any(part in {'..', '.', '.git'} for part in parts):
        raise ValueError('unsafe source path')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
                raise ValueError('unsupported source file or size')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                data = stream.read(MAX_FILE + 1)
            after = os.fstat(fd)
            if len(data) > MAX_FILE or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('source changed during inspection')
            return data, '100755' if before.st_mode & 0o111 else '100644'
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)


def _documents(name, data, depth=0, budget=None):
    if budget is None:
        budget = {'bytes': MAX_TOTAL, 'entries': MAX_FILES}
    budget['bytes'] -= len(data)
    budget['entries'] -= 1
    if budget['bytes'] < 0 or budget['entries'] < 0:
        yield name, None
        return
    if name.endswith(('.tgz', '.tar.gz', '.tar')):
        if depth >= 2:
            yield name, None
            return
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
                total = 0
                for index, member in enumerate(archive):
                    if index >= 4096 or member.size > MAX_FILE:
                        raise ValueError('archive bound')
                    parts = PurePosixPath(member.name).parts
                    if member.name.startswith('/') or '..' in parts or member.issym() or member.islnk():
                        raise ValueError('unsafe archive entry')
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise ValueError('unsupported archive entry')
                    total += member.size
                    if total > MAX_TOTAL:
                        raise ValueError('archive total bound')
                    content = archive.extractfile(member).read(MAX_FILE + 1)
                    yield from _documents(name + '!' + member.name, content, depth + 1, budget)
        except (tarfile.TarError, ValueError, OSError):
            yield name, None
    else:
        try:
            text = data.decode('utf-8')
            yield name, text if '\0' not in text else None
        except UnicodeDecodeError:
            yield name, None


def inspect_text(name, text, terms, add):
    for line_number, line in enumerate(text.splitlines(), 1):
        for rule, pattern in RULES.items():
            if rule == 'email-address' and '@' not in line:
                continue
            for match in pattern.finditer(line):
                if rule == 'email-address':
                    domain = match.group(1).lower()
                    if domain in TEST_DOMAINS or domain.endswith(('.example', '.invalid', '.test', '.localhost')):
                        continue
                    # URI userinfo and SSH remote syntax are not email addresses.
                    if re.search(r'(?:https?|ssh)://[^\s/]*$', line[:match.start()]) or (match.group(0) == ('git' + '@github.com') and line[match.end():].startswith(':')):
                        continue
                add(name, line_number, rule)
        normalized = normalize(line)
        for term in terms:
            if any(normalize(value) in normalized for value in term['values']):
                add(name, line_number, 'registered-private-' + term['category'], term['id'])


def validate_terms(terms):
    if not isinstance(terms, list) or len(terms) > 256:
        raise ValueError('invalid private dictionary')
    for term in terms:
        if set(term) != {'id', 'category', 'values'} or term['category'] not in {'person', 'company', 'project'}:
            raise ValueError('invalid private dictionary entry')
        if not re.fullmatch(r'[a-z0-9-]{1,64}', term['id']) or not isinstance(term['values'], list) or not 1 <= len(term['values']) <= 32:
            raise ValueError('invalid private dictionary entry')
        if any(not isinstance(value, str) or not 2 <= len(value) <= 256 for value in term['values']):
            raise ValueError('invalid private dictionary value')


def scan_repository(root, config, terms=None, exceptions=None):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError('an existing absolute physical repository root is required')
    root = root.resolve()
    if not isinstance(config, dict) or not re.fullmatch(r'[a-zA-Z0-9._-]{1,100}', config.get('repository_id', '')):
        raise ValueError('invalid repository configuration')
    policy_path = root / 'repository-security.json'
    policy = None
    if policy_path.exists():
        policy = json.loads(read_source(root, 'repository-security.json')[0])
        expected_keys = {'schema', 'repository_id', 'scope', 'required_engines', 'gitleaks_version'}
        if set(policy) != expected_keys or policy['schema'] != 'zixcel://repository-security/policy/v1' \
            or policy['repository_id'] != config['repository_id'] or policy['scope'] != RULESET \
            or policy['required_engines'] != ['builtin-disclosure', 'gitleaks'] or policy['gitleaks_version'] != '8.30.1':
            raise ValueError('invalid repository policy')
    terms = terms or []
    validate_terms(terms)
    exceptions = exceptions or []
    files, ignored = git_files(root)
    inventory, findings, incomplete = [], [], []
    seen = set()
    source_digest = ''
    rule_digest = digest(Path(__file__).read_bytes())
    dictionary_digest = digest(canonical(terms))
    engine_pin = config.get('gitleaks', {}).get('sha256')
    exception_index = {}
    today = dt.date.today().isoformat()
    for exception in exceptions:
        if not isinstance(exception, dict) or set(exception) != {'fingerprint', 'expires', 'reason', 'reviewer'} or not re.fullmatch(r'[a-f0-9]{64}', exception['fingerprint']):
            raise ValueError('invalid review exception')
        try:
            dt.date.fromisoformat(exception['expires'])
        except (ValueError, TypeError):
            raise ValueError('invalid exception expiration')
        if exception['expires'] >= today and exception['reason'].strip() and exception['reviewer'].strip():
            exception_index[exception['fingerprint']] = exception

    file_hashes = {}
    def add(path, line, rule, entity=None):
        parent = path.split('!', 1)[0]
        key = (path, line, rule, entity)
        if key in seen:
            return
        seen.add(key)
        fingerprint = digest(canonical([config['repository_id'], path, line, rule, entity, file_hashes.get(parent), rule_digest, dictionary_digest, engine_pin]))
        item = {'path': path, 'line': line, 'rule': rule, 'fingerprint': fingerprint,
                'disposition': 'reviewed' if fingerprint in exception_index and rule != 'tracked-excluded-data' else 'open'}
        if entity:
            item['entity_ref'] = entity
        findings.append(item)

    with tempfile.TemporaryDirectory(prefix='zixcel-security-snapshot-') as temporary:
        stage = Path(temporary)
        total = 0
        document_budget = {'bytes': MAX_TOTAL, 'entries': MAX_FILES}
        for name in files:
            try:
                data, mode = read_source(root, name)
            except (OSError, ValueError):
                incomplete.append({'path': name, 'reason': 'unsafe-or-unsupported-file'})
                continue
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError('repository byte bound exceeded')
            file_hashes[name] = digest(data)
            inventory.append({'path': name, 'sha256': file_hashes[name], 'mode': mode})
            if name in ignored:
                add(name, 0, 'tracked-excluded-data')
            for term in terms:
                if any(normalize(value) in normalize(name) for value in term['values']):
                    add(name, 0, 'registered-private-' + term['category'], term['id'])
            for doc_name, text in _documents(name, data, budget=document_budget):
                if text is None:
                    incomplete.append({'path': doc_name, 'reason': 'uninspected-format'})
                else:
                    for term in terms:
                        if any(normalize(value) in normalize(doc_name) for value in term['values']):
                            add(doc_name, 0, 'registered-private-' + term['category'], term['id'])
                    inspect_text(doc_name, text, terms, add)
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(data)
            path.chmod(0o600)
        source_digest = digest(canonical(inventory))
        gitleaks = config.get('gitleaks')
        engine = {'status': 'not-configured'}
        if gitleaks:
            executable = Path(gitleaks['path'])
            if not executable.is_absolute() or executable.is_symlink() or digest(executable.read_bytes()) != gitleaks['sha256']:
                raise ValueError('gitleaks executable digest mismatch')
            report_directory = tempfile.TemporaryDirectory(prefix='zixcel-private-report-')
            report_path = Path(report_directory.name) / 'gitleaks.json'
            trusted_rules = Path(report_directory.name) / 'gitleaks.toml'
            trusted_rules.write_text('[extend]\nuseDefault = true\n')
            ignore_file = Path(report_directory.name) / '.gitleaksignore'
            ignore_file.write_text('')
            try:
                command = [str(executable), 'dir', str(stage), '--no-banner', '--redact=100',
                           '--max-archive-depth=2', '--config=' + str(trusted_rules),
                           '--gitleaks-ignore-path=' + str(ignore_file), '--ignore-gitleaks-allow', '--report-format=json', '--report-path=' + str(report_path)]
                result = subprocess.run(command, capture_output=True, timeout=120,
                                        env={'PATH': '/usr/bin:/bin', 'HOME': str(stage), 'GOMAXPROCS': '1'}, cwd=stage)
                if result.returncode not in (0, 1):
                    raise ValueError('gitleaks scan failed')
                for finding in json.loads(report_path.read_text()) if report_path.exists() else []:
                    raw_path = finding['File']
                    path = raw_path.removeprefix(str(stage) + '/')
                    add(path, int(finding.get('StartLine', 0)), 'gitleaks:' + finding['RuleID'])
                engine = {'status': 'completed', 'sha256': gitleaks['sha256']}
            finally:
                report_directory.cleanup()
        else:
            incomplete.append({'path': '', 'reason': 'gitleaks-not-configured'})
        # Re-observe the original file set and all bytes; a concurrent edit invalidates the result.
        files_after, ignored_after = git_files(root)
        if files_after != files or ignored_after != ignored:
            raise ValueError('repository file set changed during inspection')
        for item in inventory:
            if digest(read_source(root, item['path'])[0]) != item['sha256']:
                raise ValueError('source changed during inspection')

    open_findings = sum(item['disposition'] == 'open' for item in findings)
    return {'schema': SCHEMA, 'repository_id': config['repository_id'], 'scope': RULESET,
            'status': 'incomplete' if incomplete else 'findings' if open_findings else 'passed',
            'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'policy_digest_sha256': digest(canonical(policy)),
            'source_digest_sha256': source_digest, 'rules_digest_sha256': rule_digest,
            'configuration_digest_sha256': digest(canonical(config)),
            'private_dictionary_digest_sha256': digest(canonical(terms)),
            'exceptions_digest_sha256': digest(canonical(exceptions)),
            'engines': {'builtin-disclosure': 'completed', 'gitleaks': engine,
                        'dependency-vulnerabilities': 'not-run', 'sast': 'not-run'},
            'inventory': inventory, 'findings': findings, 'uninspected': incomplete,
            'open_findings': open_findings, 'reviewed_findings': len(findings) - open_findings}

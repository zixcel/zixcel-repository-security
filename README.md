# Zixcel repository security

Independent local source disclosure scanner. It scans Git-eligible tracked and untracked files, inspects bounded tar archives without extracting them, rejects symlinks, and detects ignored-but-tracked data. It does not print matching values. Unknown binary formats, unavailable Gitleaks, and concurrent source changes make inspection incomplete.

Run with Python 3.12 or later and a checksum-pinned official Gitleaks executable:

```sh
PYTHONPATH=src python -m zixcel_repository_security scan --config registration/config.json --root "$PWD" --output state/receipt.json
```

Configuration is JSON containing `repository_id`, optional `private_dictionary_file`, optional `exceptions_file`, and `gitleaks: {path, sha256}`. Dictionary entries contain an opaque `id`, `category` (`person`, `company`, `project`), and `values`. Keep dictionaries/configuration in ignored registration storage with restrictive permissions. No customer data belongs in examples.

`scan-inventory --inventory <csv> --workspace <absolute-root>` inspects every CSV entry. Output receipts retain file hashes, locations, rules and review dispositions, never matched source values. Scope is disclosure and secret detection; dependency vulnerability analysis and SAST are explicitly reported as not run.

Exceptions require an exact finding fingerprint (bound to the entire file), a reviewer, reason and expiration. Do not exempt whole repositories, all tests, or every detected name. A private key remains a finding even in tests until reviewed as an intentional public fixture.

`prepare-snapshot --root <absolute-root> --branch main --message <text>` reruns inspection and prepares a bounded source artifact only after a passing result. It does not commit, push, create or delete repositories. Provide the resulting digest-named JSON artifact to the Crowsi artifact store; configured Zixcel policy, signed HAT authority and GitHub token permissions are separate requirements. Existing Git history must be inspected separately before a normal Git push; this source scanner does not certify history.

各リポジトリの `repository-security.json` で検査scope、必須engine、Gitleaks版を宣言します。`python3 tools/run-repository-security.py` をWonderlandで実行すると全CSV行を検査し、結果・件数・source digest・検査日時をCSVへ反映します。非公開辞書と実行設定は `state/repository-security/` に保存します。値を追加する場合は辞書のopaque IDごとに個人・企業・案件名、識別子、別表記を登録してください。未登録の名称や意味による機密判定をこの検査だけで保証するものではありません。

Gitleaksはchecksumを検証した公式8.30.1を使用し、実行時にバイナリdigestを照合します。検査対象側の `.gitleaks.toml`、`.gitleaksignore`、inline allowコメントで検査を弱められないよう、検査側で既定ルール・空ignoreファイルを明示します。例外fingerprintはファイル全体、検査実装、辞書、engine digestにも束縛します。検証fixture・公開依存メタデータは個別の根拠と期限を記録してレビューし、実顧客情報の検出は登録データへ移します。

`passed` は現在の公開候補ファイルに対する秘密・公開禁止情報検査の合格です。Git履歴、依存脆弱性、SAST、画像/OCRやDB内容の検査は含みません。除外登録データの実バックアップは別途保管してください。

## License / ライセンス

The current distribution is offered under Apache-2.0; see LICENSE. Prior MIT notices are retained in LICENSE-MIT and NOTICE, without revoking previous permissions. Private dictionaries, registration data and execution receipts are excluded from distribution. Gitleaks is an external tool with its own license.

現在の配布版にはApache-2.0を適用します。LICENSEを参照してください。従前のMIT表示はLICENSE-MITとNOTICEに保持し、以前の許諾を取り消しません。非公開辞書・登録データ・実行結果は配布対象外です。外部ツールGitleaksにはその独自のライセンスが適用されます。

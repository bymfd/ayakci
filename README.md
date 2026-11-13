# ayakci

Legacy HTML security-report → JSON importer CLI. Extracts vulnerability
candidates from old HTML pentest reports and prepares them for export /
push to a modern platform.

## Kurulum / Installation

```bash
pip install -r requirements.txt
```

## Kullanım / Usage

```bash
# Extract candidates from HTML files (no server)
python ayakci.py extract examples/ --no-serve

# Extract and open preview server
python ayakci.py extract examples/

# Preview an existing candidates.json
python ayakci.py preview candidates.json

# Push candidates to platform API
python ayakci.py push candidates.json --target findings \
  --api-url https://... --token TOKEN \
  --product 1 --engagement 2 --test 3

# Run built-in self-checks
python ayakci.py selftest
```

Makefile shortcuts:

```bash
make install      # pip install -r requirements.txt
make test         # run unittest suite
make selftest     # run python ayakci.py selftest
make extract      # python ayakci.py extract examples/ --no-serve
make clean        # remove artifacts
```

## Desteklenen Giriş Formatları / Supported Input Formats

- Plain HTML / HTM files
- Embedded base64-encoded JSON payloads (`base64_data`, `encrypted_data`, …)
- Embedded `<script type="application/json">` blocks
- Encrypted v2 payloads (AES-GCM + PBKDF2, password via `--password`)
- Profile-based extraction (custom CSS selectors via `--profile`)
- Manual fallback for pages with no structured data

## Özellikler / Features

- Turkish and English severity/status/retest mapping
- CVSS, CVE, CWE parsing
- Cross-file deduplication (by ref + title)
- Retest history tracking
- Preview web server with inline editing
- Direct push to platform findings API

## Lisans / License

GPL-3.0 — see [LICENSE](LICENSE) for the full text of the GNU General Public License v3.0.
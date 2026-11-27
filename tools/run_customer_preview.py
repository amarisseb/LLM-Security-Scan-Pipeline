"""Run the customer journey locally, with separate storage and real safeguards."""
import argparse
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or args.port in {3306, 5432, 6379, 9200, 11211, 27017}:
        parser.error('Choose an unprivileged port from 1024 to 65535, excluding internal service ports.')
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    storage = root / '.arisec-private' / 'customer-preview'
    storage.mkdir(parents=True, exist_ok=True)
    os.environ.update({
        'ARISEC_SELF_SERVE': '1', 'ARISEC_LOCAL_PREVIEW': '1',
        'ARISEC_LOCAL_DEMO': '0',
        'ARISEC_LOCAL_ASSURANCE': '1',
        'ARISEC_EXAMPLE_ENDPOINT': f'http://127.0.0.1:{args.port}/demo/endpoint',
        'ARISEC_ACCOUNTS_DB': str(storage / 'accounts.sqlite3'),
        'SCAN_OUTPUT_DIR': str(storage / 'runs'),
        'ATTESTATION_LOG_PATH': str(storage / 'attestations.jsonl'),
    })
    print(f'Open http://127.0.0.1:{args.port}/ — keep this terminal open.', flush=True)
    print('The example endpoint is scripted, not a real LLM. Real scans retain authorisation, quotas and target checks.', flush=True)
    import uvicorn
    # Separate preview storage; no retention/recovery startup on visual previews.
    uvicorn.run('app.pilot:app', host='127.0.0.1', port=args.port, lifespan='off')


if __name__ == '__main__':
    main()

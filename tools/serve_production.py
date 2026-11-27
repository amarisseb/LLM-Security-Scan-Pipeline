"""Fail-closed, single-process production entry point behind the bundled Caddy."""
from dataclasses import dataclass
import os
from pathlib import Path
import sys

CADDY_IP = '172.30.23.2'


@dataclass(frozen=True)
class ProductionConfig:
    public_origin: str
    data_dir: Path
    forwarded_allow_ips: str = CADDY_IP


def validate_config() -> ProductionConfig:
    """Validate without creating files, starting services, DNS or network I/O."""
    from app.example_endpoint import configured_example_endpoint
    for key, expected in {'ARISEC_SELF_SERVE': '1', 'ARISEC_LOCAL_DEMO': '0', 'ARISEC_LOCAL_PREVIEW': '0'}.items():
        if os.getenv(key) != expected:
            raise ValueError(f'{key} must be {expected} in production')
    origin = os.getenv('ARISEC_PUBLIC_ORIGIN', '')
    if configured_example_endpoint() != origin + '/demo/endpoint':
        raise ValueError('ARISEC_PUBLIC_ORIGIN must be a canonical public HTTPS origin')
    if os.getenv('FORWARDED_ALLOW_IPS', CADDY_IP) != CADDY_IP:
        raise ValueError('Only the bundled Caddy IP may supply forwarded headers')
    raw_data = os.getenv('DATA_DIR', '')
    data_dir = Path(raw_data)
    if not raw_data or not data_dir.is_absolute() or '..' in data_dir.parts:
        raise ValueError('DATA_DIR must be an absolute private directory')
    data_dir = data_dir.resolve()
    if data_dir == Path(data_dir.anchor):
        raise ValueError('DATA_DIR must not be a filesystem root')
    if os.getenv('ARISEC_EXAMPLE_ENDPOINT'):
        raise ValueError('Local example endpoints are disabled in production')
    return ProductionConfig(origin, data_dir)


def configure_environment(config: ProductionConfig) -> None:
    """Set fixed private paths, ignoring inherited per-file path overrides."""
    os.umask(0o077)
    root = config.data_dir
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = {
        'ARISEC_ACCOUNTS_DB': root / 'accounts.sqlite3',
        'SCAN_OUTPUT_DIR': root / 'runs',
        'ATTESTATION_LOG_PATH': root / 'attestations.jsonl',
        'HOME': root / 'home',
        'XDG_CACHE_HOME': root / 'cache',
        'XDG_DATA_HOME': root / 'cache' / 'share',
        'HF_HOME': root / 'cache' / 'huggingface',
        'HF_HUB_CACHE': root / 'cache' / 'huggingface' / 'hub',
        'TORCH_HOME': root / 'cache' / 'torch',
        'NLTK_DATA': root / 'cache' / 'nltk',
    }
    # A pre-existing symlink must not move private storage outside DATA_DIR.
    for path in paths.values():
        if not path.resolve().is_relative_to(root):
            raise ValueError('Private storage must stay inside DATA_DIR')
    for key, path in paths.items():
        os.environ[key] = str(path)
    for key in ('SCAN_OUTPUT_DIR', 'HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'HF_HOME', 'HF_HUB_CACHE', 'TORCH_HOME', 'NLTK_DATA'):
        paths[key].mkdir(mode=0o700, parents=True, exist_ok=True)
    os.environ['FORWARDED_ALLOW_IPS'] = config.forwarded_allow_ips
    os.environ['ENABLE_DOCS'] = '0'
    os.environ['CORS_ALLOW_ORIGINS'] = config.public_origin
    os.environ.pop('CORS_ALLOW_ORIGIN_REGEX', None)
    os.environ.pop('ARISEC_ACCOUNTS_FILE', None)
    os.environ['ARISEC_MAX_PENDING_SCANS'] = '2'


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    config = validate_config()
    configure_environment(config)
    import uvicorn
    uvicorn.run('app.pilot:app', host='0.0.0.0', port=8000, workers=1,
                proxy_headers=True, forwarded_allow_ips=config.forwarded_allow_ips,
                server_header=False, access_log=False)


if __name__ == '__main__':
    main()

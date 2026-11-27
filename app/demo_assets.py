"""Public, fixed-path educational assets; never executes or queues a scan."""
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse

ROOT = Path(__file__).resolve().parents[1] / 'demo'


def register_demo_assets(app):
    assets = {
        '/demo/scenarios.json': ('scenarios.json', 'application/json'),
        '/demo/product-walkthrough.webm': ('media/product-walkthrough.webm', 'video/webm'),
        '/demo/product-walkthrough.mp4': ('media/product-walkthrough.mp4', 'video/mp4'),
        '/demo/product-walkthrough.vtt': ('media/product-walkthrough.vtt', 'text/vtt'),
        '/demo/product-walkthrough-poster.png': ('media/product-walkthrough-poster.png', 'image/png'),
    }
    def make_endpoint(filename, media_type):
        path = ROOT / filename
        def endpoint():
            if not path.is_file():
                raise HTTPException(status_code=404, detail='Demo asset unavailable.')
            return FileResponse(path, media_type=media_type)
        return endpoint
    for url, (filename, media_type) in assets.items():
        app.add_api_route(url, make_endpoint(filename, media_type), methods=['GET'], include_in_schema=False)

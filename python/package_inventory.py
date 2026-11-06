"""Export installed distribution *metadata*, without importing their modules."""

from importlib import metadata
import json
import sysconfig


def main():
    # Explicit site-packages paths work with Python -S, which avoids running
    # potentially executable .pth files during interpreter startup.
    roots = sorted({sysconfig.get_path("purelib"), sysconfig.get_path("platlib")})
    for dist in metadata.distributions(path=roots):
        name = dist.metadata.get("Name", "").strip()
        version = str(dist.version or "").strip()
        if not name or not version:
            continue
        detail = {
            "name": name,
            "version": version,
            "summary": dist.metadata.get("Summary", ""),
            "requires_python": dist.metadata.get("Requires-Python", ""),
            "requires_dist": dist.metadata.get_all("Requires-Dist") or [],
            "home_page": dist.metadata.get("Home-page", ""),
        }
        print(json.dumps(detail, ensure_ascii=False))


if __name__ == "__main__":
    main()


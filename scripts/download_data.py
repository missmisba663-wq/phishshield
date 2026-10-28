"""Download the training datasets from Kaggle into data/raw/.

Usage:
    python scripts/download_data.py

Public datasets download anonymously through kagglehub. If Kaggle asks for
authentication, create an API token at https://www.kaggle.com/settings and
save it as ~/.kaggle/kaggle.json.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import kagglehub  # noqa: E402

from config import KAGGLE_DATASETS, RAW_DIR  # noqa: E402


def main():
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for name, info in KAGGLE_DATASETS.items():
        target = RAW_DIR / f"{name}_{info['file']}"
        if target.exists():
            print(f"[skip] {target.name} already present")
            continue
        print(f"[download] {info['slug']}  ({info['description']})")
        folder = Path(kagglehub.dataset_download(info["slug"]))
        shutil.copy(folder / info["file"], target)
        print(f"   -> {target}")
    print("Done. Now run:  python -m training.train_all")


if __name__ == "__main__":
    main()

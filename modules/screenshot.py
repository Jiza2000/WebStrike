import os
import subprocess


def capture_screenshot(target, output_path="reports/screenshot.png"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    command = [
        "chromium",
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        f"--screenshot={output_path}",
        "--window-size=1365,768",
        target
    ]

    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30
        )

        if os.path.exists(output_path):
            return output_path

    except Exception:
        pass

    return None

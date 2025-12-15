import re
import subprocess
from urllib.parse import urlparse
import tomllib  # py3.11+
from pydantic import BaseModel
from pathlib import Path
from tqdm import tqdm
import argparse
import os

DEBUG = True


def run_and_tee(cmd: list[str], output_path: Path) -> int:
    if DEBUG:
        return None
    with output_path.open("w") as f:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,  # 行缓冲
        )

        assert proc.stdout is not None
        for line in proc.stdout:
            tqdm.write(line.rstrip())
            f.write(line)  # 文件

        return proc.wait()


def safe_url_name(url: str) -> str:
    parsed = urlparse(url)
    base = parsed.netloc + parsed.path
    return re.sub(r"[^\w.-]", "_", base.strip("_"))


class ScanTarget(BaseModel):
    meta: str
    name: str
    ip: str
    needed_port: list[int]
    urls: list[str]
    skip: bool = False

    @classmethod
    def load(cls, path: Path) -> list["ScanTarget"]:
        with path.open("rb") as f:
            data = tomllib.load(f)

        return [cls.model_validate(item) for item in data["targets"]]

    @property
    def path(self) -> Path:
        path = Path(self.meta) / self.name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def nmap(self):
        output_path = self.path / f"{self.ip}.nmap"
        cmd: list[str] = [
            "nmap",
            self.ip,
            "-sS",
            "-Pn",
            "-p-",
            "-T4",
            "--max-retries",
            "4",
            "--min-rate",
            "100",
            "--defeat-rst-ratelimit",
            "--open",
        ]
        print(f"[nmap] {self.ip}")
        run_and_tee(cmd, output_path)

    def dirsearch(self, url: str):
        output_base = self.path / "dirsearch"
        output_base.mkdir(parents=True, exist_ok=True)

        name = safe_url_name(url)
        output_path = output_base / f"{name}.csv"

        cmd = [
            "dirsearch",
            "-u",
            url,
            "-w",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "-e",
            "php,asp,aspx,jsp,html,zip,rar,7z,txt",
            "--random-agent",
            "--format",
            "csv",
            "-o",
            str(output_path),
            "-t",
            "40",
            "-r",
            "2",
            "--include-status",
            "200,300-308,401,403,500",
            "--timeout",
            "5",
        ]

        print(f"[dirsearch] {url}")
        run_and_tee(cmd, output_path)

    def run(self):
        if self.skip:
            tqdm.write(f"[skip] {self.name}")
            return

        tqdm.write(f"\n[target] {self.name} ({self.ip})")
        tqdm.write("[subtask] nmap")

        self.nmap()

        if self.urls:
            for url in tqdm(self.urls, desc="dirsearch", leave=False):
                self.dirsearch(url)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-file", type=Path, default=Path("task.toml"))
    parser.add_argument("--output", type=Path, default=Path("output"))
    args = parser.parse_args()

    targets = ScanTarget.load(Path(args.task_file).absolute())
    # 切换到输出目录工作（可选）
    args.output.mkdir(parents=True, exist_ok=True)
    os.chdir(args.output)

    with tqdm(targets, desc="Targets", unit="target") as pbar:
        for target in pbar:
            pbar.set_description(f"Target: {target.name}")
            target.run()

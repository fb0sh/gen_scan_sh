import tomllib  # py3.11+
from pydantic import BaseModel
from pathlib import Path


def safe_url_name(url: str) -> str:
    from urllib.parse import urlparse
    import re

    parsed = urlparse(url)
    base = parsed.netloc + parsed.path
    return re.sub(r"[^\w.-]", "_", base.strip("_"))


class ScanTarget(BaseModel):
    # output/meta/manual/name/ip.nmap
    # output/meta/manual/name/safe_url.csv
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
    def base_dir(self):
        return f"./output/{self.meta}/manual/{self.name}"

    def gen_dir(self):
        print(f"mkdir -p {self.base_dir}")

    def gen_nmap(self):
        print(
            f"nmap -sS -Pn -p- -T4 --max-retries 4 --min-rate 100 --defeat-rst-ratelimit --open {self.ip} -oN {self.base_dir}/{self.ip}.nmap"
        )

    def gen_dirsearch(self):
        for url in self.urls:
            filename = safe_url_name(url)
            print(
                f"dirsearch -u {url} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e php,asp,aspx,jsp,html,zip,rar,7z,txt --random-agent --format=csv -o {self.base_dir}/{filename}.csv -t 40 -r 2 --include-status=200,300-308,401,403,500 --timeout=5"
            )

    def gen_script(self):
        if self.skip:
            return

        print(f"echo 'Starting Task {self.name}'")
        self.gen_dir()
        self.gen_nmap()
        self.gen_dirsearch()
        print(f"echo 'Ending task {self.name}'\n\n")


if __name__ == "__main__":
    targets = ScanTarget.load(Path("./task.toml"))
    print("#!/bin/bash\n")
    for i in targets:
        i.gen_script()

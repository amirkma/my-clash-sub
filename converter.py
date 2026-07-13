import os
import json
import base64
import hashlib
import requests
import yaml
from urllib.parse import urlparse, parse_qs, unquote

OUTPUT_DIR = "output"

os.makedirs(OUTPUT_DIR, exist_ok=True)


class Converter:

    def __init__(self):
        with open("sources.json", "r", encoding="utf-8") as f:
            self.sources = json.load(f)

        self.nodes = []

    def download(self, url):

        print("Downloading:", url)

        r = requests.get(
            url,
            timeout=30,
            headers={
                "User-Agent": "Clash-Subscription"
            }
        )

        r.raise_for_status()

        return r.text

    def unique(self, items):

        result = []

        seen = set()

        for item in items:

            h = hashlib.md5(item.encode()).hexdigest()

            if h in seen:
                continue

            seen.add(h)

            result.append(item)

        return result

    def load_source(self, name):

        url = self.sources[name]

        text = self.download(url)

        lines = []

        for line in text.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            lines.append(line)

        return self.unique(lines)

    def load_all(self):

        self.nodes.clear()

        for source in self.sources:

            print(source)

            self.nodes.extend(
                self.load_source(source)
            )

        self.nodes = self.unique(self.nodes)

        print("Total Nodes:", len(self.nodes))

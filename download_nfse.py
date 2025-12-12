import logging
import os
import sys
import threading
import datetime

from dataclasses import asdict

from nfse.downloader import NFSeDownloader
from nfse.config import Config

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = asdict(Config())


class App:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.thread = None
        self.user_stop = False
        self.downloader = NFSeDownloader(config)
        self.write("Aplicativo iniciado.", log=True)

    def write(self, msg, log=True):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        msg_fmt = f"[{now}] {msg}\n"
        self.logger.info(msg_fmt)
        print(msg_fmt, end='')

    def start(self):
        if self.running:
            return
        self.user_stop = False
        self.running = True
        self.thread = threading.Thread(target=self.download_nfse)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        self.user_stop = True
        self.downloader.close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)

    def download_nfse(self):
        try:
            self.downloader.run(write=self.write, running=lambda: self.running)
        except Exception as e:
            self.logger.error("Erro inesperado: %s", e)
            self.write(f"Erro inesperado: {e}", log=True)
        finally:
            self.running = False

REQUIRED_FIELDS = ["cert_path", "cert_pass", "cnpj", "output_xml_dir", "output_pdf_dir", "log_dir"]


def ler_config() -> Config:
    return Config.load(CONFIG_FILE)


def salvar_config(cfg: Config | dict) -> None:
    if isinstance(cfg, Config):
        cfg.save(CONFIG_FILE)
    else:
        Config(**cfg).save(CONFIG_FILE)

if __name__ == "__main__":
    try:
        cfg = Config.load(CONFIG_FILE)
    except Exception as e:
        sys.exit(1)

    app = App(cfg)
    app.start()
    app.download_nfse()

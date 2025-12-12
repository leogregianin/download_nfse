import json
import os
from dataclasses import dataclass, asdict


@dataclass
class Config:
    cert_path: str = ""
    cert_pass: str = ""
    cnpj: str = ""
    output_xml_dir: str = "./xml"
    output_pdf_dir: str = "./pdf"
    log_dir: str = "logs"
    file_prefix: str = "NFS-e"
    download_pdf: bool = False
    delay_seconds: int = 60
    auto_start: bool = False
    timeout: int = 30

    REQUIRED_FIELDS = [
        "cert_path",
        "cert_pass",
        "cnpj",
        "output_xml_dir",
        "output_pdf_dir",
        "log_dir"
    ]

    @classmethod
    def load(cls, path: str) -> "Config":
        created = False
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = {}
            created = True
        cfg_data = asdict(cls())
        cfg_data.update(data)
        cfg = cls(**cfg_data)
        missing = [k for k in cls.REQUIRED_FIELDS if not getattr(cfg, k)]
        if missing and not created:
            raise ValueError(
                "Campos obrigatórios ausentes no config.json: " + ", ".join(missing)
            )
        if created:
            cfg.save(path)
        return cfg

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)

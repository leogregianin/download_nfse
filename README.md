# Baixar NFS-e Nacional

Download de XML e PDF da Nota Fiscal de Servico Eletrônica (NFS-e) pelo Portal Nacional.

## Recursos

- Baixa automaticamente XML e PDFs das notas.
- Armazena logs e permite retomar o processo pelo último NSU.
- Utiliza certificado digital (PFX ou PEM) para autenticação.

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

* Renomeie o arquivo `config_example.json` para `config.json` e edite as configurações conforme necessário. 
* Execute o script `download_nfse.py` para iniciar o processo de download.

### config.json

- `cert_path`: caminho do certificado digital.
- `cert_pass`: senha do certificado.
- `cnpjcpf`: CNPJ/CPF utilizado no portal.
- `output_xml_dir`: pasta onde os XMLs serão salvos.
- `output_pdf_dir`: pasta onde os PDFs serão salvos.
- `log_dir`: diretório de logs.
- `file_prefix`: prefixo dos arquivos.
- `download_pdf`: `true` para baixar também o PDF.
- `delay_seconds`: intervalo entre consultas.
- `auto_start`: inicia o download ao abrir.
- `timeout`: tempo limite das requisições.

"""Importación local; nunca escribe el libro recibido ni evalúa sus fórmulas."""
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from io import BytesIO
import ipaddress
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET

import pandas as pd
from openpyxl import load_workbook

COLUMNS = ('Log_ID', 'Timestamp', 'Hostname', 'Event_ID', 'User', 'Source_IP',
           'Destination', 'Log_Source', 'Event_Description', 'Process_CommandLine',
           'Result', 'Severity')
MAX_BYTES = 10 * 1024 * 1024
MAX_ROWS = 50000

class ValidationError(ValueError):
    """Error de entrada que se puede presentar al estudiante."""

@dataclass
class ImportResult:
    fingerprint: str
    original: pd.DataFrame
    normalized: pd.DataFrame
    issues: pd.DataFrame
    sheets: list[str]

def display_records(records: pd.DataFrame) -> pd.DataFrame:
    """Copia visual serializable: Event_ID textual, sin mutar valores originales.

    Conserva índice, Log_ID y nulos; admite subconjuntos filtrados y vacíos.
    No aplica limpieza ni cambia el contrato de los registros originales.
    """
    display = records.copy(deep=True)
    display['Event_ID'] = display['Event_ID'].astype('string')
    return display

def import_excel(content: bytes, filename: str) -> ImportResult:
    if Path(filename).suffix.lower() != '.xlsx':
        raise ValidationError('Seleccione un archivo .xlsx; no se admiten macros ni otros formatos.')
    if not content or len(content) > MAX_BYTES:
        raise ValidationError('El archivo está vacío o supera el límite de 10 MiB.')
    try:
        with ZipFile(BytesIO(content)) as archive:
            entries = archive.infolist()
            if len(entries) > 2000 or sum(e.file_size for e in entries) > 50 * 1024 * 1024:
                raise ValidationError('El contenido descomprimido excede los límites de seguridad.')
            for entry in entries:
                name = entry.filename.lower()
                if any(part in name for part in ('vbaproject', 'externallinks/', 'embeddings/', 'connections.xml')):
                    raise ValidationError('El libro contiene macros, conexiones u objetos no admitidos.')
                if name.endswith('.rels'):
                    root = ET.fromstring(archive.read(entry))
                    if any(e.get('TargetMode') == 'External' for e in root):
                        raise ValidationError('El libro contiene vínculos externos no admitidos.')
        book = load_workbook(BytesIO(content), read_only=True, data_only=False, keep_links=False)
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError('No se pudo leer el Excel: archivo dañado, cifrado o incompatible.') from exc
    try:
        sheets = book.sheetnames
        if 'SIEM Export' not in sheets:
            raise ValidationError('Falta la hoja requerida SIEM Export.')
        sheet = book['SIEM Export']
        if sheet.max_column and sheet.max_column > 100:
            raise ValidationError('La hoja supera el límite de 100 columnas.')
        iterator = sheet.iter_rows()
        header_cells = next(iterator, ())
        headers = [c.value for c in header_cells]
        if any(c.data_type == 'f' for c in header_cells):
            raise ValidationError('No se admiten fórmulas en los encabezados.')
        if len(headers) != len(set(headers)):
            raise ValidationError('Hay encabezados duplicados.')
        if set(headers) != set(COLUMNS):
            missing = ', '.join(c for c in COLUMNS if c not in headers)
            raise ValidationError('Se requieren exactamente las 12 columnas oficiales. Faltantes: ' + (missing or 'ninguna; revise columnas adicionales.'))
        records, row_numbers = [], []
        for number, cells in enumerate(iterator, 2):
            if number > MAX_ROWS + 1:
                raise ValidationError('La hoja supera el límite de 50.000 filas de datos.')
            if any(c.data_type == 'f' for c in cells):
                raise ValidationError(f'La fila {number} contiene una fórmula; no se evaluó.')
            if any(c.data_type == 'e' for c in cells):
                raise ValidationError(f'La fila {number} contiene un error de Excel.')
            values = [c.value for c in cells]
            if all(v is None for v in values):
                continue
            records.append(values)
            row_numbers.append(number)
    finally:
        book.close()
    if not records:
        raise ValidationError('La hoja no contiene registros.')
    original = pd.DataFrame(records, columns=headers, dtype=object)
    original.index = pd.Index(row_numbers, name='Excel_Row')
    normalized = original.copy(deep=True)
    issues = []
    def issue(row, column, message):
        issues.append({'Fila Excel': row, 'Log_ID': original.at[row, 'Log_ID'],
                       'Campo': column, 'Problema': message})
    for row in original.index:
        for column in COLUMNS:
            value = original.at[row, column]
            blank = value is None or (isinstance(value, str) and not value.strip())
            if blank:
                issue(row, column, 'Valor ausente; no implica por sí solo un error de seguridad.')
                normalized.at[row, column] = None
                continue
            if column == 'Timestamp':
                try:
                    parsed = value if isinstance(value, datetime) else datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
                    if parsed.tzinfo is not None:
                        raise ValueError('Zona no admitida')
                    normalized.at[row, column] = parsed
                except (ValueError, TypeError):
                    normalized.at[row, column] = None
                    issue(row, column, 'Fecha inválida; se espera AAAA-MM-DD HH:MM:SS, sin asumir zona horaria.')
            elif column == 'Event_ID':
                if isinstance(value, bool) or not isinstance(value, (str, int, float)) or (isinstance(value, float) and not value.is_integer()):
                    normalized.at[row, column] = None
                    issue(row, column, 'Identificador de evento de tipo incompatible.')
                else:
                    normalized.at[row, column] = str(int(value)) if isinstance(value, (int, float)) else value
            elif not isinstance(value, str):
                issue(row, column, 'Se esperaba texto; valor original conservado.')
            if isinstance(value, str) and value != value.strip():
                issue(row, column, 'Espacios iniciales o finales conservados.')
            if column == 'User' and value == '-':
                issue(row, column, 'Identidad no especificada (-).')
            if column == 'Source_IP':
                try:
                    ipaddress.ip_address(str(value))
                except ValueError:
                    issue(row, column, 'Dirección IP inválida.')
        if original.at[row, 'Severity'] not in ('Informational', 'Warning', 'Medium', 'High'):
            issue(row, 'Severity', 'Severidad fuera del catálogo observado; no se calcula riesgo.')
    for row in original.index[original['Log_ID'].duplicated(keep=False)]:
        issue(row, 'Log_ID', 'Identificador duplicado: la trazabilidad requiere también la fila original.')
    for row in original.index[original.drop(columns='Log_ID').duplicated(keep=False)]:
        issue(row, 'Registro', 'Contenido repetido excluyendo Log_ID; no se elimina.')
    return ImportResult(sha256(content).hexdigest(), original, normalized,
                        pd.DataFrame(issues, columns=['Fila Excel', 'Log_ID', 'Campo', 'Problema']), sheets)

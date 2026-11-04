"""Tres correlaciones reproducibles. No confirma incidentes ni ejecuta comandos."""
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import ntpath
import re

@dataclass(frozen=True)
class Parameters:
    min_failures: int = 4
    failure_minutes: int = 5
    success_minutes: int = 10  # desde el último fallo del grupo
    privilege_minutes: int = 5
    min_proxy: int = 3
    proxy_minutes: int = 10
    service_minutes: int = 30
    high_bytes: int = 100_000_000

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError('Los parámetros deben ser enteros positivos.')

RULES = {
    'AUTH': {'title': 'Fallos seguidos de autenticación exitosa',
             'why': 'Una ráfaga de fallos y un éxito posterior ameritan verificar el uso de credenciales.',
             'false_positives': 'Contraseña recordada tras varios intentos; soporte o pruebas autorizadas.',
             'limits': 'Sin identificador de sesión no se atribuyen privilegios a la sesión del éxito.'},
    'TRANSFER': {'title': 'Compresión seguida de tráfico Proxy',
                 'why': 'La preparación de un archivo y tráfico posterior con entidades coincidentes justifican investigar transferencia de datos.',
                 'false_positives': 'Copias de seguridad, sincronización o envío autorizado de documentos.',
                 'limits': 'No se conoce el contenido transferido ni se demuestra que el tráfico transporte el archivo.'},
    'SERVICE': {'title': 'Servicio instalado y ejecutable observado posteriormente',
                'why': 'Una nueva instalación y procesos de la misma ruta justifican revisar persistencia.',
                'false_positives': 'Instalación o actualización legítima de software.',
                'limits': 'La ruta compartida no demuestra que el servicio haya iniciado los procesos. No se asocia una tarea cercana.'},
}

@dataclass
class Finding:
    finding_id: str
    rule: str
    version: str
    title: str
    start: str
    end: str
    entities: dict
    evidence: list  # referencias {Log_ID, Excel_Row}, en orden temporal
    context: list   # evidencia adicional, nunca misma sesión por defecto
    original_severities: list
    risk: str
    risk_reason: str
    confidence: str
    confidence_reason: str
    confirmation: str
    parameters: dict
    metrics: dict
    justification: str
    false_positives: str
    limitations: str

@dataclass
class DetectionResult:
    findings: list[Finding]
    excluded_rows: list

def known(value):
    return isinstance(value, str) and bool(value.strip()) and value.strip().lower() not in ('-', 'unknown', 'null', 'n/a')

def risk_level(score):
    """Escala ordinal local, no probabilidad: 1 bajo, 2 medio, >=3 alto."""
    return 'bajo' if score <= 1 else 'medio' if score == 2 else 'alto'

def executable(text):
    if not isinstance(text, str):
        return None
    match = re.match(r'^\s*(?:"([^"]+\.exe)"|([^"\s]+\.exe))(?=\s|$)', text, re.I)
    return ntpath.normcase(ntpath.normpath(match.group(1) or match.group(2))) if match else None

def compression(text):
    path = executable(text)
    if not path:
        return False
    args = text.strip()
    if ntpath.basename(path) in ('7z.exe', '7za.exe'):
        return bool(re.match(r'^(?:"[^"]+"|\S+)\s+a\s+\S+', args, re.I))
    if ntpath.basename(path) == 'tar.exe':
        return bool(re.search(r'(?:^|\s)-(?:[a-z]*c[a-z]*)(?=\s|$)', args, re.I) and
                    re.search(r'(?:^|\s)-[a-z]*f(?:\s|$)', args, re.I))
    return False

def service_path(text):
    if not isinstance(text, str):
        return None
    match = re.search(r'(?:^|;)\s*ImagePath\s*=\s*(.+)', text, re.I)
    return executable(match.group(1)) if match else None

def declared_bytes(text):
    if not isinstance(text, str):
        return None
    matches = re.findall(r'(?:^|\s)bytes_out=(\d+)(?=\s|$)', text)
    return int(matches[0]) if len(matches) == 1 else None

def detect(normalized, parameters=None):
    p = parameters or Parameters()
    rows, excluded = [], []
    duplicate_ids = set(normalized.loc[normalized.Log_ID.duplicated(keep=False), 'Log_ID'])
    for index, row in normalized.iterrows():
        event = row.to_dict()
        if (not isinstance(event['Timestamp'], datetime) or event['Timestamp'] != event['Timestamp']
                or not known(event['Log_ID']) or event['Log_ID'] in duplicate_ids):
            excluded.append({'Excel_Row': int(index), 'Reason': 'Fecha inválida o Log_ID ausente/duplicado.'})
            continue
        event['_row'] = int(index)
        rows.append(event)
    rows.sort(key=lambda e: (e['Timestamp'], e['_row']))
    findings = []
    def compatible(a, b, keys):
        return all(known(a[k]) and known(b[k]) and a[k] == b[k] for k in keys)
    def after(a, b, minutes):
        return timedelta(0) < b['Timestamp'] - a['Timestamp'] <= timedelta(minutes=minutes)
    def refs(events):
        return [{'Log_ID': e['Log_ID'], 'Excel_Row': e['_row']} for e in events]
    def emit(rule, events, context, score, reason, metrics, entities, confidence='media'):
        definition = RULES[rule]
        findings.append(Finding(
            f"{rule}:{events[0]['Log_ID']}:{events[-1]['Log_ID']}", rule, '1.0', definition['title'],
            str(events[0]['Timestamp']), str(events[-1]['Timestamp']), entities,
            refs(events), refs(context),
            [{'Log_ID': e['Log_ID'], 'Excel_Row': e['_row'], 'Severity': e['Severity']} for e in events + context],
            risk_level(score), reason, confidence,
            'Confianza en la correlación observada, no en intención maliciosa; faltan vínculos de sesión/proceso o contenido.',
            'no confirmado', asdict(p), metrics, definition['why'], definition['false_positives'], definition['limits']))

    keys = ('Hostname', 'User', 'Source_IP')
    # Cada éxito cierra una secuencia: no reutilizar fallos anteriores a otro éxito.
    for success in rows:
        if not (success['Event_ID'] == '4624' and success['Log_Source'] == 'Security' and success['Result'] == 'Success'):
            continue
        previous = [e['Timestamp'] for e in rows if e['Event_ID'] == '4624' and e['Log_Source'] == 'Security'
                    and e['Result'] == 'Success' and compatible(e, success, keys) and e['Timestamp'] < success['Timestamp']]
        failures = [e for e in rows if e['Event_ID'] == '4625' and e['Log_Source'] == 'Security' and e['Result'] == 'Failure'
                    and compatible(e, success, keys) and e['Timestamp'] < success['Timestamp']
                    and (not previous or e['Timestamp'] > max(previous))]
        chosen = []
        for last in reversed(failures):
            if not after(last, success, p.success_minutes):
                continue
            burst = [e for e in failures if timedelta(0) <= last['Timestamp'] - e['Timestamp'] <= timedelta(minutes=p.failure_minutes)]
            if len(burst) >= p.min_failures:
                chosen = burst
                break
        if chosen:
            context = [e for e in rows if e['Event_ID'] == '4672' and e['Log_Source'] == 'Security'
                       and e['Result'] == 'Success' and compatible(e, success, keys) and after(success, e, p.privilege_minutes)]
            emit('AUTH', chosen + [success], context, 2,
                 'Medio: ráfaga de fallos seguida de éxito. Privilegios cercanos son contexto y no elevan el riesgo automáticamente.',
                 {'failures': len(chosen), 'privilege_context': len(context)}, {k: success[k] for k in keys})

    for anchor in rows:
        if anchor['Event_ID'] == '4688' and anchor['Log_Source'] == 'Security' and anchor['Result'] == 'Success' and compression(anchor['Process_CommandLine']):
            proxy = [e for e in rows if e['Event_ID'] == 'PROXY_ACCESS' and e['Log_Source'] == 'Proxy'
                     and e['Result'] == 'Allowed' and compatible(e, anchor, keys) and after(anchor, e, p.proxy_minutes)]
            if len(proxy) >= p.min_proxy:
                amounts = [declared_bytes(e['Process_CommandLine']) for e in proxy]
                present = [v for v in amounts if v is not None]
                subtotal = sum(present)
                emit('TRANSFER', [anchor] + proxy, [], 3 if subtotal >= p.high_bytes else 2,
                     f"{'Alto' if subtotal >= p.high_bytes else 'Medio'}: secuencia correlacionada; umbral alto de bytes declarados = {p.high_bytes}. No prueba exfiltración.",
                     {'proxy_events': len(proxy), 'bytes_known_sum': subtotal, 'bytes_records': len(present),
                      'bytes_complete': len(present) == len(proxy), 'bytes_total': subtotal if len(present) == len(proxy) else None},
                     {k: anchor[k] for k in keys})
        if anchor['Event_ID'] == '7045' and anchor['Log_Source'] == 'System' and anchor['Result'] == 'Success':
            path = service_path(anchor['Process_CommandLine'])
            if not path:
                continue
            executions = [e for e in rows if e['Event_ID'] == '4688' and e['Log_Source'] == 'Security'
                          and e['Result'] == 'Success' and compatible(e, anchor, ('Hostname',))
                          and executable(e['Process_CommandLine']) == path and after(anchor, e, p.service_minutes)]
            if executions:
                emit('SERVICE', [anchor] + executions, [], 2 if len(executions) >= 2 else 1,
                     'Medio con dos o más procesos posteriores; bajo con uno. La repetición aumenta la prioridad de revisión, no confirma persistencia maliciosa.',
                     {'executions': len(executions), 'path': path}, {'Hostname': anchor['Hostname'], 'Executable': path})
    return DetectionResult(findings, excluded)

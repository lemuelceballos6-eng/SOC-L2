"""Informes SOC en memoria. Consume resultados existentes; no ejecuta reglas ni IA.

Requiere ReportLab. generate_reports devuelve tres PDF como bytes sin escribir
en disco. El llamador decide dónde guardarlos o descargarlos.
"""
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
    TableStyle,
)

from detection import DetectionResult
from importer import ImportResult

NAVY = colors.HexColor('#17354A')
TEAL = colors.HexColor('#007C83')
LIGHT = colors.HexColor('#EEF3F6')
WIDTH = A4[0] - 36 * mm

# Recomendaciones editoriales de investigación, no acciones ejecutadas ni hechos nuevos.
RECOMMENDATIONS = {
    'AUTH': (
        'Revisar los registros originales de inicio de sesión y el acceso autorizado '
        'de la cuenta y del origen. Obtener identificadores de sesión para verificar '
        'si el contexto de privilegios corresponde al acceso observado. La identidad '
        'registrada no identifica por sí sola a la persona o actor real.',
        'Validar con el responsable de la cuenta si los intentos y el acceso estaban '
        'autorizados; preservar los registros completos antes de decidir una respuesta.',
    ),
    'TRANSFER': (
        'Contrastar los registros Proxy completos con la autorización del destino y '
        'del envío. Verificar si el comando produjo un archivo comprimido; obtener '
        'sus metadatos, proceso padre y telemetría de red para investigar si '
        'el tráfico transportó ese archivo.',
        'Revisar qué mide bytes_out en la fuente y la disponibilidad de todos los '
        'registros. Los bytes declarados no acreditan el contenido ni una exfiltración.',
    ),
    'SERVICE': (
        'Verificar la ruta y configuración del servicio contra cambios autorizados. '
        'Obtener hash y firma digital del ejecutable, proceso padre y eventos de '
        'inicio del servicio: estos datos no se deducen del nombre del archivo.',
        'Correlacionar los identificadores de proceso y servicio para determinar el '
        'origen de las ejecuciones. La tarea programada cercana no se atribuye al '
        'servicio sin evidencia adicional.',
    ),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('ReportTitle', fontName='Helvetica-Bold', fontSize=26,
                              leading=30, textColor=NAVY, spaceAfter=14))
    styles.add(ParagraphStyle('ReportHeading', fontName='Helvetica-Bold', fontSize=14,
                              leading=18, textColor=NAVY, spaceBefore=14,
                              spaceAfter=8, keepWithNext=True))
    styles.add(ParagraphStyle('ReportBody', fontName='Helvetica', fontSize=9.5,
                              leading=14, spaceAfter=7, splitLongWords=True))
    styles.add(ParagraphStyle('ReportSmall', parent=styles['ReportBody'], fontSize=8,
                              leading=11, spaceAfter=3))
    styles.add(ParagraphStyle('ReportCell', parent=styles['ReportSmall'], spaceAfter=0))
    return styles


def _value(value):
    if value is None or (not isinstance(value, (dict, list, tuple)) and pd.isna(value)):
        return '(sin dato)'
    return str(value)


def _p(text, styles, kind='ReportBody'):
    # Logs y nombres se imprimen como texto: nunca se interpretan como HTML o código.
    return Paragraph(escape(_value(text)).replace('\n', '<br/>'), styles[kind])


def _count(number, singular, plural):
    return f'{number} {singular if number == 1 else plural}'


def _table(rows, widths, styles, header=False, vertical_padding=5):
    table = LongTable([[_p(cell, styles, 'ReportCell') for cell in row] for row in rows],
                      colWidths=widths, repeatRows=1 if header else 0, hAlign=TA_LEFT)
    commands = [('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 7),
                ('RIGHTPADDING', (0, 0), (-1, -1), 7),
                ('TOPPADDING', (0, 0), (-1, -1), vertical_padding),
                ('BOTTOMPADDING', (0, 0), (-1, -1), vertical_padding),
                ('LINEBELOW', (0, 0), (-1, -1), .3, colors.HexColor('#CBD5DC'))]
    if header:
        commands += [('BACKGROUND', (0, 0), (-1, 0), LIGHT)]
    else:
        commands += [('BACKGROUND', (0, 0), (0, -1), LIGHT)]
    table.setStyle(TableStyle(commands))
    return table


def _validate(imported, analysis):
    """Fallar claramente ante evidencias incoherentes en lugar de inventar valores."""
    if not imported.original.index.is_unique:
        raise ValueError('Las filas originales deben tener un índice único.')
    seen = set()
    for finding in analysis.findings:
        if finding.finding_id in seen:
            raise ValueError('Identificador de hallazgo duplicado.')
        seen.add(finding.finding_id)
        if finding.rule not in RECOMMENDATIONS or finding.risk not in ('bajo', 'medio', 'alto'):
            raise ValueError('Regla o riesgo no admitido por este generador.')
        if not finding.evidence:
            raise ValueError('El hallazgo carece de evidencias.')
        for ref in finding.evidence + finding.context:
            row = ref.get('Excel_Row')
            if row not in imported.original.index or imported.original.at[row, 'Log_ID'] != ref.get('Log_ID'):
                raise ValueError('La evidencia Log_ID/fila no coincide con los registros originales.')


def _scope(imported, analysis, source_name, generated_at, styles):
    dates = imported.normalized['Timestamp'].dropna()
    interval = f'{dates.min()} a {dates.max()}' if len(dates) else 'Sin fechas válidas'
    return [
        _table([
            ('Archivo analizado', source_name),
            ('SHA-256 del Excel', imported.fingerprint),
            ('Hoja y registros', 'SIEM Export | ' + _count(len(imported.original), 'registro', 'registros')),
            ('Intervalo de registros', interval),
            ('Zona horaria de registros', 'No especificada; no se ha supuesto una zona horaria.'),
            ('Generación del documento', generated_at.astimezone(timezone.utc).isoformat(timespec='seconds')),
        ], [43*mm, WIDTH-43*mm], styles),
        Spacer(1, 8),
        _p('Alcance: resultados de las tres reglas seleccionadas y los parámetros '
           'recibidos del motor SOC. No constituyen cobertura completa del Excel. '
           'Una coincidencia temporal no demuestra causalidad; User representa '
           'una identidad registrada, sin acreditar autoría.', styles),
        _p('Este documento no incorpora interpretaciones de Qwen ni consulta Ollama. '
           'Las recomendaciones son propuestas de investigación, no acciones ejecutadas.', styles),
    ]


def _entities(finding):
    labels = {'Hostname': 'Host', 'User': 'Identidad registrada',
              'Source_IP': 'IP de origen', 'Executable': 'Ruta correlacionada'}
    return '; '.join(f'{labels.get(k, k)}: {v}' for k, v in finding.entities.items())


def _observation(f):
    if f.rule == 'AUTH':
        return (f"El motor relaciona {_count(f.metrics['failures'], 'fallo', 'fallos')} con una autenticación "
                'exitosa posterior por identidad registrada, origen y host coincidentes. '
                f"{'Se conserva' if len(f.context) == 1 else 'Se conservan'} "
                f"{_count(len(f.context), 'evento adicional', 'eventos adicionales')} como contexto separado.")
    if f.rule == 'TRANSFER':
        amount = (f"Total declarado: {_count(f.metrics['bytes_total'], 'byte', 'bytes')}."
                  if f.metrics['bytes_complete'] else
                  f"Subtotal conocido: {_count(f.metrics['bytes_known_sum'], 'byte', 'bytes')}; total no determinado.")
        return ('El motor relaciona un evento de creación de proceso cuyo comando '
                'solicita compresión con '
                f"{_count(f.metrics['proxy_events'], 'evento Proxy posterior', 'eventos Proxy posteriores')} "
                'por host, identidad y origen. ' + amount +
                ' No demuestra que el comando terminara, que el archivo se creara '
                'ni que se transfiriera.')
    return ('Un registro de instalación de servicio se relaciona con '
            f"{_count(f.metrics['executions'], 'creación posterior', 'creaciones posteriores')} "
            f"de proceso con la misma ruta: {f.metrics['path']}. "
            'Esto no acredita legitimidad ni origen del binario, o ejecución iniciada por el servicio.')


def _executive(imported, analysis, source_name, generated_at, styles):
    story = [_p('Informe ejecutivo', styles, 'ReportTitle'),
             _p('SOC NIVEL 2 | RESULTADOS PARA REVISIÓN', styles, 'ReportSmall')]
    story += _scope(imported, analysis, source_name, generated_at, styles)
    risks = Counter(f.risk for f in analysis.findings)
    states = Counter(f.confirmation for f in analysis.findings)
    story += [_p('Resumen de resultados', styles, 'ReportHeading'),
              _p(f'{_count(len(analysis.findings), "hallazgo", "hallazgos")}. Riesgo bajo: {risks["bajo"]}; '
                 f'medio: {risks["medio"]}; alto: {risks["alto"]}. '
                 'Estados del motor: ' + '; '.join(f'{state}: {count}' for state, count in states.items())
                 + ('.' if states else 'sin hallazgos.'), styles)]
    if not analysis.findings:
        story.append(_p('Sin hallazgos bajo las reglas seleccionadas. Este resultado '
                        'no acredita ausencia de incidentes.', styles))
    for f in analysis.findings:
        story.append(KeepTogether([_p(f.title, styles, 'ReportHeading'),
                  _p(f'{f.finding_id} | {f.start} a {f.end}', styles, 'ReportSmall'),
                  _p(f'Riesgo calculado: {f.risk}. Confianza analítica: {f.confidence}. '
                     f'Estado de confirmación: {f.confirmation}.', styles),
                  _p(_entities(f), styles), _p(_observation(f), styles),
                  _p(f'Prioridad de revisión: {f.risk_reason}', styles),
                  _p(f'Limitación: {f.limitations}', styles),
                  _p('Acción propuesta: ' + RECOMMENDATIONS[f.rule][0], styles)]))
    story += [_p('Decisiones pendientes', styles, 'ReportHeading'),
              _p('Validar autorizaciones y obtener los registros complementarios '
                 'antes de clasificar un incidente o decidir contención. El nombre '
                 'de un ejecutable no demuestra su función o procedencia. La severidad '
                 'original, el riesgo calculado, la confianza y el estado de '
                 'confirmación son atributos independientes.', styles),
              _p(f'Registros excluidos por el motor: {len(analysis.excluded_rows)}. '
                 'Las observaciones de calidad y los Log_ID completos se detallan '
                 'en el informe técnico.', styles)]
    return story


def _criteria(f):
    p = f.parameters
    if f.rule == 'AUTH':
        return (f"Security/4625/Failure: al menos {_count(p['min_failures'], 'fallo', 'fallos')} en "
                f"{_count(p['failure_minutes'], 'minuto', 'minutos')} (límites inclusivos), con "
                f"Security/4624/Success posterior hasta {_count(p['success_minutes'], 'minuto', 'minutos')} "
                'desde el último fallo. Igualdad exacta de host, identidad y origen '
                'conocidos. Éxito estrictamente posterior; no reutiliza fallos '
                'anteriores a otro éxito. Contexto Security/4672/Success con las '
                f"mismas entidades dentro de {_count(p['privilege_minutes'], 'minuto', 'minutos')} después del éxito, "
                'sin atribuirlo automáticamente a la misma sesión.')
    if f.rule == 'TRANSFER':
        return ('Security/4688/Success registra la creación de un proceso con '
                'argumentos de compresión reconocidos para 7z, 7za o tar; no '
                'confirma que se haya creado el archivo. Se requieren al menos '
                f"{_count(p['min_proxy'], 'evento', 'eventos')} Proxy/PROXY_ACCESS/Allowed "
                f"dentro de {_count(p['proxy_minutes'], 'minuto', 'minutos')} después "
                'del proceso (límite superior inclusivo). Igualdad exacta de host, identidad y origen '
                'conocidos. No exige destino único. Bytes sumados solo cuando '
                'bytes_out tiene un único entero no negativo interpretable. '
                f"Umbral inicial para riesgo alto: {p['high_bytes']} bytes conocidos, "
                'incluso si el total es incompleto.')
    return ('System/7045/Success con ImagePath interpretable y posteriores '
            'Security/4688/Success del mismo host y ruta ejecutable, durante '
            f"{_count(p['service_minutes'], 'minuto', 'minutos')} (límite superior inclusivo). Se normaliza solo la ruta "
            'derivada según convenciones Windows. Una ejecución recibe riesgo '
            'bajo; dos o más, medio. No se exige igualdad de usuario u origen '
            'en esta regla ni se relaciona una tarea por cercanía temporal.')


def _event(ref, role, imported, styles):
    row = imported.original.loc[ref['Excel_Row']]
    # Campos originales completos: no se compactan las evidencias para PDF.
    return _table([
        (f"{role} | {row['Log_ID']}", f"Fila Excel {ref['Excel_Row']} | {row['Timestamp']}"),
        ('Evento / fuente / resultado / severidad original',
         ' | '.join(_value(row[k]) for k in ('Event_ID', 'Log_Source', 'Result', 'Severity'))),
        ('Entidades originales', f"Host: {_value(row['Hostname'])}; identidad registrada: "
         f"{_value(row['User'])}; origen: {_value(row['Source_IP'])}; destino: {_value(row['Destination'])}"),
        ('Descripción original', row['Event_Description']),
        ('Process_CommandLine original', row['Process_CommandLine']),
    ], [57*mm, WIDTH-57*mm], styles, vertical_padding=2.5)


def _technical(imported, analysis, source_name, generated_at, styles):
    story = [_p('Informe técnico', styles, 'ReportTitle'),
             _p('SOC NIVEL 2 | MÉTODO Y EVIDENCIAS', styles, 'ReportSmall')]
    story += _scope(imported, analysis, source_name, generated_at, styles)
    story += [_p('Método y calidad de datos', styles, 'ReportHeading'),
              _p('El generador recibe ImportResult y DetectionResult ya calculados. '
                 'No ejecuta de nuevo las reglas ni calcula riesgo. Las fechas y '
                 'Event_ID normalizados se conservan separados de las celdas '
                 'originales; cada evidencia se valida mediante fila Excel y Log_ID. '
                 'Los umbrales son parámetros iniciales sujetos a pruebas, no '
                 'estándares universales.', styles)]
    blanks = [(column, sum(1 for v in imported.original[column]
                          if pd.isna(v) or (isinstance(v, str) and not v.strip())))
              for column in imported.original.columns]
    story.append(_table([('Columna', 'Valores ausentes (nulo o texto vacío)')] +
                        [(column, count) for column, count in blanks if count],
                        [WIDTH*.6, WIDTH*.4], styles, header=True))
    story.append(_p('Las demás columnas tienen cero valores ausentes según esta '
                    'comprobación; el marcador User=- se informa por separado.', styles))
    story += [_p(f'Observaciones del importador: {len(imported.issues)}. '
                 'Una ausencia no implica por sí sola un evento malicioso.', styles),
              _p('Escala de riesgo del motor: bajo, medio y alto. Se conserva el '
                 'valor calculado y su motivo por hallazgo; la confianza describe '
                 'la interpretación de la correlación y el estado de confirmación '
                 'se mantiene separado. Las severidades originales aparecen en '
                 'cada evento, sin sustituirlas por el riesgo.', styles)]
    if not imported.issues.empty:
        counts = imported.issues.groupby(['Campo', 'Problema'], dropna=False).size()
        story.append(_table([('Campo', 'Observación', 'Cantidad')] +
                            [(field, problem, int(count)) for (field, problem), count in counts.items()],
                            [45*mm, WIDTH-63*mm, 18*mm], styles, header=True))
    story.append(_p(f'Registros excluidos por el motor: {len(analysis.excluded_rows)}.', styles))
    if analysis.excluded_rows:
        story.append(_table([('Fila Excel', 'Motivo')] +
                            [(e['Excel_Row'], e['Reason']) for e in analysis.excluded_rows],
                            [30*mm, WIDTH-30*mm], styles, header=True))
    if not analysis.findings:
        story.append(_p('Sin hallazgos bajo las reglas seleccionadas; no acredita '
                        'ausencia de incidentes.', styles))
    for f in analysis.findings:
        story += [PageBreak(), _p(f.title, styles, 'ReportTitle'),
                  _p(f'{f.finding_id} | Regla {f.rule}, versión {f.version}', styles),
                  _table([
                      ('Intervalo de evidencia', f'{f.start} a {f.end}'),
                      ('Entidades', _entities(f)), ('Riesgo calculado', f.risk),
                      ('Motivo del riesgo', f.risk_reason),
                      ('Confianza analítica', f'{f.confidence}. {f.confidence_reason}'),
                      ('Estado de confirmación', f.confirmation),
                  ], [40*mm, WIDTH-40*mm], styles),
                  _p('Observación reproducible', styles, 'ReportHeading'),
                  _p(_observation(f), styles),
                  _p('Criterios de correlación y parámetros', styles, 'ReportHeading'),
                  _p(_criteria(f), styles),
                  _p('Justificación: ' + f.justification, styles),
                  _p('Falsos positivos posibles: ' + f.false_positives, styles),
                  _p('Limitaciones: ' + f.limitations, styles),
                  _p('Recomendaciones de investigación', styles, 'ReportHeading')]
        story.extend(_p(f'{n}. {text}', styles) for n, text in enumerate(RECOMMENDATIONS[f.rule], 1))
        story += [_p('Evidencias originales completas', styles, 'ReportHeading'),
                  _p(f'{_count(len(f.evidence), "evento", "eventos")} de evidencia y '
                     f'{_count(len(f.context), "evento", "eventos")} de contexto separado. Los campos se reproducen como '
                     'texto; no se ejecutan comandos ni contenido activo.', styles)]
        for ref in f.evidence:
            story.append(KeepTogether([_event(ref, 'Evidencia', imported, styles), Spacer(1, 6)]))
        if f.context:
            story += [_p('Contexto adicional', styles, 'ReportHeading'),
                      _p('No se atribuye automáticamente a la misma sesión.', styles)]
            for ref in f.context:
                story.append(KeepTogether([_event(ref, 'Contexto', imported, styles), Spacer(1, 6)]))
    return story


def _build(story, title):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm,
                            leftMargin=18*mm, topMargin=22*mm, bottomMargin=20*mm,
                            title=title, author='Proyecto académico SOC Nivel 2')

    def decorate(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(TEAL)
        canvas.setLineWidth(1.5)
        canvas.line(18*mm, A4[1]-14*mm, A4[0]-18*mm, A4[1]-14*mm)
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(NAVY)
        canvas.drawString(18*mm, 12*mm, 'SOC L2 | Análisis de registros | Revisión del analista pendiente')
        canvas.drawRightString(A4[0]-18*mm, 12*mm, f'Página {document.page}')
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return buffer.getvalue()


def generate_reports(imported: ImportResult, analysis: DetectionResult, *,
                     source_name='Excel cargado', generated_at=None) -> dict[str, bytes]:
    """Genera ejecutivo, técnico y consolidado con los mismos resultados.

    No acepta respuestas de IA: evita incluir como hechos borradores sin revisión.
    generated_at debe tener zona horaria; no afecta la zona de los logs.
    """
    _validate(imported, analysis)
    generated_at = generated_at or datetime.now(timezone.utc)
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError('La fecha de generación debe incluir zona horaria.')
    styles = _styles()
    args = imported, analysis, source_name, generated_at, styles
    return {
        'ejecutivo': _build(_executive(*args), 'Informe ejecutivo SOC Nivel 2'),
        'tecnico': _build(_technical(*args), 'Informe técnico SOC Nivel 2'),
        'consolidado': _build(_executive(*args) + [PageBreak()] + _technical(*args),
                              'Informe consolidado SOC Nivel 2'),
    }

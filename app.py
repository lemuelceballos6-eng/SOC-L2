"""Interfaz SOC L2: navegación, exploración y evidencias con revisión humana."""
from dataclasses import asdict
from hashlib import sha256
import json

import streamlit as st

from detection import detect
from importer import import_excel, display_records, ValidationError, MAX_BYTES
from local_ai import (
    analyze as analyze_with_local_ai, ask_followup, AIError,
    MAX_HISTORY_TURNS, MAX_QUESTION_CHARS,
)
from dashboard import (
    INTERVAL_MINUTES, category_distribution, category_label, dashboard_metrics,
    distribution_chart, filter_options, filter_records, risk_distribution,
    temporal_distribution, timeline_chart,
)

PDF_STATE = 'soc_pdf_reports'


def show_records(records, *, explicit_row=False, height=280):
    """Vista de lectura con trazabilidad y altura acotada; conserva todas las filas."""
    view = display_records(records)
    if explicit_row:
        view = view.reset_index()
    st.dataframe(
        view, height=height, hide_index=explicit_row,
        column_config={
            'Excel_Row': st.column_config.NumberColumn('Excel_Row', help='Fila original del Excel.'),
            'Timestamp': 'Fecha y hora',
            'Hostname': 'Host',
            'Log_Source': 'Fuente de logs',
            'Severity': 'Severidad original',
            'Event_Description': st.column_config.TextColumn('Descripción original', width='large'),
            'Process_CommandLine': st.column_config.TextColumn('Comando original', width='large'),
        },
    )


def clear_event_filters(fingerprint):
    for column in ('Hostname', 'Severity', 'Log_Source'):
        st.session_state[f'dashboard_{column}_{fingerprint}'] = []


@st.fragment
def render_event_explorer(imported):
    st.subheader('Exploración de eventos', anchor=False)
    st.caption('Esta vista filtra registros y gráficos. Los hallazgos, sus riesgos, la IA y los PDF usan el Excel completo.')
    with st.container(border=True):
        st.markdown('**Filtros de eventos**')
        selections = []
        for container, column, label, placeholder in zip(
                st.columns(3), ('Hostname', 'Severity', 'Log_Source'),
                ('Host', 'Severidad original', 'Fuente de logs'),
                ('Todos los hosts', 'Todas las severidades', 'Todas las fuentes')):
            with container:
                selections.append(st.multiselect(
                    label, filter_options(imported.original, column),
                    format_func=category_label, placeholder=placeholder,
                    help='Puede seleccionar varios valores. Se conservan nombres, mayúsculas y espacios originales.',
                    key=f'dashboard_{column}_{imported.fingerprint}',
                ))
        st.caption('Sin selección se incluyen todos los valores. Los filtros se combinan entre sí; (sin dato) permite consultar ausencias.')
        interval_col, reset_col = st.columns([3, 1])
        with interval_col:
            interval = st.select_slider(
                'Agrupar eventos cada (minutos)', options=INTERVAL_MINUTES, value=15,
                key=f'dashboard_interval_{imported.fingerprint}')
        with reset_col:
            st.button('Limpiar filtros', key=f'dashboard_reset_{imported.fingerprint}',
                      on_click=clear_event_filters, args=(imported.fingerprint,))
    filtered = filter_records(imported.original, hosts=selections[0],
                              severities=selections[1], sources=selections[2])
    st.caption(f'Vista actual: {len(filtered)} de {len(imported.original)} registros importados.')
    if filtered.empty:
        st.info('No hay registros que coincidan con los filtros seleccionados.')
    chronology, distributions, records = st.tabs(['Cronología', 'Severidad y fuente', 'Registros'])
    with chronology:
        timeline = temporal_distribution(imported.normalized.loc[filtered.index],
                                          interval_minutes=interval)
        dated = int(timeline['Eventos'].sum())
        st.markdown('**Eventos por intervalo**')
        st.caption(f'{dated} registros con fecha válida · {len(filtered) - dated} sin fecha válida. '
                   f'Intervalos de {interval} minutos: inicio incluido y fin excluido.')
        if timeline.empty:
            st.info('Sin fechas válidas en los registros seleccionados.')
        else:
            st.altair_chart(timeline_chart(timeline, interval_minutes=interval))
        st.caption('Zona horaria no especificada. Se conserva la hora registrada; solo se dibujan intervalos con eventos. '
                   'Pase el cursor por una barra para ver la fecha completa y la cantidad.')
    with distributions:
        st.caption('Cantidad y porcentaje sobre los eventos de la vista actual, incluidos los valores ausentes.')
        for container, column, title in zip(
                st.columns(2), ('Severity', 'Log_Source'),
                ('Severidad original', 'Fuente de logs')):
            with container:
                st.markdown(f'**{title}**')
                counts = category_distribution(filtered, column)
                if counts.empty:
                    st.info('Sin registros para esta distribución.')
                else:
                    st.altair_chart(distribution_chart(counts, column))
        st.caption('Severity procede del Excel. Es una propiedad del evento y se mantiene separada del riesgo calculado de los hallazgos.')
    with records:
        st.markdown('**Eventos filtrados · valores originales**')
        st.caption('Log_ID y Excel_Row identifican cada registro. Event_ID se presenta como texto solo en pantalla. '
                   'La tabla conserva todas las filas seleccionadas y permite desplazarse dentro de ella.')
        show_records(filtered, explicit_row=True, height=300)
        with st.expander('Consultar el libro completo: originales y vista normalizada'):
            originals, normalized = st.tabs(['Originales', 'Normalizados'])
            with originals:
                st.subheader('Registros originales', anchor=False)
                st.caption('No se eliminan duplicados ni se fusionan hosts. Esta tabla no depende de los filtros.')
                show_records(imported.original, height=300)
            with normalized:
                st.markdown('**Vista normalizada para análisis**')
                st.caption('Las fechas y los identificadores normalizados se conservan separados del Excel original.')
                show_records(imported.normalized, height=300)


def render_dashboard(imported, analysis):
    st.subheader('Resumen general', anchor=False)
    metrics = dashboard_metrics(imported.original, analysis)
    for container, (label, value) in zip(st.columns(4), metrics.items()):
        with container:
            with st.container(border=True):
                st.metric(label, value)
    st.caption(f'Base completa: {len(imported.original)} registros importados. '
               'Analizados cuenta los admitidos por el motor; los excluidos se conservan para consulta.')
    risk_col, scope_col = st.columns([1, 1])
    with risk_col:
        st.markdown('**Hallazgos por riesgo calculado**')
        st.altair_chart(distribution_chart(risk_distribution(analysis), 'Riesgo',
                                          count_column='Hallazgos', risk=True))
    with scope_col:
        with st.container(border=True):
            st.markdown('**Alcance del análisis**')
            st.write('Los indicadores y riesgos utilizan el Excel completo y no cambian al explorar filtros.')
            st.write('Un hallazgo es una prioridad de investigación. La correlación temporal no confirma causalidad ni un incidente.')
            st.caption(f'Calidad de datos: {len(imported.issues)} observaciones para revisar.')
    with st.expander('Revisar la calidad de datos'):
        st.subheader('Calidad de datos', anchor=False)
        st.caption(f'{len(imported.issues)} observaciones. Un campo ausente no implica un incidente.')
        st.dataframe(imported.issues, hide_index=True, height=220)
    if analysis.excluded_rows:
        st.warning(f'{len(analysis.excluded_rows)} registros excluidos por fecha inválida o Log_ID ausente/duplicado.')
        with st.expander('Consultar filas excluidas del motor'):
            st.write(analysis.excluded_rows)


def finding_status(finding):
    risk_col, confirmation_col, confidence_col = st.columns(3)
    color = {'bajo': 'blue', 'medio': 'orange', 'alto': 'red'}[finding.risk]
    risk_col.markdown(f'**Riesgo calculado**\n\n:{color}[{finding.risk.upper()}]')
    confirmation_col.markdown(f'**Confirmación**\n\n{finding.confirmation}')
    confidence_col.markdown(f'**Confianza analítica**\n\n{finding.confidence}')


def render_findings(imported, analysis):
    st.subheader('Hallazgos para investigación', anchor=False)
    st.caption('Abra un hallazgo para revisar su explicación, los registros originales y el método. '
               'Riesgo, confianza y confirmación son atributos independientes.')
    if not analysis.findings:
        st.info('Sin hallazgos bajo las tres reglas seleccionadas; no demuestra ausencia de incidentes.')
    for finding in analysis.findings:
        with st.expander(f'{finding.rule} · {finding.title} · riesgo {finding.risk}'):
            finding_status(finding)
            st.caption(finding.finding_id)
            reading, evidence, method = st.tabs(['Lectura del hallazgo', 'Evidencias originales', 'Método'])
            with reading:
                st.write('Justificación:', finding.justification)
                st.write('Motivo del riesgo:', finding.risk_reason)
                st.write('Confianza:', finding.confidence_reason)
                st.write('Posibles falsos positivos:', finding.false_positives)
                st.write('Limitaciones:', finding.limitations)
            with evidence:
                st.markdown('**Evidencia original**')
                st.caption(f'{len(finding.evidence)} registros · Log_ID y Excel_Row permiten volver a la fuente.')
                show_records(imported.original.loc[[ref['Excel_Row'] for ref in finding.evidence]],
                             height=260)
                if finding.context:
                    st.markdown('**Contexto adicional separado**')
                    st.caption('No se atribuye automáticamente a la misma sesión.')
                    show_records(imported.original.loc[[ref['Excel_Row'] for ref in finding.context]],
                                 height=150)
            with method:
                st.json({key: value for key, value in asdict(finding).items()
                         if key in ('start', 'end', 'entities', 'parameters', 'metrics', 'version')})


def render_local_ai(result, analysis):
    st.subheader('Interpretación asistida por IA local', anchor=False)
    st.caption('Borrador pendiente de revisión humana. La IA no determina el riesgo ni confirma incidentes. '
               'Solo se consulta Ollama en 127.0.0.1 al pulsar el botón. '
               'Los filtros de eventos no reducen la evidencia del hallazgo.')
    if not analysis.findings:
        st.info('No hay hallazgos para solicitar una interpretación.')
        return
    selection = st.selectbox(
        'Hallazgo para analizar', range(len(analysis.findings)),
        format_func=lambda i: f'{analysis.findings[i].rule} · {analysis.findings[i].title}',
        key='local_ai_finding')
    selected = analysis.findings[selection]
    finding_status(selected)
    st.caption(selected.finding_id)
    # Vincula la respuesta al Excel y a una instantánea del hallazgo completo,
    # incluidas evidencias, contexto, versión y parámetros del motor.
    ai_context = (result.fingerprint, selected.finding_id, asdict(selected))
    if st.button('Solicitar interpretación a qwen3:4b en este equipo', key='request_local_ai'):
        try:
            with st.spinner('Consultando Ollama local…'):
                ai_result = analyze_with_local_ai(selected, result.original)
            st.session_state['local_ai_result'] = (ai_context, ai_result)
        except AIError as exc:
            st.session_state.pop('local_ai_result', None)
            st.error(str(exc))
    saved = st.session_state.get('local_ai_result')
    if saved and saved[0] == ai_context:
        ai_result = saved[1]
        st.info(ai_result.review_status)
        explanation, hypotheses, recommendations = st.tabs(['Explicación', 'Hipótesis y límites', 'Recomendaciones'])
        with explanation:
            st.write(ai_result.answer['explicacion'])
        with hypotheses:
            st.markdown('**Hipótesis**')
            st.write(ai_result.answer['hipotesis'])
            st.markdown('**Limitaciones**')
            st.write(ai_result.answer['limitaciones'])
        with recommendations:
            for recommendation in ai_result.answer['recomendaciones']:
                st.markdown(f'- {recommendation}')
        st.caption('Log_ID citados y verificados: ' + (', '.join(ai_result.cited_log_ids) or 'Ninguno'))

    st.divider()
    st.subheader('Preguntas de investigación', anchor=False)
    st.caption(f'Pregunte sobre las evidencias del hallazgo seleccionado (máximo {MAX_QUESTION_CHARS} caracteres). '
               f'Se conservan los últimos {MAX_HISTORY_TURNS} intercambios de esta conversación; se envían '
               'solo turnos completos que quepan en el contexto local. Las respuestas previas no son evidencia.')
    saved_followup = st.session_state.get('local_ai_followup')
    turns = saved_followup['turns'] if saved_followup and saved_followup['context'] == ai_context else []
    context_key = sha256(json.dumps(ai_context, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()
    question = st.text_area('Pregunta sobre este hallazgo', max_chars=MAX_QUESTION_CHARS,
                            height=100, key=f'local_ai_question_{context_key}',
                            placeholder='Por ejemplo: ¿qué evidencias faltan para comprobar esta hipótesis?')
    if st.button('Enviar pregunta a Qwen3 local', key='request_local_ai_followup'):
        try:
            with st.spinner('Consultando el hallazgo en Ollama local…'):
                reply = ask_followup(selected, result.original, question, history=turns)
            turns = (turns + [{'question': question.strip(), 'result': reply}])[-MAX_HISTORY_TURNS:]
            st.session_state['local_ai_followup'] = {'context': ai_context, 'turns': turns}
        except AIError as exc:
            st.error(str(exc))
    for turn in turns:
        with st.container(border=True):
            st.markdown('**Pregunta del analista**')
            st.text(turn['question'])
            reply = turn['result']
            st.info(reply.review_status)
            st.write(reply.answer['explicacion'])
            with st.expander('Hipótesis, limitaciones y verificaciones sugeridas'):
                st.markdown('**Hipótesis**')
                st.write(reply.answer['hipotesis'])
                st.markdown('**Limitaciones**')
                st.write(reply.answer['limitaciones'])
                for recommendation in reply.answer['recomendaciones']:
                    st.markdown(f'- {recommendation}')
            st.caption('Log_ID citados y verificados: ' + (', '.join(reply.cited_log_ids) or 'Ninguno'))


@st.fragment
def pdf_download_buttons(documents, fingerprint):
    for container, kind, label, description in zip(
            st.columns(3), ('ejecutivo', 'tecnico', 'consolidado'),
            ('ejecutivo', 'técnico', 'consolidado'),
            ('Prioridades, alcance y decisiones pendientes.',
             'Método, parámetros y evidencias originales.',
             'Secciones ejecutiva y técnica completas.')):
        with container:
            with st.container(border=True):
                st.markdown(f'**Informe {label}**')
                st.caption(description)
                st.download_button(
                    f'Descargar informe {label}', data=documents[kind],
                    file_name=f'informe_{kind}_{fingerprint[:12]}.pdf',
                    mime='application/pdf', key=f'download_pdf_{kind}',
                )


def render_pdf_reports(imported, analysis, source_name):
    """Conserva un único juego de PDF por sesión, vinculado a sus entradas reales."""
    st.subheader('Informes PDF', anchor=False)
    st.caption('Los tres informes corresponden al Excel completo. Los filtros no cambian su contenido '
               'y los borradores de IA no se incorporan. Funcionan sin Ollama.')
    report_key = (imported.fingerprint, source_name, asdict(analysis))
    saved = st.session_state.get(PDF_STATE)
    if saved is None or saved['key'] != report_key:
        saved = {'key': report_key, 'documents': None}
        st.session_state[PDF_STATE] = saved
        try:
            from reports import generate_reports
            with st.spinner('Generando informes PDF…'):
                saved['documents'] = generate_reports(imported, analysis, source_name=source_name)
        except Exception:
            # No mostramos excepciones que pudieran contener datos de los registros.
            pass
    if saved['documents'] is None:
        st.warning('No se pudieron generar los informes PDF. Los registros y hallazgos '
                   'siguen disponibles. Puede reintentar la generación.')
        if st.button('Reintentar generación de PDF', key='retry_pdf_reports'):
            st.session_state.pop(PDF_STATE, None)
            st.rerun()
        return
    pdf_download_buttons(saved['documents'], imported.fingerprint)


st.set_page_config(page_title='SOC Sentinel', layout='wide', initial_sidebar_state='expanded')
# Estilo constante: no incorpora contenido del Excel ni de la IA.
st.markdown('<style>.block-container {padding-top:1.5rem;padding-bottom:2rem;max-width:1440px;}</style>',
            unsafe_allow_html=True)
st.title('SOC Sentinel', anchor=False)
st.caption('Análisis de registros y correlación de eventos de seguridad.')
with st.sidebar:
    st.header('Fuente de datos', anchor=False)
    upload = st.file_uploader('Seleccione el Excel oficial (máximo 10 MiB)', type=['xlsx'])
    st.caption('Se procesa la hoja SIEM Export. Los valores originales se conservan.')

if upload is None:
    st.session_state.pop(PDF_STATE, None)
    st.info('Cargue el Excel desde el panel lateral para comenzar el análisis.')
else:
    if upload.size > MAX_BYTES:
        st.session_state.pop(PDF_STATE, None)
        st.error('El archivo supera el límite de 10 MiB.')
        st.stop()
    try:
        result = import_excel(upload.getvalue(), upload.name)
    except ValidationError as exc:
        st.session_state.pop(PDF_STATE, None)
        st.error(str(exc))
        st.stop()
    analysis = detect(result.normalized)
    dates = result.normalized['Timestamp'].dropna()
    with st.sidebar:
        st.success('Excel cargado y validado')
        st.write(upload.name)
        st.caption(f'{len(result.original)} registros importados · {len(result.sheets)} hojas')
        st.caption('**Rango de fechas válidas** · Zona horaria no especificada.')
        if len(dates):
            st.write('Desde:', str(dates.min()))
            st.write('Hasta:', str(dates.max()))
        else:
            st.caption('Sin fechas válidas')
        with st.expander('Identificación y trazabilidad del libro'):
            st.write('Hojas:', ', '.join(result.sheets))
            st.write('Hoja analizada: SIEM Export')
            st.caption('SHA-256 del Excel')
            st.code(result.fingerprint, language=None, wrap_lines=True)
    overview, events, findings, ai, reports = st.tabs(['Resumen', 'Eventos', 'Hallazgos', 'IA local', 'Informes'])
    with overview:
        render_dashboard(result, analysis)
    with events:
        render_event_explorer(result)
    with findings:
        render_findings(result, analysis)
    with ai:
        render_local_ai(result, analysis)
    with reports:
        render_pdf_reports(result, analysis, upload.name)

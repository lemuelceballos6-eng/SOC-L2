"""Cálculos y gráficos de exploración SOC, sin modificar registros ni detecciones."""
from collections import Counter
from datetime import datetime, timedelta
import json
from math import ceil

import altair as alt
import pandas as pd

RISKS = ('bajo', 'medio', 'alto')
INTERVAL_MINUTES = (1, 5, 15, 30, 60)
FILTER_COLUMNS = ('Hostname', 'Severity', 'Log_Source')
RISK_COLORS = {'bajo': '#3574A8', 'medio': '#B97714', 'alto': '#C13C46'}


def dashboard_metrics(original, analysis):
    """Analizados cuenta filas admitidas por el motor; las excluidas se conservan."""
    return {
        'Registros analizados': len(original) - len(analysis.excluded_rows),
        'Hallazgos detectados': len(analysis.findings),
        'Hallazgos de riesgo alto': sum(f.risk == 'alto' for f in analysis.findings),
        'Registros excluidos': len(analysis.excluded_rows),
    }


def risk_distribution(analysis):
    counts = Counter(f.risk for f in analysis.findings)
    return pd.DataFrame({'Riesgo': pd.Categorical(RISKS, categories=RISKS, ordered=True),
                         'Hallazgos': [counts[risk] for risk in RISKS]})


def _category_key(value):
    # La identidad incluye el tipo: no fusiona 1, True y "1" si el Excel
    # contiene valores incompatibles con una columna de texto.
    return ('missing', '') if pd.isna(value) else (type(value).__name__, repr(value))


def category_label(value):
    if pd.isna(value):
        return '(sin dato)'
    if isinstance(value, str):
        if value != value.strip() or value == '(sin dato)' or value.startswith('['):
            return repr(value)
        return value
    return f'[{type(value).__name__}] {value}'


def filter_options(original, column):
    """Opciones originales exactas; los nulos se pueden seleccionar como None."""
    values = {}
    for value in original[column]:
        values.setdefault(_category_key(value), None if pd.isna(value) else value)
    return sorted(values.values(), key=lambda value: (category_label(value), _category_key(value)))


def filter_records(original, *, hosts=(), severities=(), sources=()):
    """OR dentro de cada filtro, AND entre filtros. Vacío significa todos."""
    mask = pd.Series(True, index=original.index)
    for column, selected in zip(FILTER_COLUMNS, (hosts, severities, sources)):
        if selected:
            keys = {_category_key(value) for value in selected}
            mask &= original[column].map(lambda value: _category_key(value) in keys)
    return original.loc[mask].copy(deep=True)


def category_distribution(original, column):
    counts = Counter(_category_key(value) for value in original[column])
    labels, amounts, used = [], [], set()
    for value in filter_options(original, column):
        label = category_label(value)
        # Incluso una etiqueta literal igual a una representación especial
        # conserva su propia barra; nunca se agregan categorías diferentes.
        while label in used:
            label += f' [{_category_key(value)!r}]'
        used.add(label)
        labels.append(label)
        amounts.append(counts[_category_key(value)])
    return pd.DataFrame({column: pd.Series(labels, dtype='str'),
                         'Eventos': pd.Series(amounts, dtype='int64')})


def temporal_distribution(normalized, *, interval_minutes=15):
    """Intervalos [inicio, fin), solo con eventos. No convierte zonas horarias.

    Las etiquetas ISO conservan la hora del registro, sin serializarla como UTC
    en el navegador. No se construye una rejilla densa entre fechas muy lejanas.
    """
    if interval_minutes not in INTERVAL_MINUTES:
        raise ValueError('Intervalo temporal no admitido.')
    counts = Counter()
    for value in normalized['Timestamp']:
        if isinstance(value, datetime) and pd.notna(value) and value.tzinfo is None:
            start = value.replace(minute=value.minute // interval_minutes * interval_minutes,
                                  second=0, microsecond=0)
            counts[start.isoformat(sep=' ', timespec='minutes')] += 1
    intervals = sorted(counts)
    return pd.DataFrame({'Intervalo': pd.Series(intervals, dtype='str'),
                         'Eventos': pd.Series([counts[value] for value in intervals], dtype='int64')})


def with_percentages(counts, count_column='Eventos'):
    """Añade etiquetas de presentación sobre una copia; no altera los conteos."""
    view = counts.copy(deep=True)
    total = int(view[count_column].sum())
    view['Porcentaje'] = view[count_column] * 100 / total if total else 0.0
    view['Etiqueta'] = pd.Series(
        [f'{int(number)} · {percentage:.1f}%'.replace('.', ',')
         for number, percentage in zip(view[count_column], view['Porcentaje'])],
        index=view.index, dtype='str',
    )
    return view


def distribution_chart(counts, category, *, count_column='Eventos', risk=False):
    """Barras horizontales con cantidades, porcentajes y etiquetas completas al pasar el cursor."""
    data = with_percentages(counts, count_column)
    maximum = int(data[count_column].max()) if len(data) else 0
    text_color, axis_color = '#F1F5F9', '#CBD5E1'
    label_size, label_gap = 13, 8
    # Reserva píxeles para la etiqueta externa, incluso si la barra es muy pequeña.
    longest = max((len(value) for value in data['Etiqueta']), default=0)
    label_space = max(96, ceil(longest * label_size * 0.75) + label_gap + 12)
    order = list(RISKS) if risk else data.sort_values(count_column, ascending=False)[category].tolist()
    base = alt.Chart(data).encode(
        x=alt.X(f'{count_column}:Q', title=count_column,
                scale=alt.Scale(domain=[0, max(1, maximum)], nice=False),
                axis=alt.Axis(tickMinStep=1, tickCount=4, labelAngle=0, labelOverlap='greedy',
                              labelColor=axis_color, titleColor=text_color,
                              labelFontSize=12, titleFontSize=13, labelPadding=6, titlePadding=10,
                              domainColor='#64748B', tickColor='#64748B', gridColor='#334155')),
        y=alt.Y(f'{category}:N', title=None, sort=order,
                axis=alt.Axis(labelLimit=150, labelFontSize=13, labelPadding=8,
                              labelOverlap=False if category == 'Severity' else alt.Undefined,
                              labelColor=axis_color, titleColor=text_color, titleFontSize=13,
                              domainColor='#64748B', tickColor='#64748B', grid=False)),
        tooltip=[alt.Tooltip(f'{category}:N', title='Riesgo calculado' if risk else category),
                 alt.Tooltip(f'{count_column}:Q', format='d'),
                 alt.Tooltip('Porcentaje:Q', title='Porcentaje (%)', format='.1f')],
    )
    bars = base.mark_bar(color='#277C88')
    if risk:
        bars = bars.encode(color=alt.Color(
            'Riesgo:N', legend=None,
            scale=alt.Scale(domain=list(RISKS), range=[RISK_COLORS[value] for value in RISKS])))
    labels = base.mark_text(color=text_color, align='left', baseline='middle', dx=label_gap,
                            fontSize=label_size, fontWeight=500, clip=False, limit=0).encode(text='Etiqueta:N')
    return (bars + labels).properties(
        height=min(260, max(130, len(data) * 30)),
        padding={'left': 4, 'right': label_space, 'top': 8, 'bottom': 8},
        autosize=alt.AutoSizeParams(type='fit', contains='padding', resize=True),
    ).configure_view(stroke=None).configure_title(color=text_color, fontSize=14)


def timeline_chart(timeline, *, interval_minutes=15):
    """Eje temporal legible con distancias reales entre horas sin zona asignada.

    Los desplazamientos son minutos entre fechas ingenuas. El navegador recibe
    números y etiquetas literales, sin convertir fechas a UTC ni a su zona local.
    """
    data = timeline.copy(deep=True).sort_values('Intervalo')
    starts = [datetime.fromisoformat(value) for value in data['Intervalo']]
    offsets = [int((value - starts[0]).total_seconds() / 60) for value in starts]
    data['Inicio_min'] = pd.Series(offsets, index=data.index, dtype='int64')
    data['Fin_min'] = data['Inicio_min'] + interval_minutes
    count = min(6, len(data))
    ticks = ([round(offsets[-1] * number / (count - 1)) for number in range(count)]
             if count > 1 else ([0] if count else []))
    labels = [(starts[0] + timedelta(minutes=value)).strftime('%d/%m %H:%M') for value in ticks]
    expression = f'{json.dumps(labels)}[indexof({json.dumps(ticks)}, datum.value)]'
    return alt.Chart(data).mark_bar(color='#277C88').encode(
        x=alt.X('Inicio_min:Q', title='Fecha y hora registrada · día/mes y hora',
                scale=alt.Scale(domain=[0, offsets[-1] + interval_minutes if offsets else 1], nice=False),
                axis=alt.Axis(values=ticks, labelExpr=expression, labelAngle=0,
                              labelOverlap='greedy', labelLimit=120, labelFontSize=11)),
        x2='Fin_min:Q',
        y=alt.Y('Eventos:Q', title='Eventos', axis=alt.Axis(tickMinStep=1, tickCount=4)),
        tooltip=[alt.Tooltip('Intervalo:N', title='Inicio del intervalo · sin zona horaria'),
                 alt.Tooltip('Eventos:Q', title='Eventos', format='d')],
    ).properties(height=210).configure_view(stroke=None)

"""Regresión de la conversión Arrow real y de la ejecución Streamlit."""
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
import logging

import pandas as pd
import pyarrow as pa
import pytest
from streamlit.testing.v1 import AppTest

from importer import display_records, import_excel
from detection import detect

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / 'SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx'

def test_mixed_ids_and_filtered_queries():
    original = pd.DataFrame({
        'Log_ID': ['A', 'B', 'C', 'D', 'E'],
        'Event_ID': [4625, 'PROXY_ACCESS', 'HTTP_ACCESS', None, '04624'],
    }, index=pd.Index([2, 7, 9, 12, 13], name='Excel_Row'))
    before = original.copy(deep=True)
    # Reproduce exactamente la incompatibilidad que escapaba a las pruebas.
    with pytest.raises(pa.ArrowInvalid):
        pa.Table.from_pandas(original)
    view = display_records(original)
    assert view.Event_ID.tolist()[:3] == ['4625', 'PROXY_ACCESS', 'HTTP_ACCESS']
    assert pd.isna(view.loc[12, 'Event_ID'])
    assert view.loc[13, 'Event_ID'] == '04624'
    for subset in [view, view[view.Event_ID.isin(['4625', 'PROXY_ACCESS'])],
                   view.query("Event_ID == 'HTTP_ACCESS'"), view.iloc[:0],
                   display_records(original.iloc[[0, 1]])]:
        table = pa.Table.from_pandas(subset)
        assert table.num_rows == len(subset)
        assert table['Log_ID'].to_pylist() == subset.Log_ID.tolist()
        assert table['Excel_Row'].to_pylist() == subset.index.tolist()
    pd.testing.assert_frame_equal(original, before)

def test_official_app_serialization(caplog):
    if not DATASET.exists():
        pytest.skip('Dataset oficial no disponible')
    content = DATASET.read_bytes()
    result = import_excel(content, DATASET.name)
    original = result.original.copy(deep=True)
    for frame in (result.original, result.normalized):
        view = display_records(frame)
        assert pa.Table.from_pandas(view).num_rows == 715
        proxy = view.query("Event_ID == 'PROXY_ACCESS'")
        assert pa.Table.from_pandas(proxy).num_rows == 22
    pd.testing.assert_frame_equal(result.original, original)
    upload = BytesIO(content)
    upload.name = DATASET.name
    upload.size = len(content)
    # Inyecta solo la entrada de carga: app.py y st.dataframe se ejecutan realmente.
    with patch('streamlit.file_uploader', return_value=upload):
        with caplog.at_level(logging.WARNING):
            app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=20)
    assert not app.exception
    assert not app.error
    assert app.metric[0].value == '715'
    frames = [element.value for element in app.dataframe]
    expected = [result.issues, display_records(original).reset_index(),
                display_records(original), display_records(result.normalized)]
    for finding in detect(result.normalized).findings:
        for references in (finding.evidence, finding.context):
            if references:
                expected.append(display_records(original.loc[[ref['Excel_Row'] for ref in references]]))
    assert len(frames) == len(expected)
    for frame, view in zip(frames, expected):
        # Arrow representa nulos como NaN en algunas columnas de texto.
        pd.testing.assert_frame_equal(frame.astype(object).where(frame.notna(), None),
                                      view.astype(object).where(view.notna(), None), check_dtype=False)
    assert not any('arrow' in r.getMessage().lower() or 'serializ' in r.getMessage().lower()
                   for r in caplog.records)
    assert DATASET.read_bytes() == content

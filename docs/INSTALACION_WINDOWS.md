# Instalación y verificación en Windows 11

SOC Sentinel es una aplicación académica desarrollada en el contexto del proyecto SOC Nivel 2. Esta guía explica cómo prepararla y ejecutarla desde PowerShell. Lea también el [README del proyecto](../README.md), que describe arquitectura, reglas y límites analíticos.

Los pasos de instalación y descarga que siguen son para el evaluador. En la auditoría documental del Bloque 6D no se instalaron herramientas, no se descargaron modelos ni se eliminó ningún entorno. La compatibilidad de los comandos se contrastó con la estructura, las ayudas locales disponibles y la documentación oficial; no se afirma haber realizado una instalación limpia.

## 1. Prerrequisitos verificables

| Elemento | Requisito o comprobación |
| --- | --- |
| Sistema | Windows 11 y PowerShell. Las comprobaciones locales se realizaron con Windows PowerShell 5.1. |
| Python | Python 3.12.14 de 64 bits fue validado únicamente en el entorno existente; no dispone de un instalador binario oficial para Windows. La selección y prueba de un intérprete distribuible siguen pendientes. pandas 3.0.1 requiere >=3.11; ese requisito no verifica la compatibilidad del proyecto con otras versiones. |
| Archivos | Copia autorizada del código con `app.py`, los módulos del README, `requirements.txt`, `tests/test_detection_synthetic.py` y `tests/test_display.py`. No se necesita Git para ejecutar el proyecto. |
| Evidencias | Para analizar datos se necesita un Excel `.xlsx` autorizado compatible. La suite pública no necesita ese libro; determinadas pruebas internas requieren el archivo de integración, cuya distribución autorizada sigue pendiente. No se incorpora a esta documentación. |
| Ollama | Instalación local para la funcionalidad opcional de IA, con la etiqueta exacta `qwen3:4b`. Importación, reglas, dashboard y PDF pueden usarse sin Ollama. |
| Red y recursos | Acceso autorizado para obtener Python, paquetes y el modelo. Disco y memoria suficientes para Ollama y el modelo; el proyecto no ha establecido un mínimo de RAM ni un rendimiento garantizado. |
| Navegador | Navegador local para acceder a Streamlit y guardar descargas PDF. |

Python **3.12.14** fue validado únicamente en el entorno existente y **no dispone de un instalador binario oficial para Windows**. La selección y prueba de un intérprete distribuible siguen pendientes; no se presenta otra versión como verificada. Para esa selección futura, consulte el [sitio oficial](https://www.python.org/downloads/windows/) y sus [instrucciones de instalación para Windows](https://docs.python.org/3.12/using/windows.html). Los pasos siguientes describen el procedimiento una vez seleccionado y probado dicho intérprete, con Python y pip habilitados y accesibles mediante PATH; no acreditan que esa selección o una instalación limpia se hayan completado.

No es necesario instalar Microsoft Excel, 7-Zip, Docker, WSL, Poppler ni un SDK Python de Ollama para el funcionamiento implementado. La aplicación lee comandos registrados; no ejecuta herramientas de compresión. ReportLab crea los PDF y pypdf se usa en las pruebas internas.

## 2. Abrir PowerShell en la carpeta del proyecto

En el Explorador de archivos, abra la carpeta entregada que contiene `app.py` y abra PowerShell en esa ubicación. Todos los comandos siguientes usan rutas relativas a esa carpeta, sin depender de una ruta personal.

```powershell
Get-Location
Test-Path -LiteralPath '.\app.py' -PathType Leaf
Test-Path -LiteralPath '.\requirements.txt' -PathType Leaf
Test-Path -LiteralPath '.\tests\test_detection_synthetic.py' -PathType Leaf
Test-Path -LiteralPath '.\tests\test_display.py' -PathType Leaf
Get-Command python -ErrorAction Stop
python --version
python -c "import struct, sys; print(sys.version.split()[0]); print(struct.calcsize('P') * 8)"
```

Las cuatro comprobaciones de archivos deben devolver `True`; el último comando debe mostrar la versión elegida y `64`. Si `python` no se reconoce o abre la tienda de aplicaciones, deténgase y complete su instalación/configuración de PATH. Cierre y vuelva a abrir PowerShell. No use una `.venv` copiada de otro equipo para resolverlo.

## 3. Crear y activar .venv

Primero compruebe que no va a reutilizar accidentalmente un entorno existente:

```powershell
if (Test-Path -LiteralPath '.\.venv') {
    throw 'Ya existe .venv. Revise ese entorno antes de crear otro o use la seccion de reversion.'
}
python -m venv .venv
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -c "import sys; print(sys.prefix != sys.base_prefix)"
```

La última salida debe ser `True`. La [documentación de venv](https://docs.python.org/3.12/library/venv.html) explica que el entorno depende de su intérprete base y debe recrearse al mover el proyecto, no copiarse como instalación portátil.

Para activarlo en PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Si la política de ejecución bloquea el script, puede omitir la activación y utilizar los comandos completos `.\.venv\Scripts\python.exe` de esta guía. La activación solo facilita el PATH; no es obligatoria. No necesita deshabilitar políticas de seguridad ni abrir PowerShell como administrador para esta alternativa.

## 4. Instalar las dependencias declaradas

```powershell
.\.venv\Scripts\python.exe -m pip --version
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

El último comando debe informar que no hay requisitos incompatibles. Si falta pip, el intérprete estándar permite prepararlo con `.\.venv\Scripts\python.exe -m ensurepip`; después repita la comprobación. No agregue paquetes a mano para ocultar errores ni cambie `requirements.txt` sin autorización.

Declaraciones actuales, sin modificaciones en el Bloque 6D:

| Dependencia | Declaración exacta | Uso |
| --- | --- | --- |
| Streamlit | `streamlit>=1.40,<2` | Interfaz y AppTest. |
| Altair | `altair>=5,<7` | Gráficos del dashboard. |
| pandas | `pandas==3.0.1` | Tablas y vistas de registros. |
| openpyxl | `openpyxl==3.1.5` | Lectura y validación del libro; libros de prueba en memoria. |
| ReportLab | `reportlab==4.4.9` | Generación PDF. |
| pytest | `pytest>=8,<10` | Suites pública e interna. |
| pypdf | `pypdf>=6,<7` | Lectura independiente de PDF en la suite interna. |

pip también resuelve dependencias transitivas. Por ejemplo, PyArrow se usa para las tablas y Starlette en las pruebas de descarga con el Streamlit instalado; no son nuevas instrucciones de instalación separada. No hay un archivo de bloqueo que fije todo el conjunto.

Puede consultar versiones sin cambiar el entorno:

```powershell
.\.venv\Scripts\python.exe -c "import importlib.metadata as m; print('\n'.join(f'{n}=={m.version(n)}' for n in ('streamlit','altair','pandas','openpyxl','reportlab','pytest','pypdf')))"
```

## 5. Preparar Ollama y Qwen3

Instale Ollama mediante su [descarga oficial para Windows](https://ollama.com/download/windows) y abra la aplicación. Ollama ofrece una aplicación nativa que puede quedar ejecutándose en segundo plano. Sus requisitos y controladores están en la [documentación de Windows](https://docs.ollama.com/windows). Reserve espacio adicional para el modelo; la [ficha de `qwen3:4b`](https://ollama.com/library/qwen3:4b) indica aproximadamente 2,5 GB de descarga, que no equivalen a la memoria necesaria durante la inferencia.

Abra una PowerShell nueva después de instalar. Compruebe el comando y la API local:

```powershell
Get-Command ollama -ErrorAction Stop
Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/version' -Method Get -TimeoutSec 10
(Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -Method Get -TimeoutSec 10).models | Where-Object { $_.name -eq 'qwen3:4b' } | Select-Object name
```

La primera solicitud devuelve la versión del servidor. La segunda debe encontrar `qwen3:4b`; la ausencia de salida indica que no aparece esa etiqueta en la lista. `/api/tags` es el [endpoint oficial de modelos disponibles](https://docs.ollama.com/api/tags).

Si falta el modelo, y dispone de autorización y conexión para descargarlo, ejecute:

```powershell
ollama pull qwen3:4b
ollama ls
```

`pull` descarga y `ls` lista modelos según la [referencia oficial de la CLI](https://docs.ollama.com/cli). Espere a que la descarga termine y repita la consulta de `/api/tags`. No sustituya la etiqueta por `qwen3`, `latest`, variantes Instruct u otro tamaño: el código utiliza exactamente `qwen3:4b`. La etiqueta no fija de forma inmutable el contenido del modelo; documentar su digest en una entrega reproducible está pendiente.

Si la API no responde y Ollama no está ya iniciado, abra otra terminal para el servidor manual:

```powershell
$env:OLLAMA_HOST = '127.0.0.1:11434'
ollama serve
```

Mantenga esa terminal abierta. La variable anterior solo afecta a ese proceso y a sus hijos; no cambia una aplicación Ollama que ya estuviera abierta. No ejecute dos servidores en el mismo puerto. Si utiliza la aplicación de la bandeja y necesita corregir su dirección, siga la [configuración oficial para Windows](https://docs.ollama.com/faq), manteniendo el enlace local `127.0.0.1:11434`.

La integración utiliza `/api/chat`, respuestas JSON con esquema y `think=false`. No se declara en el proyecto una versión mínima de Ollama comprobada. En esta auditoría respondió la API **0.40.13** y se encontró `qwen3:4b`; esto no certifica toda versión anterior ni constituye una nueva prueba de precisión del modelo.

## 6. Iniciar Streamlit en conexión local

En una terminal situada en la raíz del proyecto:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

Abra **http://127.0.0.1:8501** manualmente. `--server.headless true` evita la apertura automática del navegador; `--browser.gatherUsageStats false` desactiva las estadísticas de uso de Streamlit. `-X utf8` evita errores de codificación observados al imprimir la ayuda en una consola Windows. La forma de ejecutar y las opciones se contrastaron con la ayuda instalada y la [CLI oficial de Streamlit](https://docs.streamlit.io/develop/api-reference/cli/run), junto con su [referencia de configuración](https://docs.streamlit.io/develop/api-reference/configuration/config.toml).

Si 8501 está ocupado, conserve el proceso existente y use otro puerto libre, por ejemplo:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m streamlit run app.py --server.address 127.0.0.1 --server.port 8502 --server.headless true --browser.gatherUsageStats false
```

En ese caso abra **http://127.0.0.1:8502**. No cambie la dirección a una interfaz pública para resolver un conflicto de puerto. La aplicación no implementa autenticación de usuarios para una exposición compartida.

Sin Excel cargado debe aparecer una invitación a seleccionar el archivo en el panel lateral. Para comprobar únicamente que el servidor responde, puede consultar en otra terminal:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8501/_stcore/health' -Method Get -TimeoutSec 10
```

Espere `ok`; ajuste el puerto a 8502 si corresponde. Esta comprobación verifica el servidor, no la carga de evidencias ni todo el comportamiento de la interfaz.

## 7. Cargar el Excel autorizado

1. En el panel lateral **Fuente de datos**, use **Seleccione el Excel oficial (máximo 10 MiB)** y elija el `.xlsx` autorizado. Puede estar fuera de la carpeta del código.
2. El libro debe contener `SIEM Export`, con la primera fila formada exactamente por las 12 columnas listadas en el README. Tener una extensión correcta no basta.
3. Espere **Excel cargado y validado**. Compruebe cantidad de registros, rango de fechas y huella en **Identificación y trazabilidad del libro**.
4. Abra **Resumen → Revisar la calidad de datos**. Revise ausencias, fechas, tipos y duplicados antes de interpretar hallazgos.
5. Si hay filas excluidas por el motor, revise su detalle. Permanecen en los originales; el programa no las borra del Excel.

No se utiliza un archivo predeterminado por su presencia en la carpeta. No convierta el original, cambie sus columnas, elimine fórmulas o altere evidencias para superar una validación: solicite una copia compatible autorizada. Las fechas de los registros no tienen zona horaria asignada.

## 8. Recorrer las pestañas y verificar correlaciones y filtros

| Pestaña | Qué hacer y comprobar |
| --- | --- |
| **Resumen** | Revise registros analizados, hallazgos detectados, hallazgos de riesgo alto y registros excluidos. Consulte distribución de riesgos y calidad de datos. Son métricas del libro completo. |
| **Eventos** | Filtre por Host, Severidad original y Fuente de logs. Dentro de un filtro se admite cualquiera de los valores seleccionados; entre filtros se exige coincidencia conjunta. Sin selección se incluyen todos. Use **Limpiar filtros** para restablecerlos. |
| **Eventos → Cronología** | Pruebe agrupaciones de 1, 5, 15, 30 y 60 minutos. Los intervalos incluyen el inicio y excluyen el final. Solo se dibujan intervalos con eventos; no se transforma la zona horaria. |
| **Eventos → Severidad y fuente / Registros** | Contraste las distribuciones con la tabla filtrada. En el desplegable del libro completo consulte **Originales** y **Normalizados**, independientes de los filtros. |
| **Hallazgos** | Abra un hallazgo; compare **Lectura del hallazgo**, **Evidencias originales** y **Método**. Verifique Log_ID, fila original, parámetros, métricas y contexto separado. |
| **IA local** | Seleccione un hallazgo y realice una solicitud manual como se explica más adelante. |
| **Informes** | Descargue y revise los tres PDF, según la sección siguiente. |

Para evaluar las reglas sin necesitar el Excel, ejecute `tests/test_detection_synthetic.py` mediante el comando público de la sección 11: comprueba las tres correlaciones, ventanas, coincidencia de entidades, umbrales, eventos no admitidos y límites de causalidad. La suite pública añade la regresión de visualización; la integración con datos oficiales pertenece a la suite interna.

En la interfaz, confronte cada hallazgo con los criterios AUTH, TRANSFER y SERVICE del README. No presuponga que cualquier Excel generará tres hallazgos ni todos los niveles de riesgo. **Sin hallazgos** significa que no se cumplieron las tres reglas, no que no existan incidentes.

Seleccione filtros que reduzcan o vacíen la tabla de Eventos. Deben cambiar esa vista y sus gráficos, mientras se conservan métricas globales, hallazgos, riesgos, evidencia de IA y contenido analítico de los informes. Cambiar el intervalo modifica la agrupación gráfica, no las ventanas de las reglas.

## 9. Generar y descargar informes

Al cargar un libro válido, Streamlit ejecuta la generación de los tres PDF en memoria; no existe un botón previo obligatorio de generación. En **Informes** encontrará:

- **Descargar informe ejecutivo:** alcance, resumen, entidades, riesgos, observaciones, límites y recomendaciones de investigación.
- **Descargar informe técnico:** añade calidad de datos, criterios, parámetros y los campos originales completos de cada evidencia y contexto de los hallazgos.
- **Descargar informe consolidado:** contiene las secciones ejecutiva y técnica completas.

Los nombres de descarga siguen `informe_ejecutivo_<huella>.pdf`, `informe_tecnico_<huella>.pdf` e `informe_consolidado_<huella>.pdf`; `<huella>` representa los primeros 12 caracteres del SHA-256 del libro, no texto que deba escribirse manualmente. El navegador elige el destino de guardado. No se necesita crear una carpeta de salida para usar estos botones.

Abra los documentos con un visor PDF y compruebe que no están vacíos, identifican la fuente y su huella, mantienen el estado de confirmación y permiten volver a las filas originales. La cantidad de páginas depende de los datos. Los informes no incluyen los textos generados por Qwen ni se recalculan al filtrar Eventos.

Si falla la generación, la interfaz conserva registros y hallazgos, muestra un aviso y ofrece **Reintentar generación de PDF**. Compruebe ReportLab y las dependencias con `pip check`. La validación de referencias puede impedir un informe incoherente; no suprima ese control para obtener una descarga.

## 10. Consultar la IA local

1. Compruebe la API local y la presencia de `qwen3:4b` según la sección 5.
2. Abra **IA local**, seleccione **Hallazgo para analizar** y revise su riesgo, confianza y confirmación.
3. Pulse **Solicitar interpretación a qwen3:4b en este equipo**. Revise **Explicación**, **Hipótesis y límites**, **Recomendaciones** y los Log_ID verificados.
4. En **Preguntas de investigación**, escriba hasta 500 caracteres y pulse **Enviar pregunta a Qwen3 local**. Por ejemplo: «¿Por qué se asignó este riesgo? Cita las evidencias y separa hechos, hipótesis y datos que faltan para confirmar el incidente».
5. Lea primero el aviso de revisión y el fundamento determinista que acompaña las preguntas. En TRANSFER muestra volumen declarado, cobertura, total completo o desconocido y umbral; no convierte el hallazgo en exfiltración confirmada.
6. Contraste la respuesta con el registro original y las limitaciones. Una identidad registrada no demuestra autoría; un comando no prueba creación del archivo; la proximidad entre compresión y Proxy no acredita transferencia del archivo.

El tiempo de espera predeterminado es 90 segundos. El contexto y el historial son acotados; TRANSFER puede enviarse como muestra con agregados completos. El historial conserva hasta tres intercambios en la interfaz y no se considera nueva evidencia. Una respuesta con citas inválidas, esquema incorrecto o tamaño excesivo se rechaza expresamente.

El modelo puede equivocarse aunque las citas existan. Se conserva su texto original junto a las cautelas del código; no lo trate como conclusión pericial. Las recomendaciones son propuestas, no acciones que la aplicación haya ejecutado. La IA no ejecuta contención ni altera reglas, datos o PDF.

## 11. Ejecutar las pruebas

### Suite pública incluida en el repositorio

La copia pública contiene `tests/test_detection_synthetic.py` y `tests/test_display.py`. Las 21 pruebas del motor utilizan datos creados en el propio módulo; la regresión de visualización comprueba identificadores mixtos y serialización Arrow. No importan auxiliares de otras pruebas.

Desde la raíz, ejecute exactamente:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_detection_synthetic.py tests/test_display.py
```

Sin el Excel oficial, se recogen 23 casos: **22 deben aprobar y 1 debe omitirse**. El caso omitido es la prueba opcional oficial de `test_display.py`; la omisión no valida la integración. No se necesita crear, copiar, renombrar ni obtener el libro para ejecutar la suite pública.

**Resultado real del Bloque 6E.5, 3 de noviembre de 2026: 22 aprobadas y 1 omitida.** Se usó la entrada CLI de pytest con los argumentos anteriores dentro de un proceso controlado: el libro se presentó como inexistente y su apertura quedó bloqueada; también se bloqueó la lectura de módulos privados. No se leyó el Excel ni se importaron pruebas excluidas durante esa ejecución.

El arnés de validación fue temporal, en memoria y no forma parte de la distribución. Desactivó la escritura de artefactos y sustituyó la reserva temporal inicial de AppTest por un objeto sin carpeta real; no ejecutó AppTest. Usó captura de salida en memoria y no modificó archivos de dependencias. La ejecución en un equipo limpio sigue pendiente.

La cobertura pública se limita a AUTH, TRANSFER y SERVICE con datos sintéticos y a la regresión de visualización. No verifica IA, PDF, el dashboard completo, la importación del libro oficial ni toda la interfaz. Con el libro autorizado presente, el caso opcional puede ejecutarse, pero su aprobación no demuestra independencia del archivo.

### Suite interna con datos autorizados

El conjunto interno original consta de 13 módulos y no se distribuye íntegramente. Determinadas fixtures necesitan el archivo literal `SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx`, con su contenido autorizado, en la raíz junto a `app.py`. Ese nombre es un requisito de integración interna; el cargador manual admite otros libros compatibles autorizados. El procedimiento de distribución del archivo sigue pendiente.

**Última validación completa, Bloque 6E.5, 3 de noviembre de 2026: 220 pruebas y 3 subpruebas aprobadas en 81,03 s.** Incluye importación, AppTest, IA con respuestas controladas, dashboard, PDF y descargas HTTP en proceso. No requiere un Ollama activo para las respuestas simuladas.

Para conservar el conteo original, esta ejecución interna excluyó `tests/test_detection_synthetic.py`; sus 21 casos ya existen en las pruebas internas. Se mantuvo el Excel disponible y se conservaron las pruebas y sus aserciones originales. Los temporales XML de openpyxl se serializaron a `BytesIO` mediante ajustes en memoria; se evitó crear la carpeta temporal inicial de AppTest y se permitieron únicamente los pares de sockets locales usados por asyncio. El control de escrituras permaneció activo. No se cambiaron dependencias en disco ni se validó una instalación limpia.

El comando público evita importar módulos privados o depender de fixtures ausentes en una copia pública. Los antiguos comandos generales de pytest, la selección por `not official` y el recorrido unittest del importador no son instrucciones para esa copia. El antecedente del Bloque 6D, con el mismo conteo interno, se conserva en la sección 15.

## 12. Errores habituales y soluciones seguras

| Síntoma | Comprobación y respuesta |
| --- | --- |
| `python` u `ollama` no se reconoce | Compruebe `Get-Command`, termine la instalación oficial y abra otra terminal. La API puede funcionar aunque la CLI de Ollama no esté en el PATH. No reinstale ni descargue el modelo solo por ese error. |
| `Activate.ps1` bloqueado | Use directamente `.\.venv\Scripts\python.exe`. No es necesario cambiar la política de ejecución. |
| pip ausente | Use `-m ensurepip` dentro de `.venv` y después los comandos de la sección 4. |
| `WinError 10013`, fallo TLS o índice inaccesible | Revise conectividad, proxy y políticas con el responsable del equipo. No desactive antivirus, cortafuegos o verificación TLS. Un error posterior de distribución no demuestra incompatibilidad si no se pudo consultar el índice. |
| `ModuleNotFoundError` | Confirme que usa el Python de `.venv`, complete `pip install -r requirements.txt` y ejecute `pip check`. No importe bibliotecas desde una instalación personal ajena al entorno. |
| Importación de rutas internas de Streamlit falla en pruebas | Registre las versiones resueltas. El rango declarado permite versiones que no se han probado; los tests de descargas usan APIs internas. Documente el bloqueo y solicite una decisión de compatibilidad; no edite pruebas ni agregue paquetes para disimularlo. |
| Puerto 8501 ocupado | Use el comando completo con 8502 de la sección 6. No cierre un proceso ajeno sin identificarlo. |
| Archivo rechazado | Revise `.xlsx`, límites, hoja y columnas, fórmulas y vínculos no admitidos. Preserve el original y solicite un archivo autorizado compatible. |
| No aparecen hallazgos | Revise calidad, exclusiones y criterios de las reglas. No altere evidencias para forzar coincidencias. |
| Fechas, identificadores mixtos o campos ausentes | Consulte observaciones y las vistas original/normalizada. La conversión visual de `Event_ID` a texto no cambia el original. |
| Ollama no responde o vence la espera | Verifique la API y la instancia local; revise recursos del equipo. Una consulta puede exceder 90 s. Importación, reglas y PDF siguen disponibles. No modifique el código para ocultar el error. |
| HTTP 404 o modelo no encontrado | Confirme la etiqueta `qwen3:4b` mediante `/api/tags`. Si falta, obténgala solo con autorización; la integración no la descarga automáticamente. |
| Respuesta IA inválida, extensa o con citas no enviadas | Formule una pregunta más concreta y vuelva a solicitar manualmente. No complete citas ni acepte como evidencias eventos fuera de la muestra. |
| Falla un PDF | Compruebe dependencias, conserve el aviso y use el reintento. Una referencia inválida debe investigarse, no ignorarse. |
| Error de caché de pytest | Utilice el comando documentado con `-p no:cacheprovider`. No cambie permisos generales para ejecutar las pruebas. |
| `UnicodeEncodeError` en la consola | Ejecute la CLI con `-X utf8`, como en los comandos de arranque. No recodifique las evidencias para corregir la salida de la consola. |

## 13. Detener la aplicación

1. Descargue los informes que necesite conservar y revise su manejo autorizado. Las conversaciones y los PDF en memoria no constituyen un archivo persistente de casos.
2. Pulse **Ctrl+C** en la terminal que inició Streamlit. Cerrar la pestaña del navegador no detiene el servidor.
3. Si activó `.venv`, ejecute `deactivate` en esa terminal cuando vuelva el indicador de PowerShell.
4. Si inició **su propia** instancia manual de `ollama serve`, deténgala con Ctrl+C en su terminal. Si usa la aplicación de la bandeja, puede salir desde ella cuando no la necesiten otras tareas. Detener Streamlit no detiene Ollama.

## 14. Revertir el entorno virtual, solo si es necesario

**Eliminar `.venv` borra su intérprete asociado y los paquetes instalados dentro de esa carpeta, además de cualquier archivo que se hubiera guardado allí por error. La acción no se deshace con `deactivate`.** Respalde primero lo que necesite y cierre Streamlit y otros procesos que usen ese entorno. La siguiente operación no desinstala Python del sistema ni Ollama, y no elimina sus modelos ni archivos del proyecto que estén fuera de `.venv`.

Abra una PowerShell nueva en la raíz correcta. Compruebe visualmente la ruta completa que se mostrará y confirme solo si apunta al entorno de este proyecto. Este bloque no se ejecutó durante la auditoría:

```powershell
$raizProyecto = (Get-Location).ProviderPath
if (-not (Test-Path -LiteralPath '.\app.py' -PathType Leaf) -or -not (Test-Path -LiteralPath '.\requirements.txt' -PathType Leaf)) {
    throw 'No se reconoce la carpeta del proyecto.'
}
$entornoProyecto = Get-Item -LiteralPath '.\.venv' -Force -ErrorAction Stop
$rutaEsperada = Join-Path -Path $raizProyecto -ChildPath '.venv'
if (-not $entornoProyecto.PSIsContainer -or $entornoProyecto.FullName -ne $rutaEsperada -or ($entornoProyecto.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw 'El destino no es la carpeta .venv local esperada; no se elimina.'
}
if (-not (Test-Path -LiteralPath (Join-Path -Path $entornoProyecto.FullName -ChildPath 'pyvenv.cfg') -PathType Leaf)) {
    throw 'No se reconoce un entorno virtual; no se elimina.'
}
$entornoProyecto.FullName
Remove-Item -LiteralPath $entornoProyecto.FullName -Recurse -Confirm
```

La comprobación rechaza enlaces o uniones de directorio y exige la ruta `.venv` dentro de la raíz actual. No sustituya el destino por la raíz del proyecto. Tras eliminarlo, repita las secciones 3 y 4 para reconstruirlo. La validación limpia de ese procedimiento continúa pendiente; no se probó una eliminación real.

## 15. Verificación realizada y pendientes

Conjunto observado durante el Bloque 6D, el **2 de noviembre de 2026**; es un registro de validación, no un cambio ni una fijación adicional de dependencias:

| Componente | Versión observada |
| --- | --- |
| Python | 3.12.14 |
| Streamlit | 1.66.1 |
| Altair | 6.3.0 |
| pandas | 3.0.1 |
| openpyxl | 3.1.5 |
| ReportLab | 4.4.9 |
| pytest | 9.2.0 |
| pypdf | 6.21.4 |
| PyArrow / Starlette, transitivas | 26.0.0 / 1.10.0 |
| Servidor Ollama, leído mediante API | 0.40.13 |

Resultados históricos del Bloque 6D:

- `.venv` disponible y aislada de los paquetes del sistema según su configuración; `pip check` sin requisitos incompatibles.
- Suite completa: **220 pruebas y 3 subpruebas aprobadas en 131,15 s**. No se cambiaron pruebas ni código de producción.
- Selecciones internas previas: **26 pruebas y 3 subpruebas aprobadas** y **6 casos del importador aprobados mediante unittest**. Son antecedentes de pruebas privadas; no corresponden a la suite pública del Bloque 6E.5.
- Opciones de Streamlit reconocidas por la ayuda instalada. El puerto 8501 ya estaba ocupado; se conservó ese proceso. Arranque temporal en `127.0.0.1:8502`, salud `ok` y página HTTP 200, seguido de la detención del proceso creado para comprobarlo.
- API Ollama accesible y etiqueta `qwen3:4b` presente. No se descargó el modelo ni se repitió una consulta de inferencia en este bloque. La CLI de Ollama y el comando global `python` no estaban disponibles en el PATH de la consola de auditoría; se utilizó el ejecutable de `.venv`.
- Los comandos de creación, instalación, descarga y eliminación se revisaron sin ejecutarlos. AppTest verifica la interfaz en proceso; no se realizó una nueva sesión manual completa de navegador.
- Se analizaron los 17 bloques PowerShell del README y esta guía con el analizador de Windows PowerShell 5.1, sin errores de sintaxis. Ese análisis no ejecuta los bloques ni demuestra que una instalación o eliminación se haya completado.

Queda pendiente seleccionar y probar un intérprete distribuible, ejecutar estos pasos de principio a fin en Windows 11 limpio, fijar versiones de entrega con autorización, validar el rango de Streamlit y definir el procedimiento de distribución autorizada del archivo de integración necesario para determinadas pruebas. No existe un instalador propio ni un archivo de bloqueo del entorno. Las notas históricas del proyecto pueden describir estados anteriores y contener información del entorno; revise su contenido antes de distribuirlas y use esta guía para la instalación actual.

El Bloque 6E.5 prepara exclusivamente la selección pública de pruebas, su lista blanca y esta documentación. No prepara commits, configura remotos, publica el repositorio ni incorpora evidencias originales. Cualquier publicación posterior requiere autorización.

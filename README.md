# SOC Sentinel — Análisis de registros y correlación de eventos de seguridad

Aplicación académica en Python y Streamlit para revisar un Excel autorizado de eventos, validar su calidad y priorizar hallazgos mediante tres correlaciones deterministas. Integra interpretación opcional con Ollama y **Qwen3 4B (`qwen3:4b`)**, y genera informes PDF para revisión humana.

El proyecto ayuda a relacionar registros y conservar su trazabilidad durante una investigación SOC de nivel 2. Busca hacer explícitos los criterios, las evidencias y la información faltante. No confirma ataques ni identifica autores reales, y no sustituye al analista. Es un prototipo académico, sin certificación empresarial ni cobertura completa de detección.

## Funcionalidades implementadas

- Carga manual de `.xlsx`, validación de estructura y observaciones de calidad sin modificar el archivo de origen.
- Conservación de valores originales, vista normalizada separada, fila `Excel_Row`, referencias `Log_ID` y huella SHA-256 del libro.
- Correlaciones AUTH, TRANSFER y SERVICE, con parámetros, motivo del riesgo, evidencias, contexto y limitaciones consultables.
- Dashboard con métricas globales, distribución de riesgos y exploración de eventos por host, severidad original, fuente e intervalo temporal.
- Interpretación y preguntas manuales a la IA local sobre el hallazgo seleccionado, con citas verificadas y advertencias de revisión humana.
- Informes ejecutivo, técnico y consolidado, generados en memoria y descargables por separado. Funcionan sin Ollama e incluyen resultados del motor, sin incorporar borradores de IA.
- Suite pública de correlaciones sintéticas y regresión de visualización; suite interna de integración conservada fuera de la distribución pública completa.

La interfaz tiene cinco pestañas principales: **Resumen**, **Eventos**, **Hallazgos**, **IA local** e **Informes**. La [guía de Windows 11](docs/INSTALACION_WINDOWS.md) explica su uso y los criterios para verificar cada una.

## Arquitectura y flujo

| Archivo o carpeta | Responsabilidad |
| --- | --- |
| [app.py](app.py) | Entrada Streamlit: carga, navegación, sesiones, presentación de hallazgos, consultas manuales y descargas. |
| [importer.py](importer.py) | Valida el libro, conserva originales y crea normalización, observaciones de calidad y SHA-256. Adapta `Event_ID` a texto solo al mostrar tablas. |
| [detection.py](detection.py) | Ejecuta las tres reglas sobre la vista normalizada. Devuelve hallazgos y filas excluidas; no depende de Streamlit ni de la IA. |
| [dashboard.py](dashboard.py) | Calcula métricas, filtros y gráficos de exploración sin cambiar registros ni resultados SOC. |
| [local_ai.py](local_ai.py) | Construye contexto acotado, consulta Ollama local y valida formato y referencias. Añade fundamento determinista y cautelas independientes del modelo. |
| [reports.py](reports.py) | Valida referencias a originales y genera los tres PDF con ReportLab, sin ejecutar nuevamente reglas ni consultar IA. |
| [tests/](tests/) | Suite pública: [correlaciones sintéticas](tests/test_detection_synthetic.py) y [regresión de visualización](tests/test_display.py). Las demás pruebas internas quedan excluidas. |
| [requirements.txt](requirements.txt) | Dependencias declaradas de ejecución y pruebas. |
| [docs/INSTALACION_WINDOWS.md](docs/INSTALACION_WINDOWS.md) | Instalación, operación local, verificación y resolución de problemas. |

```text
Excel autorizado
  -> validación y normalización (importer.py)
  -> correlación determinista (detection.py)
  -> dashboard y revisión de evidencias (Streamlit)
       -> IA local opcional: interpretación y preguntas sobre un hallazgo
       -> PDF: resultados del motor y evidencias originales
```

Los PDF utilizan el Excel completo y el análisis determinista; no necesitan pasar por la IA. Los filtros de Eventos cambian tablas y gráficos de esa vista, pero no modifican hallazgos, riesgos, evidencia enviada a la IA ni informes. Las métricas generales también usan el libro completo.

## Entrada y trazabilidad

Se analiza exclusivamente la hoja **`SIEM Export`**, aunque el libro pueda contener otras hojas. Su primera fila debe tener exactamente estas 12 columnas, en cualquier orden:

```text
Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP,
Destination, Log_Source, Event_Description, Process_CommandLine,
Result, Severity
```

Se admiten hasta **10 MiB** de archivo, **50 MiB** descomprimidos, **2.000 entradas internas** del contenedor y **50.000 filas de datos**. Son límites de aceptación, no garantías de rendimiento a ese volumen. Se rechazan formatos distintos de `.xlsx`, archivos incompatibles, fórmulas en la hoja analizada y libros con macros, vínculos externos, conexiones u objetos no admitidos.

Las fechas pueden ser valores de fecha Excel o texto `AAAA-MM-DD HH:MM:SS`, sin zona horaria. El importador informa ausencias, fechas inválidas, tipos incompatibles y duplicados. Conserva registros no vacíos y valores originales; las filas completamente vacías se omiten. El motor excluye fechas inválidas y `Log_ID` ausentes o duplicados sin borrar esos registros de la vista original. `Excel_Row` permite volver a la fila fuente.

La aplicación acepta la estructura, no acredita la legitimidad ni la autorización del archivo. El archivo de integración se necesita para determinadas pruebas internas; la suite pública no lo requiere y el procedimiento de distribución autorizada está pendiente. Esta documentación no reproduce sus registros.

## Correlaciones y parámetros actuales

Los intervalos siguientes exigen eventos posteriores en el tiempo y admiten el extremo final indicado. Los nombres de entidades se comparan exactamente; no se fusionan variantes de host o de identidad.

| Regla | Condición implementada | Riesgo calculado y límites |
| --- | --- | --- |
| **AUTH** | Al menos 4 `Security/4625/Failure` en 5 minutos, seguidos de `Security/4624/Success` hasta 10 minutos después del último fallo, con `Hostname`, `User` y `Source_IP` conocidos e iguales. No reutiliza fallos anteriores a otro éxito. | **Medio**. Eventos `Security/4672/Success` de las mismas entidades hasta 5 minutos después del éxito se conservan como contexto separado; no elevan automáticamente el riesgo ni prueban una misma sesión. |
| **TRANSFER** | `Security/4688/Success` con comando reconocido de compresión (`7z.exe a`, `7za.exe a` o `tar.exe` con opciones de creación y archivo), seguido de al menos 3 `Proxy/PROXY_ACCESS/Allowed` en 10 minutos, con las mismas tres entidades. No exige destino único. | **Medio**, o **alto** si la suma conocida de enteros válidos `bytes_out` alcanza **100.000.000 bytes**. Con valores faltantes o inválidos se conserva la suma conocida y el total queda desconocido; esa suma parcial también puede alcanzar el umbral. No prueba creación del archivo, transferencia de ese archivo ni exfiltración. |
| **SERVICE** | `System/7045/Success` con `ImagePath` interpretable y al menos un `Security/4688/Success` del mismo host y ruta ejecutable en los siguientes 30 minutos. Normaliza únicamente la ruta derivada según convenciones Windows. | **Bajo** con una ejecución posterior; **medio** con dos o más. La ruta compartida no demuestra que el servicio iniciara esos procesos ni acredita persistencia maliciosa. No atribuye tareas cercanas al servicio. |

Estos parámetros locales están definidos en `Parameters`, en `detection.py`; no son estándares universales ni se editan desde la interfaz. La escala es ordinal: bajo, medio y alto. No representa una probabilidad ni una puntuación CVSS.

## Severidad, riesgo, confianza y confirmación

| Concepto | Significado en esta aplicación |
| --- | --- |
| **Severidad original** | Valor `Severity` de cada evento del Excel; se conserva, incluso si requiere revisión de calidad. No determina el riesgo del hallazgo. |
| **Riesgo calculado** | Prioridad asignada por las reglas y sus parámetros, con un motivo reproducible. Qwen no la recalcula. |
| **Confianza analítica** | Actualmente `media`, acompañada de una explicación sobre la correlación observada. No es una medición estadística de intención maliciosa. |
| **Confirmación** | El motor emite `no confirmado`. La aplicación no ofrece un flujo para confirmar incidentes ni cambia ese estado por una respuesta de IA. |

Una coincidencia temporal no demuestra causalidad. `User` representa una identidad registrada y no identifica por sí solo a la persona o actor real. Tampoco se deduce la legitimidad de un ejecutable por su nombre. No se fabrican hallazgos para completar categorías de riesgo.

## Asistente Qwen3: alcance y límites

La integración utiliza la biblioteca estándar de Python, sin SDK adicional de Ollama, y envía solicitudes a **`http://127.0.0.1:11434/api/chat`** con el modelo fijo **`qwen3:4b`**, `think=false` y `num_ctx=4096`. No necesita claves de API ni modelos de nube. La etiqueta corresponde al [modelo publicado en Ollama](https://ollama.com/library/qwen3:4b).

Las consultas se realizan únicamente al pulsar los botones de IA local. El contexto corresponde al Excel y al hallazgo seleccionados; los filtros no lo reducen. Para TRANSFER con más de ocho evidencias, se conserva un ancla no Proxy y una muestra de cuatro eventos Proxy, junto con los agregados completos ya calculados por el motor. El aviso indica cuántos eventos se enviaron y cuántos se resumieron.

Las preguntas admiten hasta **500 caracteres**. La interfaz conserva los últimos **3 intercambios** de la conversación actual; al modelo se envían solo turnos completos que quepan en los límites de contexto. El historial no constituye evidencia. El seguimiento limita la entrada completa a 9.000 bytes UTF-8, la respuesta a 2.400 caracteres de JSON y la generación a 512 tokens. Un exceso, una respuesta malformada o una cita no admitida provoca un error explícito.

Cada respuesta a preguntas muestra, aparte del texto original del modelo, el **fundamento determinista**: riesgo, motivo, confirmación y, en TRANSFER, bytes conocidos, cobertura, total y umbral. Las citas se verifican contra la muestra enviada; también se comprueban las menciones oficiales `EVT-<dígitos>` en la prosa. Esto verifica referencias, no la veracidad de todas las afirmaciones asociadas.

Qwen puede confundir muestras con totales, atribuir acciones o presentar inferencias como hechos. El prompt y las advertencias reducen riesgos, pero el detector de atribuciones no es un verificador semántico exhaustivo. Se conserva la respuesta original sin corregirla silenciosamente y se mantienen visibles las cautelas de revisión humana. Las pruebas con respuestas simuladas verifican el código, no la precisión del modelo; esta última requiere consultas reales y evaluación humana.

## Instalación y ejecución rápidas

Consulte primero la [guía completa para Windows 11 y PowerShell](docs/INSTALACION_WINDOWS.md). Python **3.12.14** fue validado únicamente en el entorno existente y no dispone de un instalador binario oficial para Windows. La selección y prueba de un intérprete distribuible siguen pendientes; no se presenta otra versión como verificada. pandas 3.0.1 declara Python **>=3.11**, pero ese requisito no acredita la compatibilidad del proyecto con otras versiones.

Los siguientes comandos describen el procedimiento una vez seleccionado y probado un intérprete distribuible, tarea todavía pendiente. Deben ejecutarse desde la carpeta que contiene `app.py` y `requirements.txt`, **sin un entorno `.venv` previo**:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -X utf8 -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

Abra **http://127.0.0.1:8501**. Cargue el Excel autorizado desde el panel lateral; no se carga automáticamente un archivo por estar en la carpeta del proyecto. Para usar IA, Ollama debe estar iniciado y disponer de `qwen3:4b`; la guía explica cómo instalarlo y obtenerlo. Sin Ollama siguen disponibles importación, correlaciones, dashboard e informes. Detenga Streamlit con **Ctrl+C** en su terminal.

Los comandos de instalación son instrucciones para el evaluador; en el Bloque 6D no se instalaron paquetes ni se descargaron modelos. La instalación desde un equipo limpio permanece pendiente de validación.

## Pruebas automatizadas

### Suite pública

La distribución pública incluye únicamente:

- `tests/test_detection_synthetic.py`: 21 casos sintéticos de AUTH, TRANSFER y SERVICE, con ventanas temporales, coincidencia de entidades, umbrales, exclusiones y límites de causalidad.
- `tests/test_display.py`: regresión de la conversión de identificadores mixtos a Arrow. Conserva una prueba opcional del libro oficial que se omite cuando ese archivo no existe.

Desde la raíz, con las dependencias instaladas en `.venv`, ejecute exactamente:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider tests/test_detection_synthetic.py tests/test_display.py
```

**Validación del Bloque 6E.5, 3 de noviembre de 2026: 22 pruebas aprobadas y 1 omitida**, con el Excel oficial inaccesible para el proceso y los módulos de pruebas privadas bloqueados. La omisión corresponde exclusivamente a la prueba oficial de `test_display.py`; no se cuenta como validación sintética. Los datos y las aserciones sintéticas del motor se conservaron al extraerlos. La guía describe los controles de esta ejecución.

La suite pública no necesita el Excel original ni auxiliares de pruebas privadas. Su cobertura se limita a las correlaciones sintéticas y la regresión de visualización; no valida IA, generación de PDF, todo el dashboard ni una sesión completa de navegador. Si el libro autorizado está presente, la prueba opcional puede ejecutarse, pero eso no sustituye la comprobación de independencia realizada sin acceso a él.

### Suite interna

La suite interna original comprende 13 módulos y necesita el Excel autorizado para completar su cobertura. No se distribuye íntegramente en el repositorio público. Los casos sintéticos extraídos ya pertenecían a ella; el nuevo archivo público no amplía el conteo interno.

**Validación interna del Bloque 6E.5, 3 de noviembre de 2026: 220 pruebas y 3 subpruebas aprobadas en 81,03 s**, con el Excel autorizado y la nueva extracción excluida para no duplicar sus casos. Esta suite incluye importación XLSX, AppTest, IA con respuestas controladas, dashboard y descargas PDF en proceso. Se ejecutó con temporales de openpyxl en memoria y canales locales de asyncio, sin escribir artefactos ni modificar dependencias en disco. No acredita una instalación limpia ni una sesión manual completa de navegador.

El antecedente del Bloque 6D y sus versiones observadas permanecen en la sección 15 de la guía. El comando público anterior selecciona únicamente los dos archivos distribuidos y evita recoger pruebas privadas de una copia interna. `-p no:cacheprovider` evita escribir la caché de pytest y `-B` evita generar bytecode. El Excel, el resto de `tests/`, cachés y temporales permanecen fuera de la lista blanca.

## Seguridad y privacidad

- Utilice solo archivos autorizados y preserve la fuente original. Una huella SHA-256 ayuda a comparar contenidos; no constituye por sí sola una cadena de custodia.
- El importador no consulta servicios externos ni ejecuta comandos presentes en los registros. Los controles del libro no sustituyen un análisis de malware.
- La aplicación procesa las cargas y conserva informes y conversaciones en memoria de sesión; su código no guarda automáticamente el Excel ni los PDF en disco. Las descargas sí quedan donde las guarde el navegador. No hay persistencia de casos ni garantía de conservación entre sesiones.
- La IA recibe campos originales de la evidencia seleccionada, que pueden ser sensibles. Mantenga Ollama y Streamlit en conexiones locales. La configuración documentada desactiva las estadísticas de uso de Streamlit; no constituye una auditoría de privacidad de los programas instalados.
- Los PDF técnico y consolidado reproducen evidencia original completa de los hallazgos y su contexto. Revise su contenido y destinatarios antes de compartirlos.
- No adjunte el Excel, registros identificables, credenciales ni conversaciones con evidencias a materiales públicos. La documentación nueva describe el esquema y los procedimientos sin reproducir registros.

## Estado y pendientes de entrega

El alcance implementado comprende las tres correlaciones, la exploración, la IA local y los tres PDF. No incluye captura en tiempo real, integración con SIEM, gestión persistente de casos, autenticación de usuarios ni contención automática.

Pendientes documentados, sin cambios de código o dependencias en este bloque:

1. **Reproducibilidad:** seleccionar y probar un intérprete distribuible y ejecutar la instalación completa en Windows 11 limpio; ambas tareas están pendientes. La validación de Python 3.12.14 corresponde al entorno existente, cuyo intérprete base es administrado por otra herramienta; `.venv` debe recrearse en cada equipo.
2. **Versiones:** `requirements.txt` combina versiones fijas y rangos. No existe un archivo de bloqueo; las pruebas internas de descargas usan APIs internas de Streamlit. El intervalo declarado no acredita compatibilidad con todas sus versiones. La guía registra el conjunto observado y los pasos de diagnóstico.
3. **IA:** registrar versión de Ollama y versión/digest del modelo en una futura entrega reproducible. El código fija una etiqueta de modelo, no su digest ni una versión mínima de Ollama validada. Mantener revisión de precisión mediante consultas reales.
4. **Datos de evaluación:** definir el procedimiento de distribución autorizada del archivo de integración, todavía pendiente, o, con autorización posterior, una alternativa anonimizada que permita evaluar sin datos sensibles. Determinadas pruebas de la suite interna dependen de ese archivo específico.
5. **Distribución:** revisar las notas históricas y materiales auxiliares antes de compartir el proyecto; algunos contienen información del entorno o evidencias y no son la guía de instalación vigente. El Bloque 6E.5 prepara una selección pública de pruebas y una lista blanca restrictiva, sin preparar commits ni publicar el repositorio.
6. **Límites técnicos y analíticos:** no se ha validado rendimiento de producción ni todas las longitudes posibles de registros. Pueden existir falsos positivos y hallazgos con evidencia compartida; no deben sumarse sus bytes como tráfico único. Las tres reglas no prueban ausencia de otros incidentes y las fechas no tienen zona horaria asignada.

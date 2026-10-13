# Dashboard Wazuh — diseño y plan de implementación

**Objetivo:** dashboard del segundo parcial con Wazuh/API, mapa temático, integración de eventos, búsqueda LDAP condicionada a usuario, hilos y JFreeChart. Entrega autorizada: viernes 16 de octubre de 2026.

**Arquitectura:** Java 17+ y Maven; aplicación Swing, receptor HTTP del JDK, Gson, JNDI y JFreeChart. No reutilizar TrustAllSSLSocketFactory: HTTPS/LDAPS verifican certificados. API del manager para agentes; alertas llegan por integración personalizada, no por un endpoint inventado `/alerts`. Muestra explícita y modo real separados; jamás sustituir errores de red con datos sintéticos.

**Alternativas:** web/Tomcat reproduce la práctica de septiembre pero añade despliegue y frontend; GraphStream facilita relaciones pero JFreeChart/Swing ya existe en el repo y resuelve las gráficas requeridas. Se elige Swing por continuidad y ejecución reproducible.

## Fuentes y alcance

- Clase 18-sep: webhook JSON, Java/Tomcat y enrutamiento por regla: https://notes.granola.ai/d/742f3c34-fb82-4a79-a363-4ef7aa4963e1
- Clase 23-sep: token, agentes, inventario, varias gráficas e integraciones: https://notes.granola.ai/d/e7488c56-b1e5-47a5-8c51-4cf9a41f7d5a
- Las clases también proponen vulnerabilidades/IA/CVSS/KEV. No se atribuyen a los seis requisitos de este encargo ni se implementan como resultados ficticios; la prioridad de este dashboard es mostrar eventos, agentes e identidades.
- API: https://documentation.wazuh.com/current/user-manual/api/index.html
- Integraciones: https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html
- Alertas: https://documentation.wazuh.com/current/user-manual/manager/alert-management.html
- Indexer distinto del manager: https://documentation.wazuh.com/current/user-manual/indexer-api/index.html

## Seis requisitos y aceptación

| Requisito | Implementación | Evidencia exigida |
|---|---|---|
| Wazuh y API | Autenticación POST `/security/user/authenticate?raw=true`, Bearer y GET `/agents` paginado | Servidor HTTP aislado comprueba autenticación, páginas, error y renovación tras 401; real pendiente de acceso |
| Mapas temáticos | Mapa geográfico de símbolos proporcionales coloreados por severidad, GeoLocation lat/lon del evento, sin geolocalización inventada | Eventos con/sin ubicación; coordenadas válidas; muestra reproducible y mapa visible |
| Integraciones | POST `/api/wazuh-events` y script `custom-dashboard` para Wazuh Integrator | POST muestra atraviesa receptor → normalización → almacenamiento → vistas |
| LDAP si hay usuario | JNDI/LDAPS, filtro escapado sAMAccountName/userPrincipalName, sin búsqueda para evento anónimo | LDAP local aislado y casos de inyección, encontrado/ausente/error; AD institucional sólo con credenciales provistas por Javier |
| Hilos | Executor de HTTP/procesamiento y refresco API; Swing EDT sólo para actualización | Pruebas de ingesta concurrente, cierre y actualización sin bloquear EDT |
| JFreeChart | Barras de reglas, severidad y serie temporal sobre los mismos eventos filtrados | Conteos exactos, filtros y render/export de gráficas |

## Contratos compartidos (paquete `edu.up.wazuh`)

Las firmas siguientes son el único contrato entre hojas. A escribe los tipos; B/C consumen sin duplicarlos.

- `model.Alert` record: `String id, Instant timestamp, String agentId, String agentName, String ruleId, int level, String description, String username, String country, Double latitude, Double longitude, String integration`. Ausentes: cadenas vacías y coordenadas null. No almacenar full_log ni payload original.
- `model.Agent` record: `String id, String name, String status, String ip, String os`.
- `model.DirectoryUser` record: `String username, String displayName, String email, String department`.
- `events.AlertParser`: `Alert parse(String json)`; lanza IllegalArgumentException para JSON inválido, regla/fecha inválida, severidad fuera 0..15 y coordenadas inválidas. Acepta JSON Wazuh raíz y envoltorio `alert`.
- `events.EventStore(int capacity)`: `boolean add(Alert alert, DirectoryUser user, String ldapStatus)`, `List<EventStore.Entry> snapshot()`, `int size()`; record público anidado `Entry(Alert alert, DirectoryUser user, String ldapStatus)`. Deduplicar id; snapshot inmutable; eviction FIFO acotado.
- `ldap.DirectoryLookup`: `Optional<DirectoryUser> find(String username) throws Exception`, extiende AutoCloseable con default close vacío.
- `ldap.JndiDirectoryLookup(String url, String bindDn, String password, String baseDn)`: implementa DirectoryLookup, contexto por consulta, timeout y recursos cerrados. No credenciales UP implícitas.
- `api.WazuhApiClient(URI baseUri, String username, String password)`: `List<Agent> fetchAgents() throws IOException, InterruptedException`; token en memoria, HTTPS seguro, HTTP sólo loopback para pruebas; no toString de secretos.
- `ui.DashboardPanel(EventStore store, boolean demo)`: `void refresh()`, `void setAgents(List<Agent> agents)`, `void setStatus(String status)`; sólo EDT. Incluye tabla seleccionable/detalle LDAP, filtros nivel/agente/búsqueda, mapas y gráficas. Consumir Entry y Alert sin modificar.
- C es dueño del coordinador, instancia clientes y maneja resultado LDAP; B recibe store, no ejecuta I/O.

## Hojas, propietarios y secuencia

1. **A / DataServices:** sólo `src/main/java/edu/up/wazuh/{model,api,events,ldap}/**` y tests correspondientes. Parser, store, API y LDAP con pruebas deterministas; no Git ni vault. Entregar firmas exactas y evidencia. Dependencias tests: JUnit Jupiter y UnboundID LDAP SDK (sólo test).
2. **B / DashboardViews:** sólo `src/main/java/edu/up/wazuh/ui/**`, tests ui y recursos geográficos si necesarios. Swing/JFreeChart/mapa y filtros; no Git ni vault. Trabaja en paralelo contra contratos A.
3. **C / RuntimeDelivery:** sólo pom.xml, `src/main/java/edu/up/wazuh/app/**`, tests app, `src/main/resources/demo/**`, `scripts/**`, README.md del dashboard, `.env.example`, docs/DEMO.md y docs/CONFIGURATION.md. Coordinación hilos, receptor protegido (token runtime), integración y CLI `--demo`, `--headless-smoke`, `--live`; no Git ni vault. Pruebas E2E app y guía equipo.
4. **Orch-sl:** .gitignore, este plan, saneo/publicación privada, ejecución central de build/tests/smoke, integración vía propietario de hoja, nota avances del vault y comunicación. No código de producto inline.
5. **Reviewer independiente:** lectura de las tres hojas, seguridad, contratos y seis requisitos; devuelve hallazgos, nunca edita ni se autoaprueba.

**Ejecución:** todas las hojas saltan builds/tests/lint/formatters durante el lote; el orquestador ejecuta una vez al acabar y devuelve fallas al writer correspondiente. Pico ≤3 implementers; reviewer posterior; profundidad 1, sin subdelegación. Cada interno informa rol/superficie asumida, modelo efectivo observado o no observado, inicio/fin, archivos cambiados y handoff; sólo el orquestador registra el recibo.

## Plan de pruebas y operación

- `mvn test package`: parser campos Unix/Windows y VirusTotal, LDAP escaping/servidor aislado, API paginación y 401, dedupe/eviction y concurrencia, webhook auth/malformed/ingesta.
- Ejecutar jar con `--demo --headless-smoke`: cargar alertas sintéticas, workers, receptor y render PNG; reportar IDs/conteos y salida, sin secretos.
- Abrir ventana real `--demo`, seleccionar evento con usuario, cambiar filtros, observar mapa/tabla/gráficas; si no se puede automatizar interfaz nativa, conservar prueba de render y declarar ese límite.
- Modo real sólo con WAZUH_API_URL/USER/PASSWORD y LDAP_URL/BIND_DN/BIND_PASSWORD/BASE_DN inyectadas. Sin estos valores se muestra el estado no configurado, no una prueba real exitosa.
- Webhook loopback por defecto. Exposición de red y configuración del manager son operaciones humanas autorizadas aparte; token compartido por entorno y transporte HTTPS mediante proxy/VPN para tráfico remoto.
- Documentar cada variable por nombre, propósito y obtención. No usar secreto de inscripción del agente como credencial del manager.

## Auditoría previa al primer commit

Extractor local emitió sólo rutas, números de línea y booleanos. Se detectaron asignaciones literales sensibles en Ldap.java, server/ValidaDerby.java y ProcesaEventos/src/java/utils/MandaCorreo.java; archivo ZIP de ProcesaEventos también contiene candidatos sensibles. Resto de ZIP/binarios y configuraciones legadas quedan fuera por lista permitida, sin borrarlos ni copiarlos. La vigencia de dichos valores no se comprobó ni se necesita para excluirlos.

La publicación inicial incluye sólo .gitignore, README raíz y dashboard-wazuh. Antes de cada commit, revisar el conjunto a publicar sin emitir valores. Repo PRIVADO no sustituye el saneo.

## Gates observados

Owner: universidad-meta; unidad y writer: orch-sl; autorización directa de Javier para continuar sin esperar y publicar privado. Sesión visible OMP `term_ac36114c-84b4-4cd4-b236-5e2b446dec18`; modelo observado GPT-6.1-Sol medium; cwd observado `/Users/javar/github/unipanam/opensourceSystemNLangs`. Wake probado mediante lectura mm_38c3f24a8666 y respuesta mm_bf080bcb2ff0. Contrato del vault es single-writer universidad-meta: orch-sl no lo modifica; recibos/evidencia viven en nota de avances de la materia. No había commits, remoto ni implementación anterior del nuevo dashboard que cortar.

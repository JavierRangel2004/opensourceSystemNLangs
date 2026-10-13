# Dashboard Wazuh

Dashboard para el segundo parcial de Sistemas y Lenguajes de Código Abierto
(Universidad de Panamá). Integra la API del Wazuh Manager, un mapa temático
geográfico, la ingesta por una integración personalizada (webhook), la
búsqueda LDAP condicional al usuario del evento, hilos acotados y gráficas
JFreeChart — los seis requisitos del encargo del 2026-10-13.

## Modos de ejecución

`--demo` y `--live` son mutuamente excluyentes. Sin argumentos se imprime
la ayuda y se sale con código 2.

| Modo | Comando | Necesita |
|---|---|---|
| Demo Swing | `java -jar target/dashboard-wazuh.jar --demo` | Ningún secreto, ningún manager |
| Demo headless (smoke) | `java -jar target/dashboard-wazuh.jar --demo --headless-smoke` | Java 17, headless AWT |
| Live | `java -jar target/dashboard-wazuh.jar --live` | Variables `WEBHOOK_TOKEN`, `WAZUH_API_*` y opcionalmente `LDAP_*` |
| Ayuda | `java -jar target/dashboard-wazuh.jar` | (sin args) |

El script `scripts/demo-launcher.sh` detecta automáticamente el binario de
Java portable (Homebrew, SDKMAN, `JAVA_HOME`) y aplica los flags necesarios.

## Compilación

```bash
mvn -B package
# Produce target/dashboard-wazuh.jar (shaded, ejecutable).
```

Java 17+, Maven 3.8+, sin dependencias externas en runtime: Gson y
JFreeChart se incluyen en el uber-jar.

## Pruebas

```bash
mvn -B test package    # unitarias + integraciones HTTP/LDAP aisladas + jar
mvn -B verify          # las mismas pruebas y el ciclo completo de Maven
```

Las pruebas arrancan servidores HTTP y LDAP reales en loopback; verifican
API/paginación/401, identidades LDAP, parser, filtros y concurrencia. Ningún
servicio institucional se contacta. Evidencia ejecutada: `docs/VERIFICATION.md`.

## Estructura

```
dashboard-wazuh/
├── pom.xml                       ← Maven shaded jar (Java 17)
├── README.md                     ← este archivo
├── .env.example                  ← nombres de variables, sin secretos
├── docs/
│   ├── PLAN.md                   ← contrato entre hojas (no se edita aquí)
│   ├── DEMO.md                   ← guía de la demo
│   └── CONFIGURATION.md          ← variables, TLS, LDAP, integración Wazuh
├── scripts/
│   ├── custom-dashboard          ← script Python (stdlib) para Wazuh Manager
│   ├── demo-launcher.sh          ← launcher portable (Homebrew/SDKMAN/JAVA_HOME)
│   └── ossec-integration.xml     ← snippet <integration> para ossec.conf
├── src/main/java/edu/up/wazuh/app/
│   ├── DashboardApplication.java ← CLI principal, valida args, conecta API→panel
│   ├── AppConfig.java            ← flags y env vars
│   ├── TokenStore.java           ← token Bearer runtime
│   ├── WebHookServer.java        ← receptor HTTP autenticado (202/400/401/405/413)
│   ├── IngestionCoordinator.java ← cola y pool acotados + estados LDAP
│   ├── ApiRefreshService.java    ← refresco de agentes del manager
│   ├── DemoDataLoader.java       ← carga alertas sintéticas del classpath
│   ├── DemoDirectoryLookup.java  ← lookup SINTÉTICO para el modo demo
│   └── HeadlessSmokeRunner.java  ← smoke real con render a PNG
├── src/main/resources/demo/
│   └── alerts.json               ← 12 alertas MUESTRA (coordenadas reales)
└── src/test/java/edu/up/wazuh/app/
    ├── TokenStoreTest.java
    ├── IngestionCoordinatorTest.java
    ├── ApiRefreshServiceTest.java
    └── WebHookServerE2ETest.java ← E2E con HttpServer + HttpClient reales
```

## Seis requisitos (resumen)

| # | Requisito | Dónde vive |
|---|---|---|
| 1 | Wazuh y API | `api.WazuhApiClient` (hoja A) + `ApiRefreshService` (hoja C) |
| 2 | Mapas temáticos | `ui.DashboardPanel` (hoja B) usa lat/lon del evento |
| 3 | Integraciones | `WebHookServer` + script `custom-dashboard` + XML |
| 4 | LDAP si hay usuario | `ldap.JndiDirectoryLookup` (hoja A) + `IngestionCoordinator` |
| 5 | Hilos | `Executor` acotado para ingesta; EDT sólo para `DashboardPanel.refresh()` |
| 6 | JFreeChart | `ui.DashboardPanel` (hoja B) |

Ver `docs/PLAN.md` para los contratos exactos y `docs/CONFIGURATION.md`
para variables, TLS y permisos.

## Privacidad y secretos

- El token Bearer se genera con `SecureRandom` en tiempo de ejecución y
  **nunca** se imprime. El script `custom-dashboard` lo lee de
  `argv[2]`, de la variable de entorno `CUSTOM_DASHBOARD_TOKEN` o del
  archivo `/etc/wazuh-dashboard/token` (modo 0640 `root:wazuh`) si el
  servicio del Manager no hereda la variable.
- En modo `--live`, `WEBHOOK_TOKEN` es obligatorio: el Integrator debe
  poder autenticarse con el receptor. En modo `--demo` se genera runtime.
- Los errores LDAP se reportan como `error` sin filtrar el detalle ni
  el nombre de usuario.
- El estado de la API se reporta con un motivo (`ok:N`, `error:Clase`)
  sin URL ni credenciales.
- Los datos del modo **demo** están marcados como `MUESTRA` en el JSON y
  usan coordenadas reales como referencia con usuarios **SINTÉTICOS**.
  El modo `--demo` utiliza `DemoDirectoryLookup` que marca
  explícitamente los `DirectoryUser` como `DEMO` y **nunca** contacta al
  AD institucional, ni siquiera si las variables LDAP están presentes.

## Limitaciones (alcance del parcial)

- La clase también propuso vulnerabilidades / IA / CVSS / KEV; esos
  puntos **no** forman parte de los seis requisitos y no se simulan
  en este dashboard.
- El modo live requiere acceso a un Wazuh Manager real y a un AD/LDAPS
  cuyas credenciales sólo Javier puede inyectar. Sin esos valores, el
  dashboard muestra `not-configured` (no rellena con muestra).
- Se verificaron el render PNG y una ventana Swing nativa. La automatización
  de clics quedó limitada por el foco de macOS/Orca; recorrer manualmente
  filtros y detalles antes de presentar.

## Aviso

No se incluyen ni se exponen secretos institucionales: tokens, contraseñas,
claves o URLs internas se inyectan por variables de entorno o archivos
restringidos. Los datos sintéticos del modo demo son explícitos y nunca
se confunden con resultados reales.
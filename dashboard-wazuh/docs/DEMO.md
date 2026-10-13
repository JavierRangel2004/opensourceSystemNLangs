# Guía de demostración

Esta guía explica cómo arrancar la **demo** del dashboard Wazuh para el
segundo parcial y cómo presentarla en clase. Está pensada para un equipo
que todavía no tiene acceso a un Wazuh Manager ni a un AD/LDAPS real.

## 1. Alcance de la demo

- Carga 12 alertas sintéticas (`src/main/resources/demo/alerts.json`)
  marcadas con la bandera `MUESTRA`. Nueve tienen coordenadas geográficas
  de referencia; tres no tienen ubicación y se cuentan explícitamente
  sin inventar coordenadas. Los usuarios son **SINTÉTICOS**.
- No se contacta al Wazuh Manager: la UI muestra estado `demo`,
  no una autenticación real ni un inventario acreditado del manager.
- No se contacta al AD/LDAPS institucional. El modo `--demo` utiliza
  `DemoDirectoryLookup` que devuelve `DirectoryUser` con la marca
  explícita `DEMO` (departamento `DEMO`, email `@demo.invalid`) para
  mostrar el camino `found` sin claim de LDAP real. Esto aplica incluso
  si las variables `LDAP_*` están presentes en el entorno: el modo
  `--demo` está totalmente aislado de credenciales reales.
- El token Bearer se genera con `SecureRandom` en tiempo de ejecución;
  no se imprime ni se persiste.

## 2. Arranque

### 2.1 Compilar el jar

```bash
mvn -B test package
```

Genera `target/dashboard-wazuh.jar` (uber-jar shaded, Java 17).

### 2.2 Demo Swing (ventana nativa)

```bash
java -jar target/dashboard-wazuh.jar --demo
```

Se abre una ventana con la tabla de eventos, el mapa temático (símbolos
proporcionales coloreados por nivel), las gráficas de JFreeChart
(conteos por regla, severidad y serie temporal) y los filtros por nivel,
agente y búsqueda libre.

### 2.3 Demo headless (smoke + PNG)

```bash
java -jar target/dashboard-wazuh.jar --demo --headless-smoke \
    --output=output/dashboard-demo.png
```

- Levanta el receptor HTTP en `127.0.0.1:8787`.
- Envía una alerta de muestra por HTTP con el token Bearer.
- Espera determinísticamente a que el `EventStore` la registre.
- Renderiza el `DashboardPanel` en el EDT a un PNG.
- Apaga el receptor y reporta conteos por stdout en una línea.

### 2.4 Launcher portable

```bash
./scripts/demo-launcher.sh                # smoke headless + PNG
./scripts/demo-launcher.sh --ui           # ventana Swing
./scripts/demo-launcher.sh --port=9000    # cambia puerto
```

`demo-launcher.sh` busca Java en este orden: `JAVA_HOME`,
`/opt/homebrew/opt/openjdk/bin/java`, `/usr/local/opt/openjdk/bin/java`,
y por último `java` en el PATH. Falla con mensaje claro si no encuentra.

## 3. Cómo recorrer la presentación

1. **Compilación reproducible**: `mvn -B package` → un jar sin
   dependencias externas.
2. **Smoke sin secretos**: `./scripts/demo-launcher.sh` → muestra una
   sola línea con conteos (`accepted`, `malformed`, `unauthorized`,
   `oversized`, `methodNotAllowed`, `dropped`) y la ruta del PNG. No
   aparece ningún token.
3. **Ventana real**: `./scripts/demo-launcher.sh --ui` → seleccionar un
   evento con usuario, ver el panel de detalle LDAP con la marca
   `DEMO` (departamento y email `@demo.invalid` son la firma del
   `DemoDirectoryLookup`, nunca contacta al AD institucional). Los
   eventos sin `data.srcuser` (demo-006, demo-012) muestran etiqueta
   `not-applicable` en el detalle. Cambiar un filtro de nivel y
   observar el mapa y las gráficas actualizándose.
4. **Ingesta vía webhook** (modo `--demo`): la ruta ya queda
   demostrada por el smoke central (`--headless-smoke`): el receptor
   acepta POSTs autenticados y los entrega al panel. **No se
   recomienda `curl` directo**: el token Bearer en modo demo se genera
   runtime y nunca se imprime, así que pegarlo en una terminal revela
   un secreto efímero. El smoke lo hace por dentro con la API correcta.
   Para una prueba interactiva en vivo el operador debe arrancar en
   `--live` con `WEBHOOK_TOKEN` explícito y conocido.
5. **Pruebas automáticas**: `mvn -B test package` ejecuta unitarias y
   pruebas HTTP/LDAP aisladas; `WebHookServerE2ETest` valida
   202/400/401/405/413 y concurrencia. `verify` recorre el ciclo Maven
   completo, pero no añade otra suite separada de E2E.

## 4. Lo que la demo **no** demuestra

- **Datos reales**: las alertas son sintéticas y están marcadas como
  tales. La clase propuso puntos adicionales (vulnerabilidades, IA,
  CVSS, KEV) que **no** forman parte de los seis requisitos y no se
  simulan. La demo no afirma haber accedido a un manager real.
- **LDAP real**: el AD/LDAPS institucional sólo se consulta si Javier
  inyecta las credenciales **y** se ejecuta en modo `--live`. La demo
  usa `DemoDirectoryLookup` (marca `DEMO`); nunca contacta al AD.
- **TLS extremo a extremo**: el receptor escucha en HTTP loopback. Para
  producción usar HTTPS con CA válida (ver `docs/CONFIGURATION.md`).
- **Ratón/teclado automatizados**: PNG y ventana nativa fueron observados;
  los comandos de entrada Orca encontraron un límite de foco en macOS.
  Recorrer filtros y selección manualmente antes de presentar.

## 5. Comprobaciones rápidas antes de presentar

| Comprobación | Comando | Resultado esperado |
|---|---|---|
| Java 17 detectado | `java -version` | `openjdk version "17..."` o superior |
| Compila y prueba | `mvn -B test package` | `BUILD SUCCESS`, jar en `target/` |
| Unitarias e integraciones aisladas | `mvn -B test` | Todas verdes, HTTP/LDAP locales |
| Ciclo completo | `mvn -B verify` | Las mismas pruebas y empaquetado |
| Smoke | `./scripts/demo-launcher.sh` | Línea `smoke.ok=true ... output=...` |
| Ventana | `./scripts/demo-launcher.sh --ui` | Swing abre sin excepciones |

## 6. Limpieza

El receptor loopback se cierra al terminar el proceso. Cierra la ventana
propia o usa Ctrl+C en la terminal que lo inició; no mates por patrón
otras instancias del equipo. Si `8787` está ocupado, usa `--port=18787`
en el smoke o `--port=18788` en la UI. No cierres servicios ajenos.
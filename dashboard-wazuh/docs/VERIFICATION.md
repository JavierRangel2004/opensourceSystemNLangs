# Verificación de entrega — 13-oct-2026

Cwd comprobado: `/Users/javar/github/unipanam/opensourceSystemNLangs/dashboard-wazuh`. Entorno observado: macOS arm64, Maven 3.9.16 y JDK Homebrew 26; el proyecto compila con `release=17`. No se ejecutó la suite en un JDK 17 independiente.

## Ejecuciones observadas

| Escenario | Resultado |
|---|---|
| `mvn -B test package` | BUILD SUCCESS; 134 pruebas, 0 fallos, 0 errores, 0 omitidas |
| Segundo `mvn -B -DskipTests package` sin cambiar fuentes | BUILD SUCCESS; se recrea el jar original antes de Shade |
| `./scripts/demo-launcher.sh --port=18787` | `smoke.ok=true`, HTTP 202, store 13, accepted 1; errores y descartes 0 |
| Contenido del smoke | 13 filas, 9 símbolos geográficos, 3 eventos sin ubicación; LDAP sintético: 11 found y 2 not-applicable |
| PNG del smoke | Observado con tabla/cabeceras, mapa Natural Earth, leyenda completa y JFreeChart; `output/dashboard-demo.png` ignorado por Git |
| Swing `--demo --port=18788` | Ventana nativa observada con 12 eventos, mapa y gráficas; selector conserva IDs/nombres de los eventos, no ordinales |
| Integrador ejecutado como Wazuh: archivo, api_key, hook_url | HTTP 202, cuerpo JSON intacto y Bearer correcto; secreto sintético sólo en ejecución, ausente de stdout/stderr |
| Integrador con proxy de entorno y sin NO_PROXY | Envío directo al receptor; 0 peticiones al proxy local de prueba |
| Integrador con 302, HTTP remoto o URL con userinfo | Fallo esperado; no segunda petición tras redirección ni envío remoto |
| CA sintética importada en JKS | JDK carga una entrada pública sin password de runtime; temporales eliminados |
| CLI `--live` sin WEBHOOK_TOKEN, puerto 0 o argumento desconocido | Salida 2, rechazo esperado |

Los tests usan HTTP y LDAP reales aislados en loopback, no servicios institucionales. Incluyen paginación y renovación 401, envelope Wazuh, identidades UPN/sAM ambiguas, escaping y TLS/loopback, parser Unix/Windows/VirusTotal, dedupe/FIFO/concurrencia, autenticación y errores del webhook, filtros, selección y proyección proporcional. La prueba horaria usa una zona de media hora para distinguir UTC de la hora local.

## Correcciones verificadas durante integración

- Fixtures LDAP configuradas antes de construir el servidor; base DN y entradas LDIF válidas. No se usan esquemas AD en el servidor aislado.
- JSON Windows escapado correctamente y selección de usuario/dominio de la misma familia de campos.
- Envelope API estricto; failed_items bajo data, token inválido rechazado sin eco, prefijo URL e IPv6 conservados.
- Agentes de demo con IDs reales de los eventos; refresco no confirma texto pendiente ni reconstruye una lista idéntica.
- Selección preservada sin limpiar el detalle en cada tick; se limpia cuando desaparece el evento aun si quedan otras filas.
- El primer render headless resultó vacío: el layout recursivo y la cabecera explícita corrigieron el PNG; se observó nuevamente su contenido.
- Proyección con escala uniforme y mundo centrado; regresión sobre lienzo ancho y alineación símbolos/polígonos.
- Transporte del integrador sin redirecciones ni proxies implícitos, HTTP sólo loopback literal/localhost.
- Empaquetar dos veces reutilizaba el uber-jar como entrada de Shade. Se fijó `maven-jar-plugin` 3.5.0, la versión ya usada, con `forceCreation=true`, según [su contrato oficial](https://maven.apache.org/plugins/maven-jar-plugin/jar-mojo.html). Permanecen advertencias de metadatos META-INF; el jar resultante se ejecutó correctamente.

Las revisiones fueron independientes de los implementers: DashboardSpecReview, RuntimeSecurityReview, ApiBoundaryReview, EventDirectoryReview, UiApiFinalReview y RuntimeLdapFinalReview. Sus hallazgos se devolvieron a integración y se cubrieron con los checks anteriores; no se atribuye a los reviewers una aprobación posterior que no emitieron.

## Límites de evidencia y prerrequisitos

- La ventana final se observó visualmente y por accesibilidad. Los intentos de entrada de Orca fallaron por foco/ventana de macOS; no se afirma un recorrido automatizado de ratón o teclado. Filtros y selección sí se ejercen programáticamente en EDT por la suite. Recorrerlos manualmente antes de presentar.
- No hubo Wazuh Manager ni LDAP institucional disponibles. La muestra está marcada DEMO y nunca acredita autenticación institucional. Falta el check extremo a extremo manager → integrador → dashboard y el lookup contra el directorio autorizado.
- Obtener del administrador una cuenta API de sólo lectura, endpoint y CA; Javier debe inyectar el bind LDAP autorizado, base DN y CA. Configurar el mismo WEBHOOK_TOKEN en receptor e integrador por canal privado. Ver `CONFIGURATION.md`; no pegar valores en notas, commits o mensajes.
- `8787` estaba ocupado: no se detuvo ese servicio ajeno. Las instancias propias usaron puertos alternativos y se cerraron; no se modificó el manager.

## Repetir antes de presentar

Desde esta carpeta:

```bash
mvn -B test package
./scripts/demo-launcher.sh --port=18787
./scripts/demo-launcher.sh --ui --port=18788
```

En la ventana: escoger un evento con usuario para ver detalle LDAP DEMO, uno sin usuario para not-applicable, filtrar por nivel/agente/búsqueda, cambiar período y restablecer. No se introducen secretos para este recorrido. Para live, seguir `CONFIGURATION.md` con credenciales exclusivamente runtime.

# Configuración

Este documento lista las variables de entorno, los endpoints y los
permisos necesarios para los modos del dashboard.

> **Privacidad.** Ningún valor secreto se publica en este repo. Los
> ejemplos muestran sólo nombres, propósitos y procedencias. La
> inyección se hace por variable de entorno, archivo restringido o
> gestor de secretos.

## 1. Variables de entorno

| Variable | Modo | Propósito | Cómo obtenerla |
|---|---|---|---|
| `DASHBOARD_HOST` | todos | Host de escucha del receptor | Por defecto `127.0.0.1` (loopback). Cambiar requiere justificación operativa |
| `DASHBOARD_PORT` | todos | Puerto de escucha | Por defecto `8787`. Cualquier puerto libre `>= 1024` |
| `WEBHOOK_TOKEN` | todos | Token Bearer que el receptor exige | **Obligatorio en modo `--live`**: el Integrator lo pasa como `argv[2]` (api_key) al script. Si se omite, el dashboard genera uno `SecureRandom` en modo `--demo` y rechaza arrancar en `--live` |
| `DASHBOARD_MODE` | todos | `demo` o `live` (excluyentes) | Documentado en este README |
| `DASHBOARD_DEMO_RESOURCE` | demo | Recurso del classpath con la muestra | Por defecto `demo/alerts.json` |
| `DASHBOARD_OUTPUT` | smoke | Ruta del PNG generado | Por defecto `output/dashboard-demo.png` |
| `WAZUH_API_URL` | live | URL del manager Wazuh | Proporcionada por el administrador del manager (ej. `https://host:55000`). **No** incluir credenciales en la URL |
| `WAZUH_API_USER` | live | Usuario con permiso lectura sobre `/agents` | Cuenta API dedicada de sólo lectura, solicitada al administrador del manager |
| `WAZUH_API_PASSWORD` | live | Contraseña del usuario API | Inyectada por gestor de secretos. El paquete no la guarda |
| `LDAP_URL` | live | URL LDAPS del directorio | `ldaps://host:636`. Verificar el certificado del servidor |
| `LDAP_BIND_DN` | live | DN de servicio para búsquedas | Proporcionado por el administrador del AD |
| `LDAP_BIND_PASSWORD` | live | Contraseña del DN | Inyectada por gestor de secretos |
| `LDAP_BASE_DN` | live | Base DN bajo el cual se buscan usuarios | Ej. `OU=Users,DC=up,DC=edu,DC=pa` |
| `CUSTOM_DASHBOARD_TOKEN` | live | Token equivalente a `WEBHOOK_TOKEN` para el script | Necesario si el servicio del Manager no hereda la variable de la shell |
| `CUSTOM_DASHBOARD_ENDPOINT` | live | Endpoint por defecto del script | Si el Manager no propaga `hook_url` en `argv[3]` |

Ver [`.env.example`](../.env.example) para un archivo de referencia.

## 2. Manager API vs Indexer API

Wazuh expone dos APIs distintas:

| API | URL típica | Uso en este dashboard |
|---|---|---|
| **Manager API** | `https://manager:55000` | Autenticación (`/security/user/authenticate?raw=true`) y agentes (`/agents?offset=&limit=`) |
| **Indexer API** | `https://indexer:9200` | **No se usa** aquí: este dashboard lee agentes desde el Manager, no desde el Indexer |

Si el operador configura `WAZUH_API_URL` apuntando al Indexer, el
cliente no encontrará el endpoint de autenticación y el estado se
reportará como error de autenticación (`error:*` con motivo saneado,
sin URL ni credenciales). El operador debe verificar que la URL
apunte al Manager y que la cuenta tenga permisos de lectura sobre
`/agents`. Solicitar al administrador del Wazuh Manager la creación de
una cuenta dedicada de sólo lectura — este paquete no la crea.

## 3. TLS y confianza

**No se usa `TrustAllSSLSocketFactory`**. El dashboard verifica los
certificados del manager (HTTPS) y del LDAP (LDAPS) con la cadena por
defecto del JDK. Si el operador necesita confiar en una CA privada del
manager o del AD, crear un **truststore local** y referenciarlo con
flags JVM, sin modificar el cacerts global del JDK.

Crear un JKS que contenga **sólo certificados públicos de CA**. `keytool`
solicita una contraseña de integridad al crearlo; introducirla en su prompt,
nunca en argv, un comando `export`, el historial ni este repositorio.
El archivo local queda ignorado y protegido para el usuario que ejecuta Java.

```bash
mkdir -p .local
chmod 700 .local
keytool -importcert -alias wazuh-manager \
    -file /ruta/absoluta/ca.pem \
    -keystore .local/truststore.jks \
    -storetype JKS
# Verificar con el administrador la huella del certificado antes de aceptarlo.
chmod 600 .local/truststore.jks

# Flags JVM antes de -jar; ejecutar desde la carpeta dashboard-wazuh.
java \
    -Djavax.net.ssl.trustStore="$(pwd)/.local/truststore.jks" \
    -Djavax.net.ssl.trustStoreType=JKS \
    -jar target/dashboard-wazuh.jar --live
```

No se pasa `trustStorePassword` en runtime: para un JKS con sólo CAs públicas,
Java puede cargar certificados sin comprobar su contraseña de integridad.
Esto **no** desactiva la verificación TLS del servidor; proteger el archivo
con permisos sigue siendo obligatorio. No usar esta receta para keystores
con claves privadas. No truncar ni reemplazar el truststore después de importarlo.
La misma receta permite importar la CA LDAP con otro alias.

Si el manager o el AD usa un certificado autofirmado, el operador debe
importarlo a un truststore local antes de arrancar el dashboard. Sin este
paso el `fetchAgents()` falla con `SSLHandshakeException` (estado saneado,
sin nombre de host).

El paquete **no** modifica `$JAVA_HOME/lib/security/cacerts` ni embebe
contraseñas ni rutas internas en el repositorio.

## 4. Integración con Wazuh Manager

### 4.1 Convención del Manager

Wazuh Manager invoca las integraciones con prefijo `custom-` siguiendo
[la documentación oficial](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html):

```
argv[1] = ruta al archivo JSON temporal con la alerta
argv[2] = api_key declarada en <integration><api_key>
argv[3] = hook_url declarada en <integration><hook_url>
```

El script `scripts/custom-dashboard` consume estos argumentos
directamente; no necesita banderas adicionales.

### 4.2 Snippet XML

Ver [`scripts/ossec-integration.xml`](../scripts/ossec-integration.xml).
**No** se publica el valor real del `api_key`; el operador debe
inyectarlo por el canal de secretos autorizado por su organización
(gestor centralizado, vault institucional, o similar). Este paquete
no recomienda canales específicos del usuario.

### 4.3 Permisos del script

El Manager exige que el script sea propiedad de `root:wazuh` con modo
`0750`. La ruta canónica es **`/var/ossec/integrations/custom-dashboard`**
(un solo archivo, sin directorio del mismo nombre).

```bash
sudo install -o root -g wazuh -m 0750 \
    scripts/custom-dashboard \
    /var/ossec/integrations/custom-dashboard
```

El Manager invoca `<integration><name>custom-dashboard</name>`
buscando ese nombre en `/var/ossec/integrations/`.

### 4.4 Herencia de variables por el servicio

El servicio del Manager (demonio) **no hereda** automáticamente las
variables de entorno de la shell que lo arrancó. Si `WEBHOOK_TOKEN` no
llega al script, se documentan estas alternativas:

1. **API del Manager (`<api_key>` en XML)**: Wazuh Manager lo pasa al
   script como `argv[2]`. El script lo acepta sin más configuración.
2. **Variable de entorno del servicio**: declarar
   `CUSTOM_DASHBOARD_TOKEN` en el unit de systemd o en
   `/etc/default/wazuh-manager`. Sólo si el operador controla el
   arranque del servicio.
3. **Archivo restringido** (recomendado en producción): crear
   `/etc/wazuh-dashboard/token` con `root:wazuh` y modo `0640`. El
   script lo lee como último recurso. La contraseña se introduce
   por entrada oculta del operador (`read -s`) o desde un archivo
   fuente con permisos `0400` propiedad de root; **no** se pega
   en la línea de comandos para evitar fuga en historial de shell.

```bash
sudo install -d -o root -g wazuh -m 0750 /etc/wazuh-dashboard
sudo install -o root -g wazuh -m 0640 /dev/null /etc/wazuh-dashboard/token
sudo -i
TOKEN_PATH=/etc/wazuh-dashboard/token
umask 0177
read -s -p "Token Bearer: " T && echo
printf '%s' "$T" > "$TOKEN_PATH"
unset T
exit
```

### 4.5 Hook URL

`<hook_url>` **no debe contener credenciales** en su cadena. Si el
receptor expone HTTPS fuera del host, usar un proxy inverso
(nginx/Caddy/Traefik) que termine TLS y delegue al loopback. El
dashboard no implementa proxy.

El integrador admite HTTP sólo con loopback literal (`127.0.0.0/8`,
`::1`) o `localhost`; no acepta un nombre DNS arbitrario por resolver
a loopback. No sigue redirecciones: un 3xx se reporta como fallo sin
reenviar el token a otro destino.

## 5. LDAP / AD institucional

Las credenciales del AD/LDAPS institucional **no** están incluidas en
este paquete. Javier las inyecta cuando estén disponibles:

- `LDAP_URL`: URL LDAPS, sólo esquema + host + puerto.
- `LDAP_BIND_DN`: DN del servicio (no usar cuentas personales).
- `LDAP_BIND_PASSWORD`: contraseña del DN.
- `LDAP_BASE_DN`: base DN para `search`.

El `JndiDirectoryLookup` (hoja A) escapa `sAMAccountName` /
`userPrincipalName` antes de enviar el filtro para evitar inyección.
Si falta cualquier variable, el `IngestionCoordinator` opera sin
`DirectoryLookup` y reporta `not-configured` por evento, **no** rellena
con datos de muestra.

Una identidad UPN se busca exactamente por `userPrincipalName`; una
identidad simple o `DOMAIN\usuario`, por `sAMAccountName` dentro de
`LDAP_BASE_DN`. El prefijo NetBIOS no se infiere ni se valida a partir
del DN: el administrador debe confirmar que el árbol configurado es
el del dominio de los eventos. Más de una coincidencia se reporta como
error, nunca se enriquece con la primera persona arbitraria.

En modo `--demo`, el dashboard utiliza `DemoDirectoryLookup` que
devuelve `DirectoryUser` con la marca explícita `DEMO` para mostrar el
camino `found` sin claim de LDAP real. **Nunca** se contacta al AD ni
se consultan usuarios reales en modo demo, ni siquiera si las variables
LDAP están presentes.

## 6. Amenazas, TLS y privacidad del token

- El token Bearer **nunca** se imprime en logs ni se refleja en respuestas
  de error. Los mensajes pueden nombrar el esquema de autenticación.
- Los errores LDAP se exponen como `error` sin el detalle de la
  excepción ni el nombre de usuario.
- El estado de la API del manager aparece como `ok:N` o
  `error:ClaseSimple`. Nunca se loguea la URL ni las credenciales.
- El `DirectoryLookup` no se persiste; sus recursos se cierran tras
  cada consulta y al cerrar el proceso.
- En demo se genera un token `SecureRandom` de 32 bytes exclusivamente
  en runtime. En live es obligatorio inyectar `WEBHOOK_TOKEN`. El
  integrador recibe el mismo secreto por el canal operativo elegido;
  se recomienda archivo restringido para evitar valores en argv.

## 7. Límites del alcance

- La clase propuso también vulnerabilidades / IA / CVSS / KEV. Esos
  puntos **no** entran en los seis requisitos y no se simulan ni se
  exponen resultados ficticios desde el dashboard.
- Para demostrar los caminos reales se necesita un Wazuh Manager
  accesible y un AD/LDAPS autorizado. Sin sus variables completas, esas
  superficies muestran `not-configured`; live no carga muestra.
- Se observaron PNG y ventana Swing nativa; la entrada automatizada
  encontró un límite de foco de macOS/Orca. Ratón/teclado se recorren
  manualmente antes de clase, sin afirmar verificación automática.
- Los endpoints de Manager API y Indexer API son distintos: este
  dashboard sólo utiliza la Manager API. Operadores que apunten a
  otro servicio verán errores de autenticación con motivo saneado.
- El modo `--live` exige `WEBHOOK_TOKEN`; si está ausente el proceso
  rechaza arrancar con un mensaje claro en stderr. La razón es que
  un token generado runtime en live no es accesible al Integrator del
  Manager y la integración quedaría inautenticada.
# Sistemas y Lenguajes de Código Abierto

Proyecto del segundo parcial: [Dashboard Wazuh](dashboard-wazuh/README.md), Java/Swing con API de Wazuh, integración de alertas, LDAP, concurrencia, mapas temáticos y JFreeChart.

- Diseño, contratos y plan: [dashboard-wazuh/docs/PLAN.md](dashboard-wazuh/docs/PLAN.md).
- Ejecución y resultados comprobados: [dashboard-wazuh/docs/VERIFICATION.md](dashboard-wazuh/docs/VERIFICATION.md).
- El repositorio de GitHub es privado; el acceso de compañeros se administra desde GitHub por el dueño.
- Las prácticas originales permanecen en el checkout local. No se publicaron: contienen candidatos a credenciales/datos privados, archivos de configuración de laboratorio y binarios. `.gitignore` usa una lista permitida para impedir su inclusión accidental; no fueron borradas ni copiadas.
- Credenciales sólo en runtime mediante entorno o archivos ignorados. No versionar eventos reales ni respuestas LDAP. Una copia privada no sustituye el saneo de secretos.

## Auditoría antes del primer commit

Se inspeccionaron fuentes, configuraciones, scripts y miembros textuales de ZIP mediante un extractor que sólo emitió rutas, líneas y booleanos. Se observaron asignaciones literales sensibles en `Ldap.java`, `server/ValidaDerby.java` y `ProcesaEventos/src/java/utils/MandaCorreo.java`, además de candidatos dentro del ZIP de ProcesaEventos. No se comprobó su vigencia; no se emitieron valores. `server - copia.txt`, `derby.properties_`, ZIP y todos los demás originales quedan excluidos por igual.

Sólo se publican este README, `.gitignore` y la carpeta nueva `dashboard-wazuh`. Para publicar prácticas originales en el futuro, primero externalizar y revisar sus credenciales y datos; no quitar la exclusión sin esa revisión.

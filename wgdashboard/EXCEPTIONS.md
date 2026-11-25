# Decisiones pendientes sobre hallazgos sin corrección automática

Decisión del owner del 2026-11-25: **VEX acotado para los tres hallazgos**. La declaración firmada, con fundamento, condiciones invalidantes y evidencia, está en `VEX-20261125.md`. La tabla siguiente conserva el estado previo a la decisión como registro histórico.

Este archivo fue un borrador de trabajo. `.trivyignore` del repositorio dice explícitamente que no hay excepciones generales y que toda excepción nueva exige revisión fechada y acotada. La validación del release 25 usó `--ignorefile /dev/null`, por lo que este archivo no fue aplicado en ese build.

| Hallazgo | Estado en el informe | Acción candidata | Requiere |
|---|---|---|---|
| CVE-2026-85394 · `python-jose 3.5.0` · CRITICAL | `affected`, sin versión corregida | Sustituir `python-jose` por una librería JWT mantenida (p. ej. PyJWT) en el código de WGDashboard, o VEX con análisis del flujo alcanzable | Decisión del owner + cambio de código upstream; fuera del alcance del wrapper |
| CVE-2024-23342 · `ecdsa 0.19.2` · HIGH | `affected`, sin versión corregida | VEX con demostración de que la ruta de firma vulnerable no es alcanzable desde la UI de solo lectura, o sustitución de la dependencia | Análisis de código + aprobación bajo `STD-VND-001` |
| CVE-2026-78661 · `golang.org/x/net v0.61.0` en `usr/bin/amneziawg-go` · HIGH | `fixed` en 0.62.0, pero binario estático heredado | Nuevo digest upstream con la versión corregida, o VEX verificando que el parser HTML no es usado por el binario | Nueva receta/digest o análisis de alcanzabilidad |

Los hallazgos con versión corregida (`msgpack`, `setuptools`, `urllib3`) ya están incluidos en el Dockerfile candidato. DS002 se aborda con `USER 1000:1000`, condicionado a comprobar que el entrypoint heredado arranca con ese UID y a que el host pre-cree `/etc/wireguard/WGDashboard_Backup` con la propiedad adecuada.

Ninguna de estas acciones autoriza publicar, mergear ni desplegar. El gate de `CHG-SVC-003` permanece `no-go-release25-validation-failed` hasta nueva validación nativa en código 0.

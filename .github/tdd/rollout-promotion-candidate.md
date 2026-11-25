# Verificación por etapa de la promoción

Este parche añade a Actions una comprobación de solo lectura para `development → staging`
y `staging → main`. Prueba la simulación sobre el SHA de origen y el SHA destino del
evento, comprueba las referencias antes y después, rechaza forks, conflictos, promociones
sin cambios y árboles distintos al origen. Nunca hace merge, push, publicación ni
ejecuta código de la PR. Jenkins sigue siendo independiente.

## Despliegue y verificación

1. Aplicar en una rama nueva de revisión. No fusionar los PR operativos mientras falte un
   check. Verificar que el archivo y su evaluador están en las bases protegidas de
   `staging` y `main` mediante el procedimiento de bootstrap firmado ya aprobado para
   el repositorio. No relajar las reglas para instalarlo.
2. Verificar la política de eventos GitHub en ambas bases y que un PR de prueba en
   draft, sin publicar, ejecuta el check en el head correcto. Repetir con conflicto,
   cambio de head y cambio de base. Probar que GitHub rechaza un merge con solo Jenkins
   verde y también con solo Actions verde; un check omitido, ausente o de otro emisor
   no es un éxito. El análisis local no prueba esa protección de GitHub.
3. Configurar los checks requeridos con sus emisores. Exigir que estén actualizados
   con la base o usar un mecanismo de cola validado con ambos CI antes de auto-merge.
   Dejar el squash a staging manual, con PR en draft hasta revisión; en main no activar
   auto-merge hasta demostrar bloqueo por base obsoleta y por falta de cualquiera de
   los dos resultados. Publicación separada, con `PUBLISH=false` en pruebas.
4. Las ramas `sync/*` de emergencia no son promociones normales. No añadir un permiso
   genérico: usar el proceso firmado de recuperación, con SHA destino, SHA origen,
   árbol y padre fijados y verificados por políticas protegidas. En particular este
   parche no pone el PR #211 en verde ni aprueba el árbol antiguo que trae.
5. Falta ajustar la automatización existente: el borrador depende hoy de Ansible,
   no de Jenkins+Actions; hay que definir si Ansible sigue como requisito adicional,
   conservar comprobaciones de firma y SHA, y validar el creador de borradores. Hay
   que confirmar el bot activo y alinear sus PR con la entrada `fix/* → development`.
   Separar el diagnóstico de ruta completa de la puerta de cada etapa solo después de
   reconciliar las ramas y verificar ambas puertas. Un pendiente se queda pendiente;
   solo un fallo definitivo debe iniciar una corrección nueva y deduplicada, nunca
   reintentos infinitos de la misma revisión.

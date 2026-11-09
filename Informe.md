# Informe breve de mejoras de seguridad

Se compararon `RepoSeguridad-antes.js` y `RepoSeguridad.js` para identificar los cambios realizados.

| Aspecto | Antes | Después |
|---|---|---|
| Consulta de usuarios | No validaba el ID y exponía `passwordHash`. | Valida que el ID contenga solo números y excluye `passwordHash` de la respuesta. |
| Registro | No validaba los datos recibidos. | Comprueba campos obligatorios, tipos, formato del nombre, rol permitido y usuarios duplicados. |
| Contraseñas | No contaba con hash mediante bcrypt. | Implementa `bcrypt` para generar y verificar hashes de contraseñas. |
| Manejo de errores | Enviaba al cliente el mensaje y el stack trace del error. | Registra el error en el servidor y devuelve una respuesta genérica. |

## Vulnerabilidades OWASP mitigadas

- **A02 – Cryptographic Failures:** se utiliza `bcrypt` para proteger las contraseñas y se evita exponer `passwordHash`.
- **A03 – Injection:** se valida el formato del ID antes de realizar la búsqueda.
- **A04 – Insecure Design:** se agregan validaciones para los datos del registro.
- **A05 – Security Misconfiguration:** se evita revelar detalles internos y trazas de errores al cliente.

## Conclusión

La versión mejorada incorpora `bcrypt`, validaciones de entrada, protección de información sensible y un manejo de errores más seguro. Estas modificaciones reducen riesgos de seguridad, aunque todavía se requiere implementar controles de autorización para impedir que cualquier usuario se registre con el rol de administrador.
# electronnicaragua

Alojamiento de la aplicación de gestión de servicios de Electrón Nicaragua.

## Configurar registro y permisos de cuentas

1. En Supabase, abre **SQL Editor**, pega el contenido de [`supabase-schema.sql`](./supabase-schema.sql) y ejecútalo una vez. El script configura la tabla de datos, acceso compartido y políticas de seguridad para registros y archivos.
2. Inicia sesión en la aplicación con `mariorugama1@gmail.com`. Esa dirección tiene permisos de administración.
3. Las cuentas creadas con correo o Google reciben acceso de **solo lectura** a los datos de la cuenta administradora. En **Configuración → Acceso de las cuentas**, el administrador puede elegir **Sin acceso**, **Solo lectura** o **Lectura y escritura** para cada cuenta.

El administrador debe crear primero las cuentas que quiera habilitar. El control de permisos se valida en Supabase además de la interfaz. La aplicación no incluye credenciales de servicio: el script utiliza la sesión autenticada y políticas de Row Level Security.

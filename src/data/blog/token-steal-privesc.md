---
author: Arnold Morales
pubDatetime: 2025-12-21T21:30:00Z
modDatetime: 2025-12-21T21:37:45.934Z
title: Token Stealing en Windows de Administrador a NT AUTHORITY\SYSTEM
slug: token-steal-privesc
featured: true
draft: false
tags:
  - Windows
  - NT SYSTEM
  - Privesc
  - exploit
  - redteam 
description:
  Escalacion de privilegios por SetDebugPrivilege en windows.
---

# Token Stealing en Windows de Administrador a NT AUTHORITY\SYSTEM

NT AUTHORITY\SYSTEM (comúnmente llamado SYSTEM) es una cuenta interna de Windows que representa al propio sistema operativo.

Su SID es:
```bash
S-1-5-18
```
Ese identificador aparece dentro del Access Token de los procesos que ejecuta el kernel o los servicios críticos del sistema.
Muchos de los componentes más críticos del sistema se ejecutan con esa identidad. Por ejemplo:

- lsass.exe → autenticación del sistema

- winlogon.exe → proceso de login

- services.exe → gestor de servicios

- smss.exe → Session Manager

Todos ellos funcionan con privilegios SYSTEM porque necesitan control total sobre el sistema operativo.

Desde la perspectiva del kernel, el token de seguridad de SYSTEM representa algo parecido a:

```bash
Identidad: NT AUTHORITY\SYSTEM
Privilegios: prácticamente todos
Integridad: System Integrity Level
Acceso: control completo del sistema
```

Si inspeccionas uno de esos procesos verás algo como:
```bash
User Name: NT AUTHORITY\SYSTEM
```
Esto significa que el proceso no pertenece a ningún usuario humano. Pertenece al núcleo del sistema operativo.

Muchos desarrolladores creen que Administrador = control total. En realidad no es así.

Un administrador sigue siendo un usuario.
SYSTEM es parte del sistema operativo.

Un administrador puede instalar programas, modificar el registro o crear usuarios. Pero hay ciertas cosas que están reservadas para procesos SYSTEM.

Por ejemplo:

- manipular servicios críticos del sistema

- acceder a memoria de procesos protegidos

- interactuar directamente con algunos subsistemas del kernel

- modificar componentes protegidos de Windows

Cuando un proceso corre como SYSTEM, muchas de esas barreras desaparecen.

# Por qué es tan poderoso

Un proceso que se ejecuta como SYSTEM puede hacer cosas que normalmente están restringidas incluso a administradores.

Entre ellas:

Desactivar defensas del sistema

Muchos mecanismos de seguridad se ejecutan como servicios del sistema.
Si tienes privilegios SYSTEM puedes:

- detener servicios de seguridad

- modificar su configuración

- alterar sus archivos

- interceptar su comunicación

Eso incluye productos de seguridad, monitoreo o protección.

Ese es el motivo por el que muchas técnicas de post-explotación buscan SYSTEM.

La consecuencia curiosa es que muchos mecanismos de seguridad en Windows están diseñados bajo una premisa implícita: si alguien ya es SYSTEM, entonces ya ganó. El sistema asume que ese nivel pertenece al propio sistema operativo.

Por eso, en investigación de seguridad, llegar a NT AUTHORITY\SYSTEM suele marcar el momento exacto en que la máquina deja de ser confiable.

# code

Bueno despues de esta breve introduccion a NT SYSTEM iniciemos con lo tecnico.

En teoria cuando un proceso crea otro proceso, el nuevo proceso hereda un token.
Esto significa que si logras obtener el token de un proceso SYSTEM, puedes ejecutar código con los mismos privilegios que el sistema operativo; Esta sera nuestro objetivo.

Nuestro flujo sera:

```bash
Admin Process
      │
      │ habilita SeDebugPrivilege
      ▼
Abre proceso SYSTEM
      │
      ▼
Obtiene su Access Token
      │
      ▼
Duplica el token
      │
      ▼
CreateProcessWithTokenW()
      │
      ▼
cmd.exe → NT AUTHORITY\SYSTEM
```
y nuestro flujo del exploit sera algo como:

- Verificar si ya se ejecuta como SYSTEM

- Habilitar SeDebugPrivilege

- Buscar un proceso que corra como SYSTEM

- Abrir el proceso

- Obtener su token

- Duplicar el token

- Crear un nuevo proceso usando ese token

Este codigo se encuentra aqui: [repo](https://github.com/MrR0b0t19/Privesc-DebugPrivilege/blob/main/steal_token.c)

# explicacion de codigo


# Verificación de privilegios actuales

```cpp
BOOL IsRunningAsSystem()
```

Esta función verifica si el proceso actual ya se ejecuta como SYSTEM.

Pasos internos:

1. Abrir el token del proceso actual

```cpp
OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)
```

2. Obtener la información del usuario del token

```cpp
GetTokenInformation(TokenUser)
```

3. Convertir el SID a string

```cpp
ConvertSidToStringSidA
```

4. Comparar contra el SID de SYSTEM

```
S-1-5-18
```

Si coincide:

```
Already running as SYSTEM
```

# Habilitar SeDebugPrivilege

```cpp
SetPrivilege(SE_DEBUG_NAME)
```

Este privilegio permite **abrir cualquier proceso del sistema**, incluso si pertenece a otro usuario.

Internamente hace tres cosas:

### 1. Obtener el token del proceso

```cpp
OpenProcessToken(...)
```

### 2. Obtener el identificador del privilegio

```cpp
LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)
```

### 3. Activar el privilegio

```cpp
AdjustTokenPrivileges(...)
```

Sin este privilegio, Windows bloquearía el acceso a procesos como:

```
lsass.exe
winlogon.exe
services.exe
```

# Búsqueda de un proceso SYSTEM

```cpp
FindTargetProcess()
```

Esta función recorre todos los procesos del sistema usando:

```
CreateToolhelp32Snapshot
Process32First
Process32Next
```

Lista de objetivos:

```
lsass.exe
winlogon.exe
services.exe
csrss.exe
```

Estos procesos normalmente se ejecutan bajo:

```
NT AUTHORITY\SYSTEM
```

Por eso sus tokens son valiosos.

# Apertura del proceso

```cpp
OpenProcess(PROCESS_QUERY_INFORMATION)
```

Esto crea un **handle al proceso SYSTEM**.

Un handle es simplemente un **índice en la tabla de handles del proceso** que apunta a un objeto del kernel.

# Obtención del Access Token

```cpp
OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)
```

Esto recupera el token del proceso objetivo.

Ahora tenemos algo como:

```
Handle → Token de SYSTEM
```

Pero aún no podemos usarlo directamente.

# Duplicación del token

```cpp
DuplicateTokenEx(...)
```

Esto crea **una copia del token original**.

Parámetros importantes:

```
SecurityImpersonation
TokenPrimary
```

Un **TokenPrimary** es necesario para crear procesos nuevos.

Resultado:

```
Token duplicado con privilegios SYSTEM
```

# Crear proceso como SYSTEM

El paso final:

```cpp
CreateProcessWithTokenW()
```

Se pasa el token duplicado y el ejecutable a lanzar.

Ejemplo:

```
cmd.exe
```

Windows ahora crea un nuevo proceso usando ese token.

Resultado:

```
cmd.exe
NT AUTHORITY\SYSTEM
```
# ¿Por qué funciona?

La clave está en el **modelo de seguridad de Windows**.

Si un proceso tiene:

```
SeDebugPrivilege
```

puede:

```
abrir cualquier proceso
leer su token
duplicarlo
crear procesos con él
```

Windows asume que **solo administradores confiables tendrán ese privilegio**.

Cuando un atacante lo obtiene, puede **escalar privilegios hasta SYSTEM**.

# Sobre Windows 11 y PPL

En Windows 11 muchos procesos críticos usan:

```
PPL
Protected Process Light
```

Ejemplo:

```
lsass.exe
```

PPL impide que incluso administradores puedan abrir el proceso o su token.

Por eso el código comenta:

```
necesitas bypass de PPL en win11
```

Sin bypass, el acceso será bloqueado.


# Uso de NtQuerySystemInformation

El código incluye una función opcional:

```
GetHandleAddress()
```

Esta usa la syscall:

```
NtQuerySystemInformation(SystemHandleInformation)
```

Esto devuelve **la tabla global de handles del sistema**.

Permite ver:

```
Handle
PID
Objeto del kernel
Permisos
```

Es útil para debugging y para entender cómo Windows mapea handles a objetos internos.

# Resultado final

Si todo funciona:

```
[+] SeDebugPrivilege enabled
[+] Found target process: lsass.exe
[+] OpenProcess successful
[+] OpenProcessToken successful
[+] DuplicateTokenEx successful
[+] Process spawned successfully
```

La nueva consola tendrá identidad:

```
NT AUTHORITY\SYSTEM
```

Ese es el **máximo nivel de privilegio en Windows userland**.

# Conclusión

El ataque demuestra algo importante:

La seguridad en Windows no depende solo de permisos de archivos o UAC.

Depende de **quién controla los tokens del sistema**.

Si un atacante puede:

```
habilitar SeDebugPrivilege
abrir procesos SYSTEM
duplicar tokens
```

entonces puede **convertirse en el sistema operativo**. bye

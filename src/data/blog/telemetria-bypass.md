---
author: Arnold Morales
pubDatetime: 2025-10-10T21:30:00Z
title: EDR Internals: Telemetría, Kernel y Evasión 
slug: telemetria-bypass
featured: true
draft: false
tags:
  - Telemetria
  - EDR
  - Windows
  - Kernel
  - callbacks   
description:
  Deshabilitando telemetria por Kernel - ¿Que hacer ya siendo NT SYSTEM?.
---

# EDR Internals: Telemetría, Kernel y Evasión

> Una mirada profunda a cómo los EDR recolectan telemetría desde el kernel de Windows,
> por qué esto importa ofensivamente, y cómo un atacante con acceso SYSTEM puede comenzar
> a desmantelar esas capacidades de detección.

Antes de comenzar, he dedicado algo de tiempo en temas de desarrollo en kernel y EDR junto a mi amigo [Adonai](https://github.com/AdonaiDiazEsparza), pero paralelamente como saben soy un atacante nato, lo cual dentro de esto me llevo a despertar ciertos factores de seguridad que aqui explico, todos estos temas quiero enverdad dar agradecimientos y mencionarlos ya que no me considero el mejor o alguien superior a ustedes, asi que si quieren investigar por su cuenta sobre cualquier tema mencionado aqui yo todo esto lo aprendi en 4 plataformas certificadoras de seguridad que para mi han influido demasiado en mi conocimiento.

* [HackTheBox Academy - Tiers IV](https://academy.hackthebox.com/app/library/modules)
* [TrainSec Academy - Master en kernel / Desarrollo de EDR](https://trainsec.net/all-courses/)
* [Zeropoint Security - CRTL / Dev BOF](https://www.zeropointsecurity.co.uk/courses)
* [SEKTOR7 - Malware Vol2](https://institute.sektor7.net/rto-maldev-adv2)

Ademas en todos mencionan a los proyectos

* [Verguilius](https://www.vergiliusproject.com/kernels/x64)
* [Proyecto zero](https://projectzero.google/)
* [Windows internals](https://windows-internals.com/cet-on-windows/)

Talvez olvide algunos que me apoyaron, ofrezco mis disculpas.

Por otro lado tambien a todos los blogs que lei y resumi esto, a sus post y aportaciones muchas gracias.
Espero lector que esto te ayude.

## Índice

1. [Arquitectura de un EDR](#arquitectura-de-un-edr)
2. [Fuentes de Telemetría](#fuentes-de-telemetría)
3. [La API de Windows y el Modo Usuario](#la-api-de-windows-y-el-modo-usuario)
4. [Hooks de API: IAT e Inline](#hooks-de-api-iat-e-inline)
5. [Syscalls Directas, Indirectas y Unhooked](#syscalls-directas-indirectas-y-unhooked)
6. [Call Stacks y Detección de Anomalías](#call-stacks-y-detección-de-anomalías)
7. [Kernel Callbacks: Los Ojos del EDR](#kernel-callbacks-los-ojos-del-edr)
8. [ETW y ETW-TI: La Fuente](#etw-y-etw-ti-la-fuente)
9. [Robo de Tokens de Acceso (T1134)](#robo-de-tokens-de-acceso-t1134)
10. [Evasión con Acceso SYSTEM](#evasión-con-acceso-system-deshabilitar-etw-y-callbacks)
11. [Procesos Protegidos (PPL)](#procesos-protegidos-ppl-el-último-obstáculo)
12. [Mapping MITRE D3FEND](#mapping-mitre-d3fend)


## Arquitectura de un EDR

Los vendors de soluciones de seguridad como los EDR (Endpoint Detection and Response) implementan lógica de detección propia que es su mayor diferenciador competitivo. Cuanto más rica y granular sea la telemetría que recolectan, más precisa será esa lógica y menores serán los falsos positivos.

Un EDR moderno en Windows generalmente consta de dos componentes principales: un **driver defensivo en modo kernel** y un **proceso en modo usuario** asociado a un servicio. Además, suele incorporar dos filtering drivers también residentes en el kernel.

```
┌─────────────────────────────────────────────────────────┐
│  USER MODE                                              │
│                                                         │
│  [New Process] [New Thread] [Registry Op] [Image Load]  │
│                      ↓ syscall ↓                        │
│  [Agent.exe] [Sigma Rules] [YARA] [hooked.dll] [ETW]    │
├─────────────────────────────────────────────────────────┤
│  KERNEL MODE                                            │
│                                                         │
│  [Defensive Driver] [Filesystem Minifilter (NTFS/NPFS)] │
│  [Network Filtering (NDIS)]  [Windows Kernel]           │
└─────────────────────────────────────────────────────────┘
```

---

## Init

## Fuentes de Telemetría

Las fuentes de telemetría que un EDR puede aprovechar son variadas. Todas alimentan al agente, que es quien toma la decisión final sobre la legitimidad de un evento.

### Kernel Callbacks (Notificaciones)

El driver defensivo registra **callbacks de notificación** en el kernel para recibir alertas cuando ocurren eventos críticos: creación de procesos/hilos, carga de imágenes en memoria, operaciones sobre handles de objetos, y modificaciones al registro. Estos callbacks no son de solo lectura: pueden **influir y modificar el resultado** de la operación notificada.

### Inyección de DLL vía KAPC

El driver defensivo puede inyectar una DLL en procesos recién creados para interceptar llamadas críticas a la API en modo usuario. Esto se realiza a través de **Kernel Asynchronous Procedure Calls (KAPC)**. Aunque fue ampliamente usado, este método se está volviendo menos popular por su fragilidad inherente al vivir en user-mode.

### YARA y Sigma

El agente también se apoya en bases de conocimiento como reglas **YARA** (para escanear imágenes en memoria) y reglas **Sigma** (para correlacionar comportamiento con patrones conocidos). Generalmente estas bases son descentralizadas y se actualizan en tiempo real.

### ETW (Event Tracing for Windows)

ETW es una de las fuentes más ricas y poderosas de telemetría en Windows. Un consumidor puede suscribirse a múltiples proveedores ETW para recolectar información relevante y correlacionarla con su lógica de detección. Más adelante hablaremos en profundidad de su variante **ETW-TI (Threat Intelligence)**.

### Network Filtering Driver (NDIS)

Un driver en la capa NDIS captura y despacha datos de tráfico de red, con capacidad de filtrar o bloquear conexiones. Enriquece la telemetría correlacionando contra fuentes de inteligencia de amenazas: IPs de C2 conocidos, dominios de phishing, etc.

### Filesystem Minifilter

Monitorea actividad en **NTFS** y en named pipes vía **NPFS (Named Pipe File System)**. Puede observar archivos creados, abiertos, modificados o eliminados, y también operaciones sobre pipe objects, un mecanismo IPC frecuentemente abusado durante escaladas de privilegios.


## La API de Windows y el Modo Usuario

La mayoría del malware e implantes dependen fuertemente de la **API nativa de Windows** para alcanzar sus objetivos. Funciones como las siguientes son el pan de cada día de herramientas como Cobalt Strike Beacon:

- `VirtualAllocEx` / `VirtualProtectEx`
- `WriteProcessMemory` / `ReadProcessMemory`
- `OpenProcess` / `OpenThread`
- `CreateRemoteThread` / `GetThreadContext` / `SetThreadContext`

Estas funciones se exportan desde DLLs como `KernelBase.dll` o `ntdll.dll` y viven en **modo usuario**. Cada proceso en modo usuario tiene su propia región de memoria virtual privada. Si un proceso falla, los demás no se ven afectados.

En contraste, el **modo kernel** comparte un único espacio de direcciones virtuales. Un driver defectuoso puede crashear toda la máquina (BSOD). Solo el código en modo kernel puede interactuar directamente con el hardware físico.

### El flujo de una syscall: OpenProcess

Cuando un proceso llama a `OpenProcess` (desde `KernelBase.dll`), esta internamente llama a `NtOpenProcess` en `ntdll.dll`. Ahí se ejecuta la instrucción `syscall`, que transfiere la ejecución al modo kernel. El kernel de Windows (`ntoskrnl.exe`) es donde ocurre el trabajo real: verificaciones de acceso y creación del handle.

```asm
; Stub de NtOpenProcess en ntdll.dll
NtOpenProcess:
    mov    r10, rcx
    mov    eax, 0x26    ; SSN (System Service Number)
    syscall             ; transición a kernel mode
    ret
```

### SSDT: System Service Descriptor Table

La **SSDT** es una tabla de lookup que mapea números de syscall (SSN) a sus funciones correspondientes en el kernel. Antes de Windows Vista, los vendors de seguridad podían hookear entradas de la SSDT para interceptar llamadas. Microsoft eliminó esta posibilidad con **Kernel Patch Protection (KPP / PatchGuard)**, que verifica periódicamente estructuras críticas del kernel y genera un BSOD si detecta modificaciones.

> **Nota histórica:** Symantec llegó a demandar a Microsoft por la implementación de PatchGuard, ya que los expulsó del kernel. Hoy en día Microsoft sigue presionando para sacar a los vendors fuera del kernel en Windows 11, aunque esto plantea problemas legales de libre competencia: si Defender puede operar en kernel mode, los demás también deben poder hacerlo.

## Hooks de API: IAT e Inline

Como los vendors no pueden hookear la SSDT, se mudaron al modo usuario. Los dos mecanismos principales son el **IAT Hooking** y el **Inline Hooking**.

### IAT Hooking (Import Address Table)

Cuando un PE se compila y usa una función externa como `MessageBoxW` de `User32.dll`, el cargador de Windows resuelve la dirección de esa función en memoria al momento de cargar el proceso y la escribe en la **Import Address Table (IAT)**. Un módulo de terceros (el EDR) puede sobrescribir esos punteros resueltos para redirigir la ejecución a sus propias funciones de "desvío" (detour). Desde ahí puede inspeccionar parámetros, bloquear la llamada, o reenviarla al original.

### Inline Hooking

El inline hooking sobrescribe directamente las primeras instrucciones de la función objetivo en memoria con un salto incondicional (`jmp`) hacia la función de desvío del EDR. Se crea también una función "trampolín" que preserva las instrucciones originales y salta de vuelta al resto de la función. Es la técnica más común hoy en día, aplicada generalmente sobre funciones de `ntdll.dll`.

```asm
; Antes del hook (función original)
NtOpenProcess:
    mov    r10, rcx
    mov    eax, 0x26
    syscall
    ret

; Después del hook (EDR sobrescribió los primeros bytes)
NtOpenProcess:
    jmp    EDR_DetourFunction   ; redirige al EDR
    mov    eax, 0x26
    syscall
    ret
```


## Syscalls Directas, Indirectas y Unhooked

Una de las técnicas más populares para bypassear hooks en modo usuario es ejecutar la syscall sin pasar por la API hookeada. La instrucción `syscall` transiciona directamente al kernel sin tocar ningún hook.

### Syscalls Directas

Se escribe manualmente un stub en assembly que mueve el SSN al registro `EAX` y ejecuta `syscall`, imitando lo que hacen los stubs legítimos en `ntdll.dll`. Requiere conocer el SSN correcto para la versión de Windows objetivo.

### Syscalls Indirectas

En lugar de ejecutar `syscall` directamente desde nuestro código, hacemos un `jmp` a una dirección de memoria que *ya contiene* la instrucción `syscall` dentro de `ntdll.dll`. Esto produce una call stack más limpia y es más difícil de detectar, ya que la instrucción `syscall` aparece originada en `ntdll`.

### Hell's Gate, Halo's Gate, Tartarus' Gate

Como los SSNs varían entre versiones de Windows y ASLR impide asumir direcciones fijas, existen proyectos que los resuelven dinámicamente:

| Librería | Estrategia |
|---|---|
| **Hell's Gate** | Recorre la EAT de `ntdll`, busca el opcode `0xB8` (mov) y extrae el SSN de los 2 bytes siguientes |
| **Halo's Gate** | Si una función está hookeada, busca en las funciones vecinas y deduce el SSN por diferencia |
| **Tartarus' Gate** | Refina la detección de hooks verificando si el 4to byte es `0xE9` (jmp), cubriendo vendors que hookean más adentro de la función |

### API Unhooking

En lugar de evitar los hooks, podemos **eliminarlos** directamente: restaurar los bytes originales de las funciones hookeadas. Como múltiples funciones de `ntdll` pueden estar hookeadas, lo más eficiente es reemplazar *toda la sección `.text`* de `ntdll` en memoria con una copia limpia leída desde disco.

```
1. Leer ntdll.dll limpia desde disco
2. Obtener dirección base de ntdll hookeada en memoria
3. Localizar su sección .text
4. Hacer la región .text escribible (VirtualProtect)
5. Copiar .text de la versión limpia sobre la hookeada
6. Restaurar permisos originales de memoria
7. Limpiar instrucción cache (FlushInstructionCache)
8. Cerrar handles
```

---

## Call Stacks y Detección de Anomalías

Una **call stack** es una estructura LIFO que registra el orden de llamadas a funciones, almacena variables locales y direcciones de retorno. Los EDR modernos analizan las call stacks para detectar actividad maliciosa.

### Convención de llamada x64

En Windows x64, los primeros cuatro parámetros enteros se pasan en los registros `RCX`, `RDX`, `R8` y `R9`. Parámetros adicionales van en la pila. El caller debe reservar siempre 32 bytes de **shadow space** para que el callee pueda volcar esos registros. `RSP` apunta siempre a la dirección más baja del frame activo.

| Tipo | 1er Param | 2do | 3ro | 4to | 5to+ |
|---|---|---|---|---|---|
| Integer | RCX | RDX | R8 | R9 | Stack |
| Float | XMM0 | XMM1 | XMM2 | XMM3 | Stack |

### Stack Unwinding

El "desenrollado de pila" es el proceso por el cual Windows recorre frames hacia atrás en tiempo de ejecución, principalmente para manejo de excepciones. Las estructuras `RUNTIME_FUNCTION`, `UNWIND_INFO` y `UNWIND_CODE` en las secciones `.pdata` y `.xdata` describen cómo cada función afecta la pila. Los EDR usan este mecanismo para rastrear el origen de llamadas API sospechosas.

> **Detección EDR:** Código como Beacon o BOFs se carga en regiones de memoria asignadas en runtime sin información de unwinding. La ejecución aparece originada en direcciones no respaldadas por módulos legítimos en disco. Los EDR detectan llamadas API que provienen de *memoria no respaldada por módulo* (unbacked memory).

### Clean Call Stacks: Cómo lo evade 

#### 1. Call Stack Spoofing

Se introducen frames falsos en la pila que parecen legítimos. Un frame con dirección de retorno `0x0` hace que el proceso de unwinding asuma que llegó al final de la pila. Se inserta un frame falso que imita a `RtlUserThreadStart`, y se usa un "gadget" encontrado en la sección `.text` de una DLL legítima como `kernel32.dll` (por ejemplo, `jmp qword ptr [rbx]`) como pivot. Una rutina de limpieza posterior elimina los frames falsos y restaura la ejecución normal.

#### 2. API Proxying (Thread Pool)

Se delega la ejecución de la API objetivo a otro hilo, usando funciones del thread pool de Windows como `TpAllocWork`, `TpPostWork` y `TpReleaseWork`. La callback se ejecuta en un hilo completamente diferente, produciendo una call stack que empieza legítimamente en `RtlUserThreadStart` y pasa por `TppWorkerThread`. La desventaja: no se puede leer el valor de retorno de la API.

---

## Kernel Callbacks: Los Ojos del EDR

El kernel de Windows expone mecanismos para que drivers en modo kernel reciban notificaciones de eventos críticos. A diferencia de los hooks en usuario, estos callbacks son robustos y difíciles de evadir sin acceso al kernel.

### PsSetCreateProcessNotifyRoutineEx

Permite registrar una callback que se dispara al crear o terminar un proceso. La versión extendida (`Ex`) provee un puntero `PEPROCESS` y una estructura `PS_CREATE_NOTIFY_INFO` con información rica: PPID, nombre del ejecutable, línea de comandos, y más. Requiere compilar el driver con el flag `/INTEGRITYCHECK`.

```c
typedef struct _PS_CREATE_NOTIFY_INFO {
  SIZE_T              Size;
  HANDLE              ParentProcessId;      // PPID
  CLIENT_ID           CreatingThreadId;
  struct _FILE_OBJECT *FileObject;
  PCUNICODE_STRING    ImageFileName;        // nombre del ejecutable
  PCUNICODE_STRING    CommandLine;          // línea de comandos completa
  NTSTATUS            CreationStatus;
} PS_CREATE_NOTIFY_INFO;
```

### ObRegisterCallbacks

Permite recibir notificaciones de operaciones sobre handles de objetos. Con la rutina **pre-operación**, el driver recibe el `ACCESS_MASK` solicitado para el handle. Si el proceso destino es sensible (como LSASS), el driver puede *remover privilegios* del handle, como `PROCESS_VM_READ`, antes de que se entregue al solicitante.

```c
typedef struct _OB_OPERATION_REGISTRATION {
  POBJECT_TYPE                *ObjectType;    // ej: PsProcessType
  OB_OPERATION                Operations;    // OB_OPERATION_HANDLE_CREATE
  POB_PRE_OPERATION_CALLBACK  PreOperation;
  POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION;
```

### CmRegisterCallbackEx

Registra rutinas para monitorear, bloquear o modificar operaciones de registro. El parámetro `Argument1` es un `REG_NOTIFY_CLASS` que indica el tipo de operación (pre/post creación de clave, set de valor, etc.). Si el driver quiere bloquear la operación, simplemente retorna un `NTSTATUS` de error.

Para deshabilitar callbacks de registro de otros drivers, se manipulan los punteros de la lista doblemente enlazada `CallbackListHead` para desvincular la entrada de interés — cualquier recorrido de la lista la omitirá completamente.


## ETW y ETW-TI: La Fuente

**Event Tracing for Windows (ETW)** es un mecanismo de logging integrado en Windows, compuesto por tres actores:

- **Providers:** generan eventos, identificados por GUID
- **Controllers:** gestionan sesiones de tracing (ej: `logman.exe`)
- **Consumers:** se suscriben a sesiones para recibir eventos

### ¿Qué es un Kernel ETW Provider?

Un kernel ETW provider inyecta datos directamente desde el kernel al feed de ETW. Esto lo hace mucho más resistente a tampering que los providers en modo usuario, donde funciones como `EtwEventWrite` pueden ser hookeadas. Para manipular un kernel provider, el atacante necesita acceso al kernel (por ejemplo, a través de un driver vulnerable).

### ETW-TI: Threat Intelligence ETW

**ETW-TI (`Microsoft-Windows-Threat-Intelligence`)** es una evolución de ETW que instrumenta más del kernel con eventos relevantes para seguridad:

- Allocaciones de memoria remotas
- Cambios de protección de regiones de memoria
- Operaciones de escritura en memoria de otros procesos
- Creación de APCs (Asynchronous Procedure Calls)
- Suspensión de threads
- Y mucho más...

> **Acceso Restringido:** El provider ETW-TI solo puede ser consumido por procesos corriendo con nivel de protección `PS_PROTECTED_ANTIMALWARE_LIGHT` o superior, lo que requiere ser lanzado por un driver ELAM (Early Launch Anti-Malware) firmado por Microsoft. Algunos proyectos comunitarios (JonMon, MentalTi) parchean la estructura `PS_PROTECTION` en el kernel para elevar artificialmente el nivel de protección de su proceso consumidor.

### ¿Por qué ETW-TI reemplaza a los hooks?

Los hooks en `ntdll.dll` son frágiles: pueden ser bypaseados con syscalls directas/indirectas o con unhooking. ETW-TI provee la misma información directamente desde el kernel, sin que el atacante pueda esquivarla desde user-mode. Los EDR modernos están migrando de hooks en user-land hacia ETW-TI como fuente primaria de telemetría.


## Robo de Tokens de Acceso (T1134)

Escalar a `NT AUTHORITY\SYSTEM`, la cuenta con los más altos privilegios en cualquier sistema Windows (superior incluso a un administrador local), es un objetivo central en post-explotación. Una técnica clave para lograrlo es el robo de tokens de acceso.

> **NT AUTHORITY\SYSTEM:** Esta cuenta tiene acceso total a todos los recursos locales, puede controlar servicios, modificar cualquier configuración del sistema y no tiene contraseña. No se puede iniciar sesión directamente como SYSTEM; es usada internamente por el OS y sus servicios. Para el atacante: obtener ejecución con estos privilegios equivale a control total de la máquina.

### Vector 1: Token Impersonation (T1134.001)

El flujo típico de un ataque de token impersonation es:

1. `OpenProcessToken` → abre el handle al token de un proceso SYSTEM
2. `DuplicateTokenEx` → duplica el token como impersonation token
3. `ImpersonateLoggedOnUser` o `SetThreadToken` → aplica el token al thread actual

```c
// DuplicateTokenEx crea una copia del token
DuplicateTokenEx(
  hExistingToken,           // handle al token SYSTEM
  TOKEN_ALL_ACCESS,
  NULL,
  SecurityImpersonation,
  TokenImpersonation,
  &hNewToken
);

// ImpersonateLoggedOnUser aplica el token al thread
// internamente llama NtSetInformationThread
ImpersonateLoggedOnUser(hNewToken);
```

`DuplicateTokenEx` está implementado en `Kernelbase.dll` y por debajo llama a `NtDuplicateToken`. `ImpersonateLoggedOnUser` verifica si el token es primario y, si lo es, crea un impersonation token vía `NtDuplicateToken` antes de llamar a `NtSetInformationThread` para aplicarlo al thread.

### Vector 2: CreateProcessWithToken (T1134.002)

Alternativamente, el token duplicado puede usarse para crear un nuevo proceso bajo el contexto de seguridad de SYSTEM. `CreateProcessWithTokenW` (en `Advapi32.dll`) es un wrapper que realiza una llamada RPC local al servicio **SECLOGON** (Secondary Logon), el cual finalmente ejecuta `CreateProcessAsUserW` en `kernelbase.dll`.

El flujo interno completo es:

```
CreateProcessWithTokenW (Advapi32.dll)
  └→ CreateProcessWithLogonCommonW
       └→ c_SeclCreateProcessWithLogonW
            └→ NdrClientCall3 [RPC → SECLOGON service]
                 └→ SeclCreateProcessWithLogonW (seclogon.dll)
                      └→ SlrCreateProcessWithLogon
                           └→ CreateProcessAsUserW (kernelbase.dll)
```

---

## Evasión con Acceso SYSTEM: Deshabilitar ETW y Callbacks

Con acceso a SYSTEM y un driver en kernel mode (o acceso a través de un driver vulnerable como `RTCore64.sys` o `afd.sys`), es posible deshabilitar las capacidades de detección del EDR directamente en el kernel.

### Paso 1: Enumerar callbacks activos

El primer paso es enumerar los callbacks registrados por el EDR: callbacks de procesos, threads, carga de imágenes, objetos y registro. Se localiza la lista de callbacks en la memoria del kernel buscando la instrucción `lea rcx, [nt!CallbackListHead]` dentro de funciones como `CmUnRegisterCallback`, y se recorre la lista para identificar las entradas del EDR.

> **⚠ Detección — ntoskrnl cargado en proceso:** Una técnica común para resolver offsets es cargar `ntoskrnl.exe` en el proceso actual con `LoadLibraryExA`. Algunos EDRs alertan cuando la imagen del kernel se carga en un proceso de usuario. Una alternativa más sigilosa es usar offsets precalculados basados en la versión específica del kernel, evitando cargar la imagen por completo. Ejecutar el BOF desde un ejecutable firmado por Microsoft también puede reducir la visibilidad.

### Paso 2: Eliminar el callback

Para callbacks de registro (`CmRegisterCallbackEx`), la eliminación se hace manipulando los punteros de la lista doblemente enlazada `CallbackListHead`. Se actualizan los punteros del nodo anterior y siguiente para que se apunten entre sí, "desvinculando" efectivamente la entrada del EDR:

```
Antes:  [Nodo A] ↔ [Nodo EDR] ↔ [Nodo B]
Después: [Nodo A] ↔ [Nodo B]
          (Nodo EDR ya no es visible en el recorrido)
```

### Paso 3: Deshabilitar ETW-TI

Para ETW, se busca la sesión del proveedor `Microsoft-Windows-Threat-Intelligence` en memoria del kernel y se manipula su estado. Con acceso al kernel es posible nulificar el handle al provider o modificar las estructuras que controlan si el provider está activo, deshabilitando efectivamente el feed de telemetría del EDR.


## Procesos Protegidos (PPL): El Último o primer Obstáculo

Incluso con acceso SYSTEM, los EDRs pueden correr como **Protected Process Light (PPL)**, una tecnología que restringe qué accesos puede obtener un proceso no protegido sobre un proceso protegido, limitando los derechos devueltos por `OpenProcess`.

### Jerarquía PPL

PPL implementa una estructura jerárquica con firmas digitales. Los firmantes "superiores" pueden acceder a los "inferiores", pero no al revés. El nivel de protección se almacena en `EPROCESS->Protection`, una estructura `_PS_PROTECTION`:

```c
struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;
            UCHAR Signer : 4;    // nivel de firmante
        };
    };
};
```

> **Windows 11:** A partir de Windows 11, LSASS corre con protección PPL habilitada por defecto. Intentar dumpear su memoria es denegado incluso siendo administrador.

### Bypass con acceso a kernel

Con acceso al kernel, es posible parchear directamente la estructura `_PS_PROTECTION` del proceso del EDR en memoria. Estableciendo el campo `Signer` en `0` (`PsProtectedSignerNone`), se elimina la protección PPL por completo y el proceso del EDR puede ser interactuado sin restricciones.

El flujo completo de evasión queda así:

```
SYSTEM access
  └→ Enumerar callbacks del EDR en kernel
  └→ Desvincular callbacks de proceso/thread/imagen/registro
  └→ Localizar sesión ETW-TI del EDR
  └→ Deshabilitar provider ETW-TI
  └→ Identificar proceso del EDR agent
  └→ Parchear _PS_PROTECTION → Signer = 0 (quitar PPL)
  └→ EDR ciego ✓
```

---

En caso de ser pentester, realizando la deshabilitacion de las defensas como se contextualiza aqui, puedes protefer tambien tus procesos ademas de esto, los EDR/AV en algunas ocaciones no marcan que se deshabilito o falla su persistencia y el reporta que esta todo OK, aqui es donde nosotros superamos una persistencia y llegamos al mejor nivel que es ESTABILIDAD.

Si este es tu escenario "FELICIDADES" acabas de romper de una manera hermosa las defensas y lo que estes analizando. XD

## Mapping MITRE D3FEND

Las técnicas defensivas del framework MITRE D3FEND que corresponden a las capacidades de detección descritas en este post:

| ID | Técnica Defensiva |
|---|---|
| D3-PSA | Process Spawn Analysis |
| D3-SSC | Shadow Stack Comparisons |
| D3-SCA | System Call Analysis |
| D3-PSMD | Process Self-Modification Detection |
| D3-FH | File Hashing |
| D3-FIM | File Integrity Monitoring |
| D3-CAA | Connection Attempt Analysis |
| D3-IPCTA | IPC Traffic Analysis |
| D3-FCOA | File Content Analysis |
| D3-FAPA | File Access Pattern Analysis |
| D3-PCSV | Process Code Segment Verification |
| D3-PLA | Process Lineage Analysis |
| D3-MBT | Memory Boundary Tracking |
| D3-NTF | Network Traffic Filtering |
| D3-ITF | Inbound Traffic Filtering |
| D3-OTF | Outbound Traffic Filtering |

Referencias: [MITRE ATT&CK](https://attack.mitre.org) · [MITRE D3FEND](https://d3fend.mitre.org) · [Microsoft Docs](https://learn.microsoft.com) · WinDbg

---

*Perspectiva: ofensiva y defensiva — entender ambos lados es la clave.*

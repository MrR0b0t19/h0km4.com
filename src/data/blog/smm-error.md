---
author: Arnold Morales
pubDatetime: 2026-02-28T14:47:00Z
modDatetime: 2025-02-28T14:51:45.934Z
title: Búsqueda de errores en SMM
slug: smm-error
featured: true
draft: false
tags:
  - SMM
  - DMA
  - BIOS
  - reversing
  - PCILeech
description:
    SMM es el corazon de la bios.
---

# Búsqueda de Errores SMM

En la busqueda interminable de vulnerabilidades llevo trabajando en esto este año 2026 y me parecieron muy interesantes y repetitivas estas vulnerabilidades asi que es un placer compartir todo lo que se sobre ellas.

## Introducción y Contexto

El **System Management Mode (SMM)** es un modo de operación especial de las CPUs x86/x86-64 que fue introducido originalmente por Intel para gestionar funciones de administración de energía y hardware de bajo nivel. Opera con el nivel de privilegio más alto posible, por encima incluso del hipervisor (Ring -2 en la jerarquía informal). Cuando una CPU entra en SMM —normalmente a través de una **System Management Interrupt (SMI)**— suspende la ejecución normal del sistema operativo, guarda el estado del procesador en una región de memoria denominada **SMRAM** (System Management RAM), ejecuta el código SMM correspondiente y luego restaura el estado para reanudar la ejecución normal.

La SMRAM está protegida por hardware mediante el registro **SMRR (System Management Range Register)**, que define los límites físicos de esta región. En condiciones normales, el código fuera de SMM no puede leer ni escribir en ella. Sin embargo, como veremos a continuación, existen numerosas vías indirectas a través de las cuales un atacante con privilegios a nivel de sistema operativo puede influir en lo que ocurre dentro de SMM.

> **Nota importante sobre el modelo de amenaza:** Las vulnerabilidades SMM generalmente requieren privilegios de nivel kernel (Ring 0) para ser explotadas, es decir, el atacante ya ha comprometido el sistema operativo. Sin embargo, la motivación para escalar a SMM es significativa: el código SMM puede persistir incluso ante reinstalaciones del SO, puede desactivar mecanismos de seguridad del firmware como Secure Boot, y puede operar completamente invisible para cualquier software que corra sobre él.

Si bien en teoría el código SMM está aislado del mundo exterior, en realidad hay muchas circunstancias en las que el código que no es SMM puede activar e incluso afectar el código que se ejecuta dentro de SMM. Debido a que SMM tiene una arquitectura compleja con muchas "partes móviles", la superficie de ataque es bastante amplia y contiene, entre otras cosas, datos pasados en buffers de comunicación, variables NVRAM, dispositivos con capacidad DMA, etc.

Tenga en cuenta que la lista de vulnerabilidades no es exhaustiva y contiene solo vulnerabilidades específicas del entorno SMM. Por ese motivo, no incluirá errores más genéricos como desbordamientos de pila y dobles liberaciones.


## 1. Llamadas de SMM (SMM Callouts)

### Descripción

La clase de vulnerabilidad SMM más básica se conoce como llamada "SMM" o *callout*. Esto ocurre siempre que el código SMM llama a una función ubicada fuera de los límites de SMRAM (según lo definido por el SMRR). El escenario de llamada más común es un controlador SMI que intenta invocar un servicio de arranque UEFI o un servicio de tiempo de ejecución como parte de su operación. Los atacantes con privilegios a nivel de sistema operativo pueden modificar las páginas físicas donde viven estos servicios antes de activar el SMI, secuestrando así el flujo de ejecución privilegiado una vez que se llama al servicio afectado.

```
Memoria física
    |
    SMRAM
    CALL F000:8070
    → un salto de code fetch en SMM
    ----------------1MB
    LEGACY BIOS SHADOW
    (F/E-segments)
    PA = 0xF0000
    ---------------carga
    0xF8070: PAYLOAD
```

En resumen: `0F000:08070 = 0xF8070 PA`

Así se vería una llamada al SMM.

> **¿Por qué ocurre esto?** Muchos controladores SMI fueron escritos originalmente para ejecutarse durante la fase de arranque (DXE/BDS), donde los servicios de arranque UEFI están disponibles. Cuando ese mismo código se reutiliza en un contexto SMM sin modificación, naturalmente sigue llamando a esos servicios, que ahora viven en memoria no protegida.

### Mitigación

Además del enfoque obvio de no escribir dicho código defectuoso en primer lugar, las llamadas SMM también se pueden mitigar a nivel de hardware. A partir de la cuarta generación de la microarquitectura Core (Haswell), las CPUs Intel admiten una función de seguridad llamada `SMM_Code_Chk_En`. Si esta función de seguridad está activada, la CPU tiene prohibido ejecutar cualquier código ubicado fuera de la región SMRAM una vez que ingresa a SMM. Se puede pensar en esta característica como el equivalente SMM de la prevención de ejecución del modo supervisor (SMEP).

La consulta del estado de esta mitigación se puede realizar ejecutando el módulo [smm_code_chk](https://chipsec.github.io/modules/chipsec.modules.common.smm_code_chk.html) de CHIPSEC.

> **Nota adicional sobre mitigaciones:** Además de `SMM_Code_Chk_En`, los procesadores modernos también implementan **SMM_Enable** en el registro IA32_FEATURE_CONTROL, que puede bloquear cambios al contenido de SMRAM después del arranque. Las plataformas que implementan correctamente el ciclo de vida del firmware deben habilitar ambas protecciones antes de transferir el control al sistema operativo (evento conocido como *End of DXE*).

### Detección

La detección estática de llamadas SMM es bastante sencilla. Dado un binario SMM, debemos analizarlo mientras buscamos controladores SMI que tengan algún flujo de ejecución que conduzca a llamar a un servicio de arranque o tiempo de ejecución UEFI. De esta manera, el problema de encontrar llamadas SMM se reduce al problema de buscar en el gráfico de llamadas ciertas rutas. Afortunadamente, no se requiere ningún esfuerzo adicional ya que esta heurística ya está implementada por el excelente plugin [efiXplorer](https://github.com/binarly-io/efiXplorer) para IDA.

**efiXplorer** es la herramienta estándar de facto para analizar binarios UEFI con IDA. Entre otras cosas, se ocupa de lo siguiente:

- Localización y cambio de nombre de GUID UEFI conocidos
- Localización y cambio de nombre de controladores SMI
- Localización y cambio de nombre de los servicios de arranque/tiempo de ejecución de UEFI
- Las versiones recientes de efiXplorer utilizan el descompilador Hex-Rays para mejorar el análisis. Una de esas características es la capacidad de asignar el tipo correcto a los punteros de interfaz pasados a métodos como `LocateProtocol()` o su contraparte SMM `SmmLocateProtocol()`.

En su mayor parte, esta heurística funciona muy bien, pero hemos encontrado varios casos extremos en los que también podría generar algunos falsos positivos. La más común se debe al uso de `EFI_SMM_RUNTIME_SERVICES_TABLE`. Esta es una tabla de configuración UEFI que expone exactamente la misma funcionalidad que el estándar `EFI_RUNTIME_SERVICES_TABLE`, con la única diferencia significativa de que, a diferencia de su contraparte "estándar", reside en SMRAM y, por lo tanto, es adecuada para ser consumida por los controladores SMI. Muchos binarios SMM a menudo remapean el puntero global `RuntimeServices` a la implementación específica de SMM después de completar algunas tareas de inicialización estándar. Llamar a servicios en tiempo de ejecución a través del puntero reasignado produce una situación que parece ser una llamada a primera vista, aunque un examen más detallado demostrará lo contrario. Para superar esto, los analistas siempre deben buscar en el binario SMM el GUID `EFI_SMM_RUNTIME_SERVICES_TABLE`. Si se encuentra este GUID, es probable que la mayoría de las llamadas que involucran servicios de tiempo de ejecución UEFI sean falsos positivos. Sin embargo, esto no se aplica a las llamadas que involucran servicios de arranque.

**Falsos positivos**

Un falso positivo causado por una llamada `GetVariable()` a través del puntero `RuntimeService` reasignado. Otra fuente de posibles falsos positivos son varias funciones contenedoras que son "modo dual", lo que significa que se pueden llamar desde contextos SMM y no SMM. Internamente, estas funciones envían una llamada a un servicio SMM si la persona que llama se está ejecutando en SMM y, en caso contrario, envían una llamada al servicio de arranque/tiempo de ejecución equivalente. El ejemplo más común que hemos visto en la naturaleza es `FreePool()` desde EDK2, que llama a `gSmst->SmmFreePool()` si el buffer a liberar reside en SMRAM, o llama a `gBs->FreePool()` de otro modo.

Las funciones de utilidad `FreePool()` de EDK2 son una fuente común de falsos positivos. Como demuestra este ejemplo, los cazadores de errores deben ser conscientes del hecho de que las técnicas de análisis de código estático tienen dificultades para determinar que ciertas rutas de código no se ejecutarán en la práctica y, como tal, es probable que las marquen como llamadas. Algunos consejos y trucos para identificar esta función en binarios compilados se transmitirán en la sección de Identificación de funciones de biblioteca.

## 2. Corrupción SMRAM Baja (Low SMRAM Corruption)

### Descripción

En circunstancias normales, el búfer de comunicación utilizado para pasar argumentos al controlador SMI no debe superponerse con SMRAM. La razón de esta restricción es bastante simple: si ese no fuera el caso, cada vez que el controlador SMI escribiera algunos datos en el búfer de comunicaciones —por ejemplo, para devolver un código de estado al llamador— también modificaría alguna parte de SMRAM en el camino, lo cual no es deseable.

En EDK2, se llama a la función responsable de comprobar si un búfer determinado se superpone o no con SMRAM `SmmIsBufferOutsideSmmValid()`. Esta función se llama al búfer de comunicación en cada invocación de SMI para hacer cumplir esta restricción.

EDK2 prohíbe que el búfer de comunicaciones se superponga con SMRAM. Lamentablemente, dado que el tamaño del búfer de comunicación también está bajo el control del atacante, esta verificación por sí sola no es suficiente para garantizar la protección y algunas responsabilidades adicionales recaen sobre los desarrolladores del firmware. Como veremos en breve, muchos controladores SMI fallan aquí y dejan un vacío que los atacantes pueden explotar para violar esta restricción y corromper la parte inferior de SMRAM.

Para entender cómo, veamos más de cerca un ejemplo concreto. Supongamos un controlador vulnerable que se vería algo como:

```cpp
EFI_STATUS __fastcall SmiHandler_1F90(
    EFI_HANDLE DispatchHandle,
    const void *Context,
    CommBuffer_1F90 *CommBuffer,
    UINTN *CommBufferSize)
{
    unsigned __int64 v4; // rax
    // sección vulnerable
    if ( !CommBuffer || !CommBufferSize )
        return 0x800000000000002ui64;

    v4 = readmsr(0x115u); // MSR_IDT_MCR5
    CommBuffer->field_0 = (HIDWORD(v4) << 32);
    return 0i64; 
}
```

Podemos dividir su funcionamiento en 4 pasos discretos:

1. Comprobación de cordura de los argumentos.
2. Lectura del valor del registro `MSR_IDT_MCR5` en una variable local.
3. Cálculo de un valor de 64 bits a partir de él y escritura del resultado nuevamente en el búfer de comunicación.
4. Retorno a la persona que llama.

El lector astuto puede ser consciente del hecho de que durante el paso 3 se escribe un valor de 8 bytes en el búfer de comunicaciones, pero en ninguna parte durante el paso 1 el código verifica el requisito previo de que el búfer tenga al menos 8 bytes de longitud. Debido a que se omite esta verificación, un atacante puede explotarla mediante:

- Colocar el búfer de comunicaciones en una ubicación de memoria lo más adyacente posible a la base de SMRAM (digamos `SMRAM – 1`).
- Establecer el tamaño del búfer de comunicaciones en un valor entero lo suficientemente pequeño, digamos 1 byte.
- Activar el SMI vulnerable.

Esquemáticamente, el diseño de la memoria se vería de la siguiente manera:

```
COMM BUFFER
(SMRAM - 1) ACTIVO

→ siguiente flujo - memoria física

Acceso a SMRAM

Disposición de la memoria en el momento de la invocación de SMI
```

Hasta donde `SmmEntryPoint` respecta, el búfer de comunicaciones tiene solo 1 byte de longitud y no se superpone con la SMRAM. Por eso, `SmmIsBufferOutsideSmmValid()` tendrá éxito y se llamará al controlador SMI real. Durante el paso 3, el controlador escribirá ciegamente un valor QWORD en el búfer de comunicaciones y, al hacerlo, también escribirá involuntariamente sobre los 7 bytes inferiores de SMRAM.

Basado en EDK2, la parte inferior de TSEG (la ubicación estándar de facto para SMRAM) contiene una estructura de tipo `SMM_S3_RESUME_STATE` cuyo trabajo es controlar la recuperación del estado de sueño S3. Como se puede ver a continuación, esta estructura contiene una gran cantidad de miembros y punteros de función cuya corrupción puede beneficiar al atacante:

```cpp
typedef struct {
  UINT64                  Signature;
  EFI_PHYSICAL_ADDRESS    SmmS3ResumeEntryPoint;
  EFI_PHYSICAL_ADDRESS    SmmS3StackBase;
  UINT64                  SmmS3StackSize;
  UINT64                  SmmS3Cr0;
  UINT64                  SmmS3Cr3;
  UINT64                  SmmS3Cr4;
  UINT16                  ReturnCs;
  EFI_PHYSICAL_ADDRESS    ReturnEntryPoint;
  EFI_PHYSICAL_ADDRESS    ReturnContext1;
  EFI_PHYSICAL_ADDRESS    ReturnContext2;
  EFI_PHYSICAL_ADDRESS    ReturnStackPointer;
  EFI_PHYSICAL_ADDRESS    Smst;
} SMM_S3_RESUME_STATE;
```

> **¿Por qué es tan crítica esta estructura?** `SmmS3ResumeEntryPoint` y `ReturnEntryPoint` son punteros de función que se invocan durante la reanudación desde S3. Si un atacante logra corromper cualquiera de ellos y luego induce un ciclo de suspensión/reanudación, puede redirigir la ejecución a código arbitrario con privilegios SMM. Esto es particularmente grave porque la reanudación S3 ocurre durante el arranque, antes de que el sistema operativo tenga la oportunidad de cargar ninguna defensa.

### Mitigación

Para mitigar esta clase de vulnerabilidades, los controladores SMI deben verificar explícitamente el tamaño del búfer de comunicación proporcionado y abandonar la ejecución en caso de que el tamaño real difiera del tamaño esperado. Esto se puede lograr de dos maneras:

**Método 1:** Desreferenciar el argumento `CommBufferSize` proporcionado y luego compararlo con el tamaño esperado. Este método funciona porque `SmmEntryPoint` ya llama a `SmmIsBufferOutsideSmmValid(CommBuffer, *CommBufferSize)`, que garantiza que los `*CommBufferSize` bytes del búfer se encuentran fuera de la SMRAM.

```cpp
if ( !CommBufferSize )
    return 0i64;
if ( *CommBufferSize != 56 )
    return 0i64;
```

La mitigación de la corrupción de SMRAM baja se puede lograr simplemente verificando el argumento `CommBufferSize`.

**Método 2:** Llamar a `SmmIsBufferOutsideSmmValid()` nuevamente en el Comm Buffer, esta vez con el tamaño concreto esperado por el controlador.

> **Consejo adicional:** El Método 1 y el Método 2 no son mutuamente excluyentes. La práctica más defensiva es combinar ambos: primero verificar que `*CommBufferSize` sea exactamente el tamaño esperado, y luego opcionalmente llamar a `SmmIsBufferOutsideSmmValid()` con ese tamaño fijo. Esto elimina cualquier ambigüedad sobre qué región se está validando y hace el código más resistente a refactorizaciones futuras.

### Detección

Para detectar esta clase de vulnerabilidades, deberíamos buscar controladores SMI que no verifiquen adecuadamente el tamaño del búfer de comunicaciones. Esto sugiere que el controlador no realiza ninguna de las siguientes acciones:

1. Desreferenciar el argumento `CommBufferSize`.
2. Llamar a `SmmIsBufferOutsideSmmValid()` en el buffer de comunicación.

La condición 1 es sencilla de comprobar porque efiXplorer ya se encarga de localizar los controladores SMI y asignarles su prototipo de función correcto. La condición 2 también es fácil de validar, pero el quid de la cuestión es este: ya que `SmmIsBufferOutsideSmmValid()` está vinculado estáticamente al código, debemos poder identificarlo en el binario compilado. Algunos consejos y trucos para hacerlo se pueden encontrar en la sección de Identificación de funciones de biblioteca.

## 3. Ataques de TOCTOU (Time-of-Check to Time-of-Use)

### Descripción

A veces, incluso llamando a `SmmIsBufferOutsideSmmValid()` sobre punteros anidados no es suficiente para hacer que un controlador SMI sea completamente seguro. La razón de esto es que SMM no fue diseñado teniendo en cuenta la concurrencia y, como resultado, sufre algunas condiciones de carrera inherentes, siendo la más destacada los ataques de **TOCTOU** contra el búfer de comunicación. Debido a que el búfer de comunicación en sí reside fuera de SMRAM, su contenido puede cambiar mientras se ejecuta el controlador SMI. Este hecho tiene graves implicaciones para la seguridad, ya que significa que las recuperaciones dobles no necesariamente producirán los mismos valores.

En un intento por remediar esto, SMM en entornos de multiprocesamiento sigue lo que se conoce como "encuentro SMI" (*SMI rendezvous*). En pocas palabras, una vez que una CPU ingresa a SMM, un preámbulo de software dedicado enviará una **Interrupción entre procesadores (IPI)** a todos los demás procesadores del sistema. Este IPI hará que ingresen también a SMM y esperen allí a que se complete el SMI. Sólo entonces podrá el primer procesador llamar de forma segura a la función del controlador para dar servicio realmente al SMI.

Este esquema es muy eficaz para evitar que otros procesadores interfieran con el búfer de comunicación mientras se utiliza, pero, por supuesto, las CPUs no son las únicas entidades que tienen acceso al bus de memoria. Como enseña cualquier curso básico de sistemas operativos, hoy en día muchos dispositivos de hardware son capaces de actuar como agentes **DMA** (*Direct Memory Access*), lo que significa que pueden leer/escribir memoria sin pasar por la CPU en absoluto. Estas son excelentes noticias en cuanto a rendimiento, pero son terriblemente malas noticias en lo que respecta a la seguridad del firmware.

El hardware compatible con DMA puede modificar el contenido del búfer de comunicación mientras se ejecuta una SMI.

Para ver cómo las operaciones DMA pueden ayudar a la explotación, veamos el siguiente fragmento tomado de un controlador SMI de la vida real:

```cpp
smm_field_18 = CommBuffer->field_18;
if ( v7 > dword_3120 - v6 )
    v7 = dword_3120 - v6;
CommBuffer->field_10 = v7;
if ( SmmIsBufferOutsideSmmValid(smm_field_18, v7) ) // Verificación sobre copia local
{
    if ( v9 && CommBuffer->field_18 != (v6 + qword_3128) )
        CopyMem(CommBuffer->field_18, (v6 + qword_3128), v9); // Re-lectura del buffer original ← PELIGRO
}
else
{
    v4 = EFI_ACCESS_DENIED;
}
```

Este controlador SMI es vulnerable a un ataque TOCTOU. Como se puede ver, hace referencia a un puntero anidado al que llamamos `field_18` en al menos 3 ubicaciones diferentes:

1. Primero, su valor se recupera del búfer de comunicaciones y se guarda en una variable local en SMRAM.
2. Entonces, `SmmIsBufferOutsideSmmValid()` se llama a la variable local para asegurarse de que no se superponga a SMRAM.
3. Si se considera seguro, el puntero anidado se vuelve a leer **desde el búfer de comunicación original** (no desde la variable local) y luego se pasa a `CopyMem()` como argumento de destino.

> **El error conceptual aquí es sutil pero fatal:** el desarrollador creyó que copiar `field_18` a una variable local era suficiente, pero la validación ocurre sobre la copia mientras la escritura usa nuevamente el original. Si el DMA malicioso modifica `CommBuffer->field_18` entre los pasos 2 y 3, la validación habrá validado una dirección segura pero la escritura ocurrirá en una dirección potencialmente arbitraria.

Como se mencionó anteriormente, nada garantiza que las lecturas consecutivas del búfer de comunicación necesariamente produzcan el mismo valor. Esto significa que un atacante puede emitir esta SMI con el puntero haciendo referencia a una ubicación perfectamente segura fuera de la SMRAM. Sin embargo, justo después de que el SMI valida el puntero anidado y justo antes de recuperarlo nuevamente, existe una pequeña ventana de oportunidad donde un ataque DMA puede modificar su valor para apuntar a otro lugar. Sabiendo que pronto se pasará el puntero a `CopyMem()`, el atacante podría indicar una dirección en SMRAM que quiere corromper.

Un dispositivo DMA malicioso puede modificar el puntero dentro del `CommBuffer` para que apunte a otro lugar, potencialmente a la memoria SMRAM.

### Mitigación

La mitigación correcta para los ataques TOCTOU es copiar **todo** el contenido relevante del `CommBuffer` a variables locales en SMRAM **antes** de hacer cualquier validación, y luego usar exclusivamente esas copias locales durante el resto de la ejecución. Nunca se debe leer dos veces un campo del `CommBuffer` cuando la primera lectura ha sido utilizada para tomar una decisión de seguridad. El patrón correcto sería:

```cpp
// CORRECTO: copiar primero, validar y usar la copia
EFI_PHYSICAL_ADDRESS local_field_18 = CommBuffer->field_18; // única lectura
if ( SmmIsBufferOutsideSmmValid(local_field_18, v7) )
{
    if ( v9 && local_field_18 != (v6 + qword_3128) )
        CopyMem(local_field_18, (v6 + qword_3128), v9); // usa la copia local
}
```

Adicionalmente, en sistemas que implementan **Intel VT-d** o **AMD-Vi** (IOMMU), es posible configurar la unidad de traducción de E/S para restringir qué regiones de memoria pueden acceder los dispositivos DMA. Si la SMRAM está excluida del espacio de direcciones accesible por DMA a nivel de IOMMU, los ataques TOCTOU mediados por hardware se vuelven imposibles incluso si el código tiene el patrón incorrecto. Sin embargo, no se debe depender únicamente de esta protección de hardware: la corrección del código debe ser la primera línea de defensa.

### Detección

Para detectar vulnerabilidades TOCTOU en los controladores SMI es necesario reconstruir el diseño interno del búfer de comunicación y luego contar cuántas veces se obtiene cada campo. Si el mismo campo se recupera dos veces o más mediante el mismo flujo de ejecución, es probable que el controlador respectivo sea susceptible a tales ataques. La gravedad de estos problemas depende en gran medida de los tipos de campos individuales, siendo los campos punteros los más agudos. Nuevamente, reconstruir adecuadamente la estructura del `CommBuffer` ayuda en gran medida a evaluar el riesgo potencial.


## 4. Manejadores Conscientes Exclusivamente de CSEG

### Descripción

La ubicación estándar de facto para la memoria SMRAM es el **Segmento de Memoria Superior**, a menudo abreviado como **TSEG**. Aún así, en muchas máquinas, una región SMRAM separada llamada **CSEG** (*Compatibility Segment*) coexiste con TSEG por razones de compatibilidad con hardware heredado. A diferencia de TSEG, cuya ubicación en la memoria física puede ser programada por el BIOS, la ubicación de la región CSEG está fijada en el rango de direcciones `0xA0000–0xBFFFF`. Algunos controladores SMI heredados se diseñaron teniendo en cuenta únicamente CSEG, un hecho del que los atacantes pueden abusar. A continuación se muestra un ejemplo de uno de estos controladores:

```cpp
int64 __fastcall SwSmiHandler_1368(EFI_HANDLE DispatchHandle, void *Context, void *CommBuffer, UINTN *CommBufferSize)
{
    unsigned __int8 *v_AttackerControllableAddress; // rcx
    int v_SavedRflags; // [rsp+30h] [rbp-18h] BYREF
    int v_SavedEs; // [rsp+34h] [rbp-14h] BYREF
    unsigned __int32 v_SavedBx[4]; // [rsp+38h] [rbp-10h] BYREF

    v_SavedEs = 0;
    (gSmmCpu_22F48->ReadSaveState)(gSmmCpu_22F48, 2i64, EFI_SMM_SAVE_STATE_REGISTER_ES, 0i64, &v_SavedEs);
    (gSmmCpu_22F48->ReadSaveState)(gSmmCpu_22F48, 4i64, EFI_SMM_SAVE_STATE_REGISTER_RBX, 0i64, &v_SavedBx);
    v_AttackerControllableAddress = (16 * v_SavedEs + LOWORD(v_SavedBx[0])); 
    if ((v_AttackerControllableAddress - 0xA00000) > 0x1FFFFF) {
        func_3020(v_AttackerControllableAddress);
        (gSmmCpu_22F48->ReadSaveState)(gSmmCpu_22F48, 4i64, EFI_SMM_SAVE_STATE_REGISTER_RFLAGS, 0i64, &v_SavedRflags);
        v_SavedRflags &= 0xFFFFFFFF;
        (gSmmCpu_22F48->WriteSaveState)(gSmmCpu_22F48, 4i64, EFI_SMM_SAVE_STATE_REGISTER_RFLAGS, 0i64, &v_SavedRflags);
        return EFI_SUCCESS;
    }
}
```

Un controlador SMI con algunas protecciones específicas de CSEG.

A diferencia de los controladores que revisamos hasta ahora, este controlador SMI no obtiene sus argumentos a través del búfer de comunicación. En su lugar, utiliza el `EFI_SMM_CPU_PROTOCOL` para leer registros del **Estado guardado de SMM** (*SMM Save State*), creado automáticamente por la CPU al ingresar a SMM. Por lo tanto, la superficie de ataque potencial en este ejemplo no es el búfer de comunicación, sino los registros de propósito general de la CPU, cuyos valores se pueden establecer casi arbitrariamente antes de emitir el SMI.

El controlador funciona de la siguiente manera:

1. Primero, lee los valores de los registros ES y EBX del estado guardado.
2. Luego, calcula una dirección lineal a partir de ellos utilizando la fórmula: `16 * ES + (EBX & 0xFFFF)`.
3. Por último, comprueba que la dirección calculada no se encuentre dentro de los límites de CSEG. Si la dirección se considera segura, se pasa como argumento a la función en `0x3020`.

> **El problema de raíz:** El controlador reiventa la lógica de `SmmIsBufferOutsideSmmValid()` pero solo para CSEG, ignorando completamente que TSEG y otras regiones SMRAM también existen. Esta es una falla clásica de "lista de exclusión incompleta" (*incomplete denylist*): en lugar de verificar que la dirección esté en una región explícitamente permitida (*allowlist*), el código solo verifica que no esté en un lugar específico conocido por el desarrollador.

Tenga en cuenta que el controlador esencialmente vuelve a implementar funciones de utilidad comunes como `SmmIsBufferOutsideSmmValid()`, solo que lo hace de una manera deficiente que descuida por completo los segmentos SMRAM distintos de CSEG. En teoría, los atacantes pueden configurar los registros ES y BX de modo que la dirección lineal calculada apunte a alguna otra región SMRAM como TSEG y seguramente pase las comprobaciones de seguridad impuestas por el controlador.

En la práctica, sin embargo, es probable que esta vulnerabilidad no sea explotable de manera realista. La razón de esto es que la dirección lineal máxima a la que podemos llegar está limitada a `16 * 0xFFFF + 0xFFFF == 0x10FFEF`, y la experiencia muestra que TSEG suele estar ubicado en direcciones mucho más altas. Sin embargo, es bueno ser consciente de estos controladores y del peligro que imponen.

### Mitigación

Mitigar estas vulnerabilidades depende enteramente de los desarrolladores del controlador SMI. La corrección es reemplazar la lógica artesanal de verificación de límites por llamadas a `SmmIsBufferOutsideSmmValid()`, que está diseñada para tener en cuenta todas las regiones SMRAM registradas en el sistema, no solo CSEG.

### Detección

Una buena estrategia para identificar estos casos es buscar controladores SMI que utilicen "números mágicos" que hagan referencia a algunas características únicas de CSEG. Estos incluyen valores inmediatos como `0xA0000` (la dirección base física de CSEG), `0x1FFFF` (su tamaño) y `0xBFFFF` (último byte direccionable). Según nuestra experiencia, es probable que una función que utiliza dos o más de estos valores tenga algún comportamiento específico de CSEG y debe examinarse cuidadosamente para evaluar su riesgo potencial.


## 5. Variables NVRAM como Superficie de Ataque

### Descripción

Una superficie de ataque frecuentemente subestimada en el contexto de SMM son las **variables NVRAM UEFI** (también conocidas como variables EFI). Estas variables se almacenan en flash y persisten entre reinicios; muchos controladores SMI las leen durante su inicialización o en cada invocación de SMI para obtener parámetros de configuración o datos de estado.

Dado que las variables NVRAM pueden ser escritas por código con privilegios de sistema operativo (mediante `SetVariable()` del runtime), un atacante que controla el sistema operativo puede pre-posicionar datos maliciosos en una variable NVRAM antes de activar el SMI que los consume.

Los patrones vulnerables más comunes incluyen:

- **Ausencia de validación de tamaño:** El controlador SMI lee una variable NVRAM con `GetVariable()` y asume que tiene el tamaño esperado, copiándola a un buffer de tamaño fijo sin verificar primero cuántos bytes devolvió realmente `GetVariable()`.
- **Ausencia de validación de contenido:** El controlador confía ciegamente en valores leídos de la variable (como índices de array u offsets) sin verificar que estén dentro de rangos válidos antes de usarlos.
- **Punteros almacenados en NVRAM:** En algunos diseños especialmente problemáticos, se almacenan direcciones físicas directamente en variables NVRAM. Un atacante puede modificarlas para que apunten a ubicaciones SMRAM.

### Mitigación

Los controladores SMI nunca deben asumir que el contenido de una variable NVRAM es confiable, incluso si dicha variable fue escrita por el propio firmware en una etapa previa del arranque. La defensa correcta es tratar toda variable NVRAM como datos controlados por el atacante y aplicar la misma rigurosidad de validación que se aplicaría a un `CommBuffer`. Esto incluye verificar el tamaño devuelto por `GetVariable()`, validar rangos de todos los campos, y nunca desreferenciar punteros provenientes de NVRAM sin validación previa con `SmmIsBufferOutsideSmmValid()`.

Adicionalmente, para variables NVRAM que solo el firmware debería escribir, se debe considerar el uso de variables con atributos que excluyan `EFI_VARIABLE_RUNTIME_ACCESS`, lo que previene que el sistema operativo las modifique en runtime.

### Detección

La detección estática consiste en identificar controladores SMI que llaman a `GetVariable()` (o su equivalente SMM) y rastrear el uso posterior de los datos retornados. Cualquier uso de esos datos como tamaño de copia, índice de array, offset de pointer aritmético o argumento a `CopyMem()` sin validación previa es una señal de alerta.

## 6. SMBASE Relocation y Ataques Asociados

### Descripción

El registro **SMBASE** define la dirección base de la SMRAM para un procesador lógico dado. Su valor predeterminado al arrancar el sistema es `0x30000`, lo que significa que el código SMM y el estado guardado se ubican inicialmente en esa dirección. Durante la fase de arranque, el firmware típicamente "relocaliza" SMBASE a TSEG mediante un procedimiento específico que implica entrar y salir de SMM con el nuevo valor configurado.

Si el proceso de relocalización no se completa correctamente, o si existe alguna ventana temporal donde SMBASE todavía apunta a memoria no protegida, un atacante puede escribir código en `0x30000` (u otra dirección baja) antes de que ocurra la relocalización y secuestrar la ejecución SMM.

> **¿Por qué puede quedar la memoria baja sin proteger?** Muchas plataformas configuran el *SMRAM lock* (el bit que hace la SMRAM de solo lectura desde fuera de SMM) solo después de completar la relocalización. Si existe una ventana entre el arranque del procesador de aplicación (AP) y el lock, hay una oportunidad de ataque. Igualmente, si el procesador de aplicación no es inicializado correctamente y sigue apuntando a la SMBASE predeterminada, puede ser explotado.

### Mitigación

La mitigación principal es asegurarse de que todos los procesadores lógicos del sistema sean correctamente relocalizados a TSEG antes de que se habilite el acceso del sistema operativo a ellos, y que el lock de SMRAM se active inmediatamente después. La herramienta CHIPSEC incluye el módulo `smm` que verifica si el lock de SMRAM está activado.

### Detección

La verificación de que el lock de SMRAM está correctamente habilitado se puede realizar con CHIPSEC:

```bash
python chipsec_main.py -m common.smm
```

## 7. Herramientas y Metodología General

Para llevar a cabo un análisis completo de seguridad de controladores SMM, se recomienda seguir la siguiente metodología:

**Extracción del firmware:** El primer paso es extraer los módulos SMM del firmware. Herramientas como `UEFITool` o `uefi-firmware-parser` pueden parsear imágenes de firmware UEFI y extraer los módulos individuales en formato PE/COFF.

**Análisis estático con IDA + efiXplorer:** Una vez extraídos los módulos, efiXplorer automatiza gran parte del trabajo inicial: renombra GUIDs, identifica controladores SMI y sus prototipos, y marca servicios de arranque/runtime. Esto proporciona una base sólida para el análisis manual posterior.

**Búsqueda automática de patrones:** Algunas de las clases de vulnerabilidades descritas en este documento se pueden buscar automáticamente. Proyectos como **efiXplorer** y **EClypsium** han desarrollado heurísticas que identifican automáticamente callouts, ausencia de verificación de `CommBufferSize`, y otras anomalías comunes.

**Verificación dinámica con CHIPSEC:** [CHIPSEC](https://github.com/chipsec/chipsec) es un framework de análisis de seguridad de plataforma que puede ejecutarse en un sistema real para verificar el estado de mitigaciones de hardware como `SMM_Code_Chk_En`, el lock de SMRAM, la configuración del IOMMU, entre otros.

**Revisión manual:** Las clases de vulnerabilidades más sutiles, especialmente TOCTOU y el manejo incorrecto de variables NVRAM, frecuentemente requieren revisión manual del código descompilado para ser identificadas con confianza.

## Resumen de Clases de Vulnerabilidades

| Clase | Vector de ataque | Impacto | Mitigación principal |
|---|---|---|---|
| SMM Callout | Modificar páginas de servicios UEFI | Ejecución de código arbitrario en SMM | `SMM_Code_Chk_En`, no llamar a servicios externos desde SMM |
| Low SMRAM Corruption | CommBuffer adyacente a SMRAM + tamaño pequeño | Corrupción de estructuras críticas como `SMM_S3_RESUME_STATE` | Verificar `*CommBufferSize` antes de escribir |
| TOCTOU | Dispositivo DMA modificando CommBuffer en vuelo | Escritura arbitraria en SMRAM | Copiar CommBuffer a SMRAM antes de validar; IOMMU |
| CSEG-Only Handlers | Registros CPU apuntando a TSEG | Acceso arbitrario a SMRAM (limitado) | Usar `SmmIsBufferOutsideSmmValid()` en lugar de lógica artesanal |
| NVRAM Poisoning | Escribir variable NVRAM maliciosa desde SO | Variable según uso (RCE, corrupción) | Validar todos los datos de NVRAM como no confiables |
| SMBASE Relocation | Escribir en memoria baja antes del lock | Control total de ejecución SMM | Relocalizar y lockear SMRAM antes de exponer APs al SO |


---

Espero que esto te sirva de ayuda para tus investigaciones!

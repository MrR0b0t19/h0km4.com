---
author: Arnold Morales
pubDatetime: 2026-02-27T14:47:00Z
modDatetime: 2025-02-27T14:51:45.934Z
title: Los registros de hardware controlan instrumentos modulares
slug: Hwd-control
featured: true
draft: false
tags:
  - PCIe
  - PCI
  - Windows
  - Evasion
  - EDR
  - PCILeech
description:
    La importancia de root complex para anillo -3 en windows.
---

# Introduccion

He/Hemos estado investigando unos temas particulares y creo que esta informacion puede servir de mucha ayuda si ustedes se encuentran con un problema similar, he leido muchos blogs y papers interesantes tratare de resumir un poco en este tema que considero el primer punto en nuestra investigacion.
lets go...

# Los registros de hardware controlan instrumentos modulares

A diferencia de los instrumentos de caja (*benchtop*), los instrumentos modulares se integran directamente en buses de entrada/salida de alta velocidad como PCIe. Esta diferencia arquitectónica elimina la necesidad de utilizar comandos **SCPI** (*Standard Commands for Programmable Instruments*), que son típicos en instrumentos conectados por GPIB, USB o Ethernet. En su lugar, los instrumentos modulares operan a un nivel mucho más cercano al hardware, donde el control se realiza directamente sobre **registros de hardware** expuestos por cada punto final PCIe (*PCIe endpoint*).

Dado que estándares como PXIe y AXIe están construidos sobre PCI Express, heredan su modelo de comunicación basado en memoria. Esto implica que cada operación de control, configuración o adquisición de datos no es más que una lectura o escritura sobre una dirección de memoria específica. Entender este modelo no solo es importante desde una perspectiva de desarrollo, sino también desde un punto de vista de rendimiento, depuración e incluso seguridad.

Para aprovechar completamente un instrumento PXIe o AXIe, es esencial comprender la cadena completa que existe entre el software de aplicación y el hardware físico. Esta cadena incluye controladores, capas del sistema operativo y mecanismos internos del bus PCIe.

Los registros de hardware no son accesibles directamente por las aplicaciones. En su lugar, se accede a ellos a través de módulos de software especializados llamados **controladores** (*drivers*), que abstraen la complejidad del hardware. Para estandarizar este acceso, la industria desarrolló las API de **VISA** (*Virtual Instrument Software Architecture*), que proporcionan funciones como `viIn32` y `viOut32` para leer y escribir registros.

Comprender cómo interactúan los controladores con los registros permite diseñar soluciones más eficientes, reducir la latencia de acceso y tener un control más preciso del comportamiento del instrumento. Este artículo describe cómo Windows, a través de su arquitectura interna, ejecuta estas operaciones sobre hardware PCIe utilizando las API VISA.


## Arquitectura de software en Windows: modo usuario y modo kernel

El sistema operativo Windows implementa un modelo de ejecución basado en dos niveles de privilegio claramente diferenciados: **modo usuario** (*User Mode*) y **modo kernel** (*Kernel Mode*).

El modo usuario es un entorno restringido donde se ejecutan las aplicaciones convencionales. En este nivel, el acceso directo al hardware está completamente prohibido, lo que garantiza estabilidad y aislamiento entre procesos. Cualquier intento de acceder a recursos críticos debe pasar por mecanismos controlados del sistema operativo.

El modo kernel, por otro lado, tiene acceso total al hardware y a la memoria del sistema. Aquí es donde residen los controladores de dispositivos, el planificador del sistema y componentes críticos como el administrador de memoria.

Como se muestra a continuación, una aplicación en modo usuario interactúa con el hardware de forma indirecta, invocando APIs del **subsistema de Windows**, que a su vez se comunican con el **administrador de E/S** (*I/O Manager*) y los controladores en modo kernel.

![user / kernel](src/assets/images/userkernel.png)

La comunicación entre estas capas se realiza mediante estructuras llamadas **IRP** (*I/O Request Packets*). Un IRP representa una solicitud de operación de entrada/salida y viaja a través de la pila de controladores hasta que es procesado. A diferencia de las interrupciones de hardware, los IRP son completamente gestionados por software.

En la parte más baja de esta pila se encuentra el **controlador de bus**, que interactúa directamente con la **HAL** (*Hardware Abstraction Layer*). La HAL abstrae las diferencias entre plataformas de hardware, permitiendo que el sistema operativo sea portable y consistente.

El acceso a registros de hardware es una operación privilegiada, restringida exclusivamente al modo kernel. Cada dispositivo PCIe cuenta con su propio controlador, y únicamente este tiene permisos para acceder a sus registros internos.

## Operaciones VISA

Dado que el acceso directo al hardware está restringido al modo kernel, la arquitectura VISA se construye como una pila híbrida que combina componentes en modo usuario y modo kernel.

En la capa superior se encuentra la aplicación del usuario, que puede ser software de pruebas personalizado, controladores **IVI** (*Interchangeable Virtual Instrument*) o interfaces gráficas como *Soft Front Panels*. Estas aplicaciones utilizan la API VISA sin preocuparse por los detalles de bajo nivel.

Las funciones `viIn32` y `viOut32` representan el punto de entrada para realizar operaciones sobre registros. Estas funciones requieren dos parámetros fundamentales:

* El **espacio de memoria**
* El **offset** dentro de ese espacio

Existen dos tipos principales de espacios accesibles:

* **Espacio de configuración PCI** (`VI_PXI_CFG_SPACE`)
* **Espacios BAR** (`VI_PXI_BAR0_SPACE` a `VI_PXI_BAR5_SPACE`)

Los **BAR** (*Base Address Registers*) son particularmente importantes, ya que definen las regiones de memoria que el sistema operativo asigna a cada dispositivo durante la fase de inicialización. Estos registros permiten traducir direcciones lógicas a direcciones físicas dentro del espacio MMIO.

El complemento VISA PXI actúa como intermediario, proporcionando APIs de más alto nivel como `PpiOpen`, `PpiBlockRead` o `PpiBlockWrite`. Internamente, estas funciones utilizan mecanismos del sistema como `CreateFile` y `DeviceIoControl`.

Cuando se invoca `DeviceIoControl`, el sistema genera un IRP de tipo `IRP_MJ_DEVICE_CONTROL`. Este IRP es procesado por el controlador del dispositivo mediante códigos **IOCTL**, que definen operaciones específicas.

Por ejemplo:

* `viIn32` → `IOCTL_AG_TRANSFER_FROM_DEVICE`
* `viOut32` → `IOCTL_AG_TRANSFER_TO_DEVICE`

Dependiendo del tipo de operación, el controlador puede:

* Delegar la solicitud al controlador de bus PCI (para espacio de configuración)
* Acceder directamente a memoria mapeada (para registros BAR)


## Mecanismo de acceso a registros

En arquitecturas PCIe, los dispositivos no se acceden mediante puertos de E/S tradicionales, sino a través de **MMIO** (*Memory-Mapped I/O*). Esto significa que el hardware se expone como regiones de memoria dentro del espacio de direcciones del sistema.

La **dirección base MMIO** es el punto de inicio de esta región. A partir de ella, es posible calcular la dirección de cualquier registro dentro de cualquier dispositivo PCIe.

El direccionamiento en PCIe sigue una estructura jerárquica basada en:

* Bus
* Dispositivo
* Función

El primer dispositivo del sistema se encuentra en Bus 0, Dispositivo 0, Función 0.
La fórmula para calcular la dirección de un registro es la siguiente:

```
Dirección del registro = MMIO_BASE + { bus[28:20], dispositivo[19:15], función[14:12] } + offset del registro
```

Este esquema permite direccionar de forma eficiente miles de dispositivos sin colisiones, utilizando un espacio de direcciones bien definido.

El **offset** representa la posición dentro del espacio de configuración extendido del dispositivo.

![PCIe](src/assets/images/pcie.png)

Cada dispositivo dispone de 4 KB de espacio de configuración (`0x000` a `0xFFF`), donde se encuentran tanto registros estándar como registros específicos del fabricante.

## Dirección base MMIO

La dirección base MMIO es el elemento más crítico de todo el modelo de acceso. Sin ella, no es posible resolver ninguna dirección de registro.

```md
-----------------------------------------
BUSCAR TABLAS ACPI EN MEMORIA DEL BIOS
-----------------------------------------
                |
                |
-----------------------------------------
ENCONTRAR RSDP EN:
- BIOS ROM
- EBDA
-----------------------------------------
                |
                |
-----------------------------------------
OBTENER:
- VERSION ACPI
- TABLA RSDT / XSDT
-----------------------------------------
                |
                |
-------------------------
¿ACPI >= 2.0?
-------------------------
        |                     |
       SI                     NO
        |                     |
---------------------   ---------------------
USAR XSDT PARA        USAR RSDT PARA
TABLAS SECUNDARIAS    TABLAS SECUNDARIAS
---------------------   ---------------------
        |                     |
        -----------+----------
                    |
                    |
-----------------------------------------
LOCALIZAR TABLA MCFG
-----------------------------------------
                |
                |
-----------------------------------------
MMIO BASE ADDRESS:
OFFSET 44 EN MCFG
-----------------------------------------
                |
                |
-----------------------------------------
RESULTADO:
ACCESO A CONFIG SPACE PCIe
-----------------------------------------
```

El proceso para obtener esta dirección comienza en las estructuras ACPI del sistema. El punto de entrada es el **RSDP** (*Root System Description Pointer*), que se encuentra en regiones específicas de memoria del BIOS.

| Campo            | Tamaño (bytes) | Descripción                                                                 |
|------------------|----------------|-----------------------------------------------------------------------------|
| Signature        | 8              | Debe ser "RSD PTR " (nota el espacio al final)                              |
| Checksum         | 1              | Los primeros 20 bytes deben sumar 0 (interpretados como byte)               |
| OEMID            | 6              | Cadena proporcionada por el fabricante (OEM)                                |
| Revision         | 1              | Versión de la estructura                                                    |
| ptrRSDT          | 4              | Puntero de 32 bits a la tabla RSDT. Sin embargo, se prefiere la XSDT         |
| Length           | 4              | Longitud total de la tabla incluyendo el encabezado                         |
| ptrXSDT          | 8              | Puntero de 64 bits a la tabla XSDT (preferida). Ambas contienen lo mismo,   |
|                  |                | pero XSDT usa punteros de 64 bits                                           |
| ExtendedChecksum | 1              | Checksum extendido para toda la estructura (no solo los primeros 20 bytes)  |
| Reserved         | 3              | Reservado, valores indefinidos                                              |

El RSDP apunta a las tablas **RSDT** o **XSDT**, que contienen referencias a otras tablas ACPI.

Entre ellas destaca la tabla **MCFG**, que contiene la dirección base MMIO.

| Rango de dirección lineal | Rango de dirección en modo real | Tipo de memoria | Uso                                               |
|---------------------------|----------------------------------|------------------|---------------------------------------------------|
| 0x00000 - 0x003FF         | 0000:0000 - 0000:03FF            | RAM              | Tabla de vectores de interrupción (IVT)          |
| 0x00400 - 0x004FF         | 0040:0000 - 0040:00FF            | RAM              | Área de datos del BIOS (BDA)                     |
| 0x00500 - 0x09FBFF        | 0050:0000 - 0090:FBFF            | RAM              | Memoria convencional libre (< 1 MB)              |
| 0x09FC00 - 0x09FFFF       | 9000:FC00 - 9000:FFFF            | RAM              | EBDA (Extended BIOS Data Area)                   |
| 0x0A0000 - 0x0BFFFF       | A000:0000 - B000:FFFF            | Video RAM        | Framebuffers VGA                                 |
| 0x0C0000 - 0x0C7FFF       | C000:0000 - C000:7FFF            | ROM              | BIOS de video (~32 KB típico)                    |
| 0x0C8000 - 0x0EFFFF       | C800:0000 - E000:FFFF            | ROM              | Hardware mapeado y dispositivos varios           |
| 0x0F0000 - 0x0FFFFF       | F000:0000 - F000:FFFF            | ROM              | BIOS de la placa base (~64 KB típico)            |
| 0x100000 - 0xFEBFFFFF     | —                                | RAM              | Memoria extendida libre (≥ 1 MB)                 |
| 0xFEC00000 - 0xFFFFFFFF   | —                                | Varios           | BIOS, ACPI, NVRAM, recursos de chipset, etc.     |

El sistema recorre estas tablas buscando la firma `"MCFG"`.

| Offset | Tamaño (bytes) | Descripción                                                                 |
|--------|----------------|-----------------------------------------------------------------------------|
| 0      | 4              | Firma de la tabla ("MCFG")                                                  |
| 4      | 4              | Longitud de la tabla (en bytes)                                             |
| 8      | 1              | Revisión                                                                   |
| 9      | 1              | Checksum (la suma de todos los bytes & 0xFF debe ser 0)                     |
| 10     | 6              | OEM ID (igual significado que en otras tablas ACPI)                         |
| 16     | 8              | OEM Table ID (identificador del fabricante/modelo)                          |
| 24     | 4              | OEM Revision (igual que en otras tablas ACPI)                               |
| 28     | 4              | Creator ID (igual que en otras tablas ACPI)                                 |
| 32     | 4              | Creator Revision (igual que en otras tablas ACPI)                           |
| 36     | 8              | Reservado                                                                  |

---

## Estructuras de asignación de direcciones base (Configuration Space Base Address Allocation)

| Offset | Tamaño (bytes) | Descripción                                                                 |
|--------|----------------|-----------------------------------------------------------------------------|
| 0      | 8              | Dirección base del mecanismo de configuración mejorado (MMIO Base Address) |
| 8      | 2              | Número de grupo de segmento PCI                                             |
| 10     | 1              | Número de bus PCI inicial                                                   |
| 11     | 1              | Número de bus PCI final                                                     |
| 12     | 4              | Reservado                                                                  |

El controlador de bus PCI adquiere tablas BIOS y ACPI durante el tiempo de arranque de Windows y las almacena en caché en la memoria y en el registro. Luego, el controlador de bus PCI o cualquier API de subsistema en modo kernel en Windows utilizan esta información en cachés para obtener la dirección base MMIO y realizar operaciones de registro IO. Para la operación de E/S en los registros del espacio de configuración PCI, el controlador PCIbus leerá y escribirá en los registros utilizando la fórmula mostrada cuando recibe IRP del controlador del dispositivo funcional. PCI busdriver también es responsable de leer/escribir en registros de direcciones base BAR utilizando el mismo método.

Dentro de la MCFG, en el offset 44, se encuentra la dirección base MMIO de 64 bits. En la práctica, muchos sistemas utilizan solo los 32 bits inferiores.

Una vez obtenida, esta dirección permite acceder a todo el espacio de configuración PCIe del sistema.

Windows cachea esta información durante el arranque, permitiendo accesos rápidos posteriores. Tanto el controlador de bus PCI como otros componentes del kernel utilizan esta información para resolver direcciones y ejecutar operaciones de E/S.

## Conclusión

Los instrumentos modulares representan un cambio fundamental respecto a los instrumentos tradicionales: eliminan capas de abstracción como SCPI y operan directamente sobre el hardware mediante acceso a memoria.

Este modelo ofrece ventajas claras en términos de rendimiento, latencia y control, pero también requiere un entendimiento más profundo del sistema, incluyendo:

* Arquitectura del sistema operativo
* Modelo de drivers
* Mecanismos de direccionamiento PCIe
* Estructuras ACPI

En entornos avanzados como pruebas de alto rendimiento, ingeniería inversa o desarrollo de hardware este conocimiento no es opcional, sino esencial.

Todos los componentes del ecosistema PXIe/AXIe, desde controladores IVI hasta interfaces gráficas, dependen internamente de este mecanismo. Cada operación realizada sobre un instrumento es, en última instancia, una operación sobre memoria mapeada.

Entender esto permite no solo usar mejor los instrumentos, sino también manipularlos, optimizarlos e incluso analizarlos desde una perspectiva más cercana al hardware.

Espero que esta informacion sirva de ayuda o contextualizacion para lo que sea que estes trabajando.


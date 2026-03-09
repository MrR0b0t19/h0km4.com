---
author: Arnold Morales
pubDatetime: 2025-10-03T14:47:00Z
modDatetime: 2025-10-04T14:51:45.934Z
title: Beacon Object Files (BOF) - Introducción
slug: BOF-Introduccion
featured: true
draft: false
tags:
  - BOF
  - Cobalt Strike
  - Windows
  - Evasion
  - EDR
description:
    Introducción a BOF y teoria completa.
---

# Beacon Object Files (BOF) — Arquitectura Interna, Resolución de Símbolos y Desarrollo Avanzado

Tuve la fortuna de aprovechar estas tecnicas para evadir varias ejecuciones en pentests con una infraestructura robusta, esto lo realice tanto con beacon o COFFLoader, al final esto no es mostrar que son vulnerables si no entenderlo y mejorarlo para que ayudemos a los defensores a dar una mejor explicacion de como proteger y que buscar como las tablas IAT... ESPERO ESTO TE GUSTA Y EMPRENDAS UN VIAJE PROFUNDO.

## Introducción

Los **Beacon Object Files (BOF)** son módulos compilados como **objetos COFF (Common Object File Format)** que pueden ejecutarse directamente dentro de la memoria de **Beacon** sin necesidad de crear procesos adicionales ni cargar DLLs completas.

Este diseño tiene varias consecuencias técnicas importantes:

* No se requiere loader del sistema operativo.
* No se ejecuta como binario PE tradicional.
* El código se integra dentro del proceso del beacon.
* Se evita el uso de `LoadLibrary` o `CreateProcess`.

Desde el punto de vista arquitectónico, un BOF es esencialmente un **fragmento de código relocatable** que Beacon carga manualmente y ejecuta como si fuese una función interna.

# 1. Arquitectura interna de un BOF

Un BOF es un **archivo COFF relocatable object**. No es un ejecutable completo.

## Estructura básica del formato COFF

Un archivo COFF contiene varias estructuras fundamentales:

```
+----------------------+
| COFF File Header     |
+----------------------+
| Section Table        |
+----------------------+
| .text                |
| .data                |
| .rdata               |
| .bss                 |
+----------------------+
| Relocation Tables    |
+----------------------+
| Symbol Table         |
+----------------------+
| String Table         |
+----------------------+
```

Cada uno cumple una función crítica durante el proceso de carga manual.

# Secciones principales

## `.text`

Contiene el **código máquina ejecutable**.

Características:

* Instrucciones compiladas.
* Posiblemente relocatable.
* Referencias a funciones externas.

Ejemplo conceptual:

```
void go(char * args, int len)
{
    BeaconPrintf(CALLBACK_OUTPUT, "BOF executed");
}
```

Ese código terminará dentro de `.text`.

## `.data`

Datos globales inicializados.

Ejemplo:

```
int counter = 5;
char msg[] = "hello";
```

Estos valores están almacenados directamente en la sección.

## `.rdata`

Datos constantes.

Ejemplo típico:

* strings
* constantes

## `.bss`

Datos globales **no inicializados**.

El loader debe reservar memoria para ellos pero no contienen datos dentro del archivo.

# 2. Tabla de relocaciones

Los **relocations** indican qué offsets del código deben corregirse cuando el objeto se carga en memoria.

Esto es necesario porque:

* El objeto no conoce su dirección final.
* Las referencias a símbolos deben ajustarse.

Ejemplo conceptual:

```
mov rax, [BeaconPrintf]
```

El compilador no conoce la dirección final de `BeaconPrintf`, por lo que genera una entrada de relocation.

Una entrada típica contiene:

```
offset
symbol_index
relocation_type
```

Durante la carga:

```
final_address = base_address + relocation_offset
```

Luego se escribe la dirección correcta.

# 3. Symbol Table

La **symbol table** describe:

* funciones
* variables
* referencias externas

Cada símbolo incluye:

```
name
section
value
storage_class
type
```

Los símbolos externos son los más importantes en BOF.

Ejemplo:

```
BeaconPrintf
BeaconDataParse
BeaconDataExtract
```

Estos símbolos no están dentro del BOF. Deben resolverse en tiempo de ejecución.


# 4. Cómo Beacon carga un BOF

Beacon implementa un **loader COFF minimalista**.

Proceso simplificado:

```
1. Leer header COFF
2. Mapear secciones en memoria
3. Aplicar relocations
4. Resolver símbolos externos
5. Buscar función "go"
6. Ejecutarla
```

Este proceso ocurre completamente **en memoria**.

No interviene el loader del sistema operativo.

# 5. Resolución de símbolos en tiempo de ejecución

Los BOF utilizan un mecanismo llamado **Dynamic Function Resolution (DFR)**.

En lugar de importar funciones mediante la IAT, Beacon resuelve los símbolos dinámicamente.

### Tabla interna de funciones

Beacon mantiene un mapa interno:

```
BeaconPrintf
BeaconDataParse
BeaconDataExtract
BeaconOutput
BeaconUseToken
```

Cuando el loader encuentra un símbolo externo:

```
symbol: BeaconPrintf
```

Hace una búsqueda en esa tabla interna.

```
address = beacon_internal_lookup("BeaconPrintf")
```

Luego parchea la relocación.

## Ejemplo conceptual

Código:

```
BeaconPrintf(CALLBACK_OUTPUT, "test");
```

Durante compilación:

```
call BeaconPrintf
```

Durante carga:

```
call 0x7ff7xxxxxxx
```

La dirección real se inserta en memoria.

# 6. Dynamic Function Resolution (DFR)

DFR permite que los BOF utilicen **APIs del sistema** sin usar la tabla de importación.

En lugar de:

```
kernel32!CreateFileW
```

Se usa un wrapper interno.

Ejemplo conceptual:

```
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(...)
```

El prefijo:

```
KERNEL32$
```

indica que Beacon resolverá la función dinámicamente.

Proceso interno:

```
1. localizar módulo (kernel32.dll)
2. recorrer export table
3. encontrar función
4. devolver dirección
```

Esto evita tener una **IAT tradicional**.

# 7. Desarrollo de BOF con C/C++

Los BOF suelen compilarse con **MinGW** o **Clang**.

Requisitos:

* arquitectura correcta (x64)
* sin CRT
* sin dependencias externas
* código position-independent

Ejemplo mínimo:

```c
#include "beacon.h"

void go(char * args, int len)
{
    BeaconPrintf(CALLBACK_OUTPUT, "Hello from BOF");
}
```

Compilación conceptual:

```
x86_64-w64-mingw32-gcc -c bof.c -o bof.o
```

El resultado:

```
bof.o
```

Ese archivo es el BOF.

# 8. Restricciones técnicas

BOF no es un entorno completo de ejecución.

Limitaciones:

* no CRT
* no heap complejo
* stack limitado
* no threads largos
* ejecución rápida recomendada

Por eso muchos BOF son:

```
acciones rápidas
enumeración
inyección simple
lectura de memoria
```

# 9. Debugging de BOF

Debuggear BOF es complejo porque:

* no es un ejecutable
* no tiene entrypoint clásico

Una estrategia común es usar **COFFLoader**.

## COFFLoader

COFFLoader es un programa que simula el loader de Beacon.

Permite:

```
cargar .o
resolver símbolos
ejecutar go()
```

Esto permite usar:

```
gdb
lldb
windbg
```

## Debugging con Wine

Muchos investigadores utilizan:

```
Wine + GDB
```

Flujo típico:

```
compilar BOF
ejecutar COFFLoader bajo Wine
adjuntar debugger
```

Esto permite:

* inspeccionar relocations
* verificar symbol resolution
* analizar crashes

# 10. Por qué los BOF reducen superficie de detección

Es importante entender esto **desde una perspectiva técnica**, no como una garantía de evasión.

Varias características influyen.


## 1. No existe un archivo ejecutable

No se escribe:

```
.exe
.dll
```

en disco.

La ejecución ocurre desde memoria.

## 2. No hay loader estándar

Los mecanismos típicos de detección observan:

```
CreateProcess
LoadLibrary
NtCreateUserProcess
```

BOF evita estas rutas.

## 3. No hay tabla de importación

Muchos motores analizan:

```
IAT
imports
API usage
```

Los BOF usan resolución dinámica.

## 4. Código pequeño y efímero

Los BOF suelen ejecutarse rápidamente y terminar.

Esto reduce:

```
persistencia en memoria
huella temporal
```

# 11. Cómo los EDR modernos analizan BOF

Los sistemas modernos no dependen únicamente de firmas.

Utilizan múltiples enfoques:

### telemetría de memoria

* páginas RX anómalas
* regiones privadas ejecutables

### heurística

* patrones de syscall
* acceso a estructuras sensibles

### behavioral analytics

* enumeración de procesos
* manipulación de tokens
* acceso a LSASS

### memory scanning

Algunos EDR inspeccionan memoria buscando:

```
patterns de shellcode
code caves
reflective loaders
```

Por lo tanto, el uso de BOF **no implica invisibilidad**.

# 12. Consideraciones operativas

Desde una perspectiva de investigación y defensa, los BOF muestran varias tendencias en tooling moderno:

* modularidad
* ejecución en memoria
* loaders personalizados
* reducción de artefactos

Esto refleja una evolución general en herramientas ofensivas hacia **componentes pequeños y efímeros**.

Para los defensores, esto implica que la detección debe moverse desde:

```
firma -> comportamiento
archivo -> memoria
```

# Conclusión

Los **Beacon Object Files** representan un enfoque minimalista para ejecutar código dentro de un agente ya comprometido.

Su funcionamiento depende de:

* formato COFF relocatable
* loader manual en memoria
* resolución dinámica de funciones
* ausencia de estructuras típicas de PE

Estas características los hacen extremadamente flexibles para operaciones modulares.

Al mismo tiempo, su análisis es un campo interesante para ingeniería inversa y desarrollo de defensas modernas.

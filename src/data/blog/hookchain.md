---
author: Diego Hernandez / Arnold Morales
pubDatetime: 2026-04-05T14:47:00Z
modDatetime: 2026-04-05T14:51:45.934Z
title: Técnica avanzada de evasión HOOKCHAIN
slug: Hookchain
featured: true
draft: false
tags:
  - red team
  - evasion
  - havoc
  - windows
  - EDR
description:
    Uso de hookchain para ejecucion de beacon.
---
# Introduccion

Dentro de pruebas de penetracion siempre tendemos a enfrentarnos a EDRs/AVs.. etc. Pero como en todos los casos buscamos nuestro propio armamento o tecnicas que talvez creemos que aun no estan mapeadas de la manera correcta, en esta ocacion contamos un poco la perspectiva que nos enfrentamos a EDRs con tecnologia Machine Learning configurada con la opcion "FULL" tuvimos la fortuna de utilizar esta tecnica combinandola con una carga cifrada para evadir esta opcion y al descargarse o compartirse por ".zip" estas no las revisaba el agente, ahora introduzcamosno un poco en toda la parte tecnica pero sobre todo en como se exploto.

HookChain es una tecnica avanzada para la evasion de soluciones de EDR, se usa principalmente por grupos delictivos (APTs) pero tambien se puede utilizar de manera etica en ejercicios de Red Team. Su principal fundamento es interceptar los hooks que los EDR instalan en el kernel del sistema operativo, ¿Que es un hook? Los hooks es una manera que tienen los EDR de monitorear las llamadas a las funciones de la API de Windows, principalmente de `ntdll.dll`, de esta manera pueden interceptar y analizar los comportamientos sospechosos en tiempo real.  La tecnica de HookChain busca evadir esta capa de monitoreo.

## ¿Como se detectan los Hooks?

La primera fase de la tecnica consiste en identificar si una funcion del sistema ha sido hookeada por el EDR, esto podemos saberlo facilmente ya que las syscalls de windows tienen un prologo estandarizado muy conocido, el cual es:

```
4C 8B D1 → mov r10, rcx 
B8 XX XX → mov eax, <SSN>
```

Por ejemplo, asi se ve una syscall NO hookeada en ensamblador:

![ensamblador](src/assets/images/ensamblador.png)

Si los primeros bytes de una función como `NtAllocateVirtualMemory` han sido modificados (por ejemplo, reemplazados por un `JMP` a un módulo del EDR), se considera que la función está hookeada.

#### System Service Numbers (SSN) Dinámicos

En lugar de utilizar las funciones hookeadas de `ntdll.dll`, HookChain recupera dinámicamente el SSN (System Service Number) de cada syscall. Este número es el identificador que usa el kernel de Windows para despachar la llamada al sistema correcta.

Al conocer el SSN, es posible invocar directamente al kernel sin pasar por el código del EDR, una técnica conocida como **Direct Syscall**.

![direct](src/assets/images/direct.png)

#### Manipulacion de la tabla IAT

La técnica también involucra manipulación de la Import Address Table (IAT), que es la tabla donde el ejecutable guarda las direcciones de las funciones importadas de DLLs externas. Al sobrescribir una entrada en la IAT, se puede redirigir llamadas a funciones legítimas hacia handlers controlados por el atacante, evitando que el EDR intercepte la ejecución.

![ejecucion](src/assets/images/ejecucion.png)

#### Cifrando nuestro payload con XOR

HookChain suele combinar la evasión de hooks con cifrado del payload, en este caso vamos a utilizar XOR para evitar detección estática basada en firmas. El shellcode va cifrado en memoria y solo se descifra antes de su ejecución.

Podemos utilizar un string (en este caso "CHANGEMYKEY") como llave para nuestro encriptado de XOR y una shellcode generada con msfvenom, pero tambien podemos utilizar otros frameworks de C2, como veremos mas adelante.

![code](src/assets/images/code.png)

### Usando Havoc con la tecnica de HookChain

Todo este articulo ha sido basado en [esta]([johto89/HookChain: HookChain is an evasion framework for bypassing Endpoint Detection and Response (EDR) solutions by leveraging techniques like IAT Hooking, dynamic SSN resolution, and indirect system calls](https://github.com/johto89/HookChain))prueba de concepto, la cual podemos utilizar para nuestro loader e insertar una shellcode de Havoc, con el cual podremos infectar un host con un agente de EDR instalado. El codigo es el siguiente:

```
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
<SNIP>
```

Generamos nuestro demon de Havoc en formato de shellcode:

![havoc](src/assets/images/havocs.png)


Encriptamos nuestra shellcode utilizando cyberchef, puedes llegar a cambiar la clave de XOR:

![cyberchef](src/assets/images/cyberchef.png)


Ejecutamos nuestro loader, el cual va a inyectar nuestra shellcode en la memoria:

![carga](src/assets/images/carga.png)

Y recibimos nuestra conexion en nuestro C2:

![c2conect](src/assets/images/c2conect.png)


### Conclusion

HookChain es una de las tecnicas mas "nuevas" y utilizadas en la actualidad y hemos comprobado su eficiencia incluso en entornos corporativos, con la configuracion del demon correcta y una infraestructura con buena OPSEC, puedes realizar operaciones de red team sin ningun problema, aunque tambien presenta un desafio para el equipo de blue team, ya que es una tecnica dificil de detectar.


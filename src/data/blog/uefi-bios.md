---
author: Arnold Morales
pubDatetime: 2026-05-02T14:47:00Z
modDatetime: 2026-05-02T14:51:45.934Z
title: Jugando con UEFI - BOOTKIT
slug: uefi-bios
featured: true
draft: false
tags:
  - UEFI
  - BIOS
  - BootKit
  - Evasion
  - EDR
description:
    Tecnica de evasion derivada de un bootkit.
---

# Motivación

A lo largo de mi carrera he sufrido muchas acciones repetitivas, pero siempre debes tomar algo negativo como impulso, ya sea el fracaso o retos que parecen imposibles.
Sobre todo para el lector que es considerado Jr o que está iniciando, debes disfrutar el proceso de investigación en cualquier punto de tu carrera. Sin importar el resultado final, las personas que no son técnicas no entenderán lo emocionante y gratificante que puede ser esto.

Volviendo al punto inicial, antes de realizar cualquier pentest o prueba, lo que quiero transmitir es que para poder hackear algo debes saber cómo funciona como requisito mínimo. Pero si se complica, además de entenderlo, tienes que aprender a hacerlo tú mismo; así sabrás cómo y por qué sucede cada situación.
La mayor parte de las vulnerabilidades provienen de errores humanos, es decir, de un developer que hizo algo mal y se dejó pasar porque su superior tampoco sabe programación o, en el mejor de los casos, “ya no había tiempo”. Esto aplica a todo: web, mobile, APIs, aplicaciones de escritorio, EDR, sistemas embebidos, etc.
Y claro, si funciona, ya no le muevas.

Este punto es una reflexión propia sobre mi postura. Hablaré de temas que me gustan y en los que tuve que dejar a un lado mi ego y reconocer mis errores, iniciando desde cero. Así que, parcialmente, comenzamos: explicaré una vulnerabilidad a nivel UEFI, pero no solo se trata de ejecutar código; a lo largo de este proceso contaré varios problemas que tuve, para que veas que nada sale a la primera, pero hay señales claras de que vas avanzando.

# Introducción

Comenzaremos con la BIOS/UEFI. Este chip, de poco espacio, almacena información de configuración, se encarga de comunicarse con el hardware y realizar varias acciones desde el NVRAM. Entre otras cosas, controla el encendido del sistema.
Esto es algo que puedes encontrar fácilmente buscando en internet, pero lo que no te dicen es su importancia, sobre todo en entornos OT y en ciberseguridad.

Existe la idea equivocada de “casar” IDs de placas base, pero ahí te han mentido. En realidad, lo que se hace es trabajar con los IDs de la BIOS (GUIDs).
Dentro de esta investigación, me di cuenta de que estas memorias pueden copiarse y pegarse en distintos chips. Las validaciones de muchos productos se basan directamente en tablas dentro de la BIOS; si cambias el hardware pero mantienes el mismo firmware, no ocurre ningún error.

Como leíste, esto parece fácil. Después de cometer múltiples errores, deja de serlo. Pero, citando de quien aprendí, en mi proceso por entender cómo funciona todo esto, encontré un curso de desarrollo de BIOS en YouTube de [Queso Fuego](https://www.youtube.com/watch?v=t3iwBQg_Gik&list=PLT7NbkyNWaqZYHNLtOZ1MNxOt8myP5K0p).
Ahí aprendí a desarrollarlo y confirmé que muchas de estas ideas son posibles. Solo toma en cuenta que hoy en día hay muchos mecanismos adicionales de protección.

# ¿Pero bien, qué buscamos?

La BIOS normalmente almacena configuraciones, algunas más importantes que otras. Pero, una vez que ya tienes conocimientos de programación en UEFI, surge la pregunta: ¿por qué no hacer un bootkit?

No entraré en mucho detalle sobre cómo lo hice, pero te dejo recursos para que puedas investigarlo por tu cuenta:

* Libro *Rootkits and Bootkits*
* Curso de desarrollo de UEFI en C de  [Queso Fuego](https://www.youtube.com/watch?v=t3iwBQg_Gik&list=PLT7NbkyNWaqZYHNLtOZ1MNxOt8myP5K0p)
* Documentación oficial de [UEFI](https://uefi.org/uefi)
* Repositorio basado en una charla de DEFCON: [Abyss](https://github.com/TheMalwareGuardian/Abyss)

Con esto tienes una base sólida. Al final, si te enfrentas a un EDR que protege desde UEFI o detecta cambios en memoria, lo más efectivo es operar en el nivel con mayor privilegio. En este caso, UEFI.
Si puedes escribir una BIOS modificada, muchas veces no existen validaciones completas del firmware, sino de tablas como los GUIDs, lo que hace que sea complejo de desarrollar, pero relativamente efectivo para evadir controles.

# Evadir

Una vez que tienes control, la pregunta clave es: ¿cómo ejecutar código sin ser detectado?

Aquí entran conceptos como headers, tables, memory map y Boot Services. La idea es dejar que la BIOS cargue normalmente los componentes del sistema (por ejemplo, `winload.efi`) y, a partir de ahí, localizar en memoria el kernel (`ntoskrnl.exe`) para modificarlo.

Un fragmento representativo sería:

```c
QWORD hModuleNTOSKRNL = FindNtoskrnl();
QWORD hPsCreateSystemThread = PEGetProcAddressH(hModuleNTOSKRNL, H_PsCreateSystemThread);
```

A partir de ese punto, se puede inyectar código directamente en el kernel. Este proceso ocurre en una etapa muy temprana del arranque, antes de que los mecanismos tradicionales de seguridad estén activos.
Se ocultan funciones mediante hashes, se analiza la estructura interna del kernel, se buscan espacios libres en memoria y se insertan payloads. Finalmente, se modifica una función legítima para redirigir la ejecución hacia el código inyectado.

¿Por qué no te detectan?
Porque un EDR o antivirus tradicional vive en el kernel. Si el kernel aún no arranca completamente, tienes control total sin interferencia. Incluso con protecciones adicionales en UEFI, si puedes modificar la BIOS sin alertas, ya estás en una posición privilegiada.
Además, no solo puedes ejecutar código, sino manipular completamente el proceso de arranque e incluso engañar al usuario si lo haces correctamente.

# Errores

Si es tu primer bootkit o tu primer parcheo de kernel desde UEFI, estos serán tus principales problemas:

**Sistema operativo:**

* Pantalla azul: generalmente indica que la dirección de memoria es incorrecta, pero la ejecución sí se intentó
* Congelamiento del sistema: el sistema entra en modo de protección
* Nada ocurre: esto es peor; puede significar que tu código nunca se ejecutó. Lo recomendable es validar creando un usuario o escribiendo un archivo en `C:\`

**BIOS:**

* No hay imagen: siempre haz un respaldo antes
* Arranque congelado: error en el memory map o en la búsqueda de memoria
* Error de encendido: problema relacionado con el RTC

Son errores muy comunes y sobre los que no hay mucha documentación.

# Conclusión

Estando en esta posición, básicamente estás interactuando directamente con el kernel. Todo lo que hagas a partir de aquí tiene una alta probabilidad de evadir mecanismos tradicionales de seguridad.
Si el sistema falla por un error de memoria, puedes intentar ejecutar dentro de procesos confiables para mantener estabilidad.
Además, entender este nivel no solo te permite atacar, sino también comprender cómo defender correctamente sistemas desde su base más crítica.

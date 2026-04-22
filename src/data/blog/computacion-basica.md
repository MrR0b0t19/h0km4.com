---
author: Gothic-X/hokma/Fr34k
pubDatetime: 2007-08-10T14:47:00Z
modDatetime: 2025-08-10T14:51:45.934Z
title: Hacking Hardware o Ciencias de la computacion
slug: computacion-basica
featured: true
draft: false
tags:
  - Computacion
  - Overclocking
  - Hardware
  - Hacking
  - UEFI
description:
    Issue que te lleva ala cuspide.
---

# Introducción

Como todo en la vida tiene un comienzo y cimientos fuertes, podemos decir que en la tecnología también sucedió así. Comenzamos por una tarjeta madre con circuitos que serían nuestros cimientos; una base sólida sobre la cual se construiría todo lo que hoy conocemos como computación moderna.

A lo largo de la historia hubo varios errores, sobre todo de integridad, que se fueron solventando con el tiempo. Pero los genios que hicieron posible todo esto merecen todo el crédito del mundo, ya que sin ellos no seríamos nada de lo que somos hoy.

En la época de mejora de CPUs surgió una técnica conocida como *Overclocking*, que consiste en aumentar la frecuencia de reloj de componentes electrónicos (como la CPU, la GPU o la RAM) para que funcionen a una velocidad superior a la establecida de fábrica por el fabricante. El objetivo principal es mejorar el rendimiento del equipo, permitiendo que realice más operaciones por segundo, lo que se traduce en mayor potencia de cálculo y tasas de fotogramas más altas en videojuegos o tareas exigentes.

Claro que hubo muchos errores durante este proceso, lo cual llevó a las grandes empresas a añadir en su placa alguna manera de resetear las configuraciones. A esto se le llamó un *"issue"*, para que las personas curiosas tuvieran un "Ctrl+Z" a sus errores y no tuviesen que reemplazar toda la placa. Pero esto, en realidad, no es una vulnerabilidad ni un fraude; es simplemente un *issue* porque por sí solo no representa un riesgo de seguridad: solo regresa de fábrica las configuraciones en la BIOS, aunque en algunos casos, si tienes contraseña configurada, puede restaurarla también. Todo depende del CMOS y de cómo esté configurado.

Antes de comenzar quiero comentarles algo: el mundo tiende a ser muy pequeño. Lo digo por los participantes en este post; aunque uno no está directamente escribiendo o participando, es un gusto poder trabajar a la par de él.

# Teoría

Vamos con lo bueno. Primero hablemos del **RTCRST** (*Real Time Clock Reset*): es un simple jumper físico en la placa base que permite resetear el BIOS/CMOS y limpiar la NVRAM.

Ahora bien, ¿qué es el **CMOS** (*Complementary Metal-Oxide-Semiconductor*)? Es un pequeño chip de memoria en la placa base que almacena la configuración del BIOS, como la fecha, hora, orden de arranque y ajustes de hardware. Funciona de manera continua gracias a una pequeña batería, generalmente una pila tipo **CR2032**, lo que le permite mantener esos datos incluso cuando el equipo está completamente apagado y desconectado de la corriente.

Y para no dejar cabos sueltos: la **BIOS** (*Basic Input/Output System*, Sistema Básico de Entrada y Salida) es un firmware integrado directamente en la placa base. Es el primer programa que se ejecuta al encender el equipo, antes incluso de que cargue el sistema operativo. Su trabajo es inicializar y verificar el hardware presente — CPU, RAM, almacenamiento, periféricos — y luego transferir el control al gestor de arranque del sistema operativo.

Por último, la **NVRAM** (*Non-Volatile Random Access Memory*, Memoria de Acceso Aleatorio No Volátil) es un tipo de memoria que retiene los datos incluso cuando la computadora está apagada, a diferencia de la RAM convencional, que es volátil y pierde todo al cortarse la energía. En una computadora, la NVRAM se utiliza principalmente para almacenar configuraciones críticas del sistema como:

- Fecha y hora del sistema
- Orden de arranque
- Configuraciones de hardware
- Parámetros del sistema y contraseñas

Esta memoria puede estar respaldada por una batería (como la CR2032) o utilizar tecnologías intrínsecamente no volátiles como **EEPROM** o **memoria flash**, lo que le permite mantener los ajustes sin necesidad de energía constante. Esta distinción es importante: una NVRAM basada en flash no necesita batería para retener datos, mientras que el CMOS clásico sí depende de ella.

## La relación entre BIOS, CMOS y NVRAM

Aquí hay algo interesante que vale la pena entender bien, porque mucha gente confunde estos tres términos.

El **CMOS** es el *contenedor físico* donde se guardan los datos. La **NVRAM** es el *concepto funcional* de esa memoria: no volátil, persistente. Y la **BIOS** o su sucesora moderna, la **UEFI**, es el *programa* que lee y escribe en esa memoria para funcionar.

En los sistemas modernos, la BIOS tradicional ha sido prácticamente reemplazada por **UEFI** (*Unified Extensible Firmware Interface*), que es esencialmente una BIOS evolucionada. UEFI tiene su propio entorno de ejecución, soporte para discos de más de 2TB, interfaz gráfica, arranque seguro (*Secure Boot*) y, lo más relevante para nuestra historia: almacena su configuración en una memoria flash integrada en la placa base, ya no dependiente de la batería CR2032 para los datos críticos, aunque la batería sigue siendo necesaria para el reloj en tiempo real (RTC).

Una vez centrados los conceptos, podemos avanzar. Al no ser una vulnerabilidad en sí misma, ¿esto no afecta en nada? Bueno, la postura que se desarrolla aquí resalta algo interesante: ¿qué hay en la BIOS/UEFI que nos interese?

Recordemos que la BIOS configura parámetros de hardware y le dice a la computadora cómo arrancar y levantar todo. Pero aquí caen muchas cosas: los **buses de memoria**, conectores como **M.2**, puertos USB, e incluso funciones de virtualización pueden bloquearse o habilitarse desde la BIOS. Si por defecto vienen habilitados y tú tienes que entrar para deshabilitarlos manualmente, al resetear a configuraciones de fábrica volverán a estar activos. Eso es lo que nos interesa.

## Root Complex

El **Root Complex (RC)** es el componente central de la arquitectura **PCI Express**. Actúa como puente entre el procesador (CPU), la memoria principal (RAM) y el resto del sistema PCIe, que incluye tarjetas gráficas, discos SSD NVMe, tarjetas de red, controladores USB, etc. Se puede visualizar como la *"ciudad principal"* o la *"sede central"* desde donde se originan todas las comunicaciones del sistema.

Sus funciones principales son:

- **Origen de las transacciones:** Genera solicitudes de lectura y escritura en nombre de la CPU para acceder a dispositivos PCIe (llamados *Endpoints*).
- **Gestión del sistema PCIe:** Descubre, configura y asigna recursos (como espacio de memoria y direcciones de E/S) a todos los dispositivos conectados durante el arranque, en un proceso llamado *enumeración*.
- **Control de recursos:** Gestiona la asignación de ancho de banda, interrupciones y estados de energía del sistema PCIe.
- **Mapeo de memoria:** Mantiene estructuras de configuración que definen qué partes de la memoria del sistema son accesibles para cada dispositivo PCIe.

El Root Complex suele estar integrado en el propio CPU (como ocurre en los procesadores Intel y AMD modernos) o en el chipset (PCH) de la placa base, dependiendo de la arquitectura.

Un detalle importante: el Root Complex no es solo un componente de enrutamiento pasivo. Durante el proceso de *enumeración PCIe* en el arranque, el firmware (UEFI/BIOS) interactúa directamente con el RC para asignar recursos a cada dispositivo. Esto significa que el RC tiene un rol activo en cómo se configura el sistema antes de que el sistema operativo tome el control.

## Buses de Lectura de Memoria

El término *"buses de lectura de memoria"* no se refiere a un tipo de bus físico específico, sino al tráfico de datos que viaja por los buses del sistema cuando se ejecuta una operación de lectura de memoria.

En el contexto del Root Complex y PCIe, el flujo de lectura típico es el siguiente:

1. La CPU necesita datos que están en la memoria RAM.
2. El Root Complex genera una solicitud de lectura de memoria (*Memory Read Request*).
3. Esta solicitud viaja desde el Root Complex, a través de los buses internos del CPU y el bus de memoria (DDR4/DDR5), hasta el módulo de RAM correspondiente.
4. Los datos solicitados se leen de la RAM.
5. Los datos viajan de regreso por los mismos buses hasta el Root Complex, y de ahí a la CPU.

Para operaciones donde un dispositivo PCIe (como una tarjeta gráfica o un controlador de red) necesita leer datos de la memoria del sistema, el proceso involucra:

1. El dispositivo PCIe solicita acceso directo a la memoria RAM, sin pasar por la CPU.
2. El Root Complex valida la solicitud contra las tablas de traducción de direcciones.
3. Los datos se transfieren directamente entre la RAM y el dispositivo PCIe.
4. La CPU recibe una interrupción cuando la transferencia termina.

Aquí entra en juego otro concepto relevante: el **IOMMU** (*Input-Output Memory Management Unit*), que en Intel se llama *VT-d* y en AMD se llama *AMD-Vi*. El IOMMU actúa como una MMU para dispositivos de E/S, controlando qué regiones de memoria puede acceder cada dispositivo PCIe. Si está habilitado y configurado correctamente, un dispositivo comprometido no puede leer libremente toda la RAM. Si está deshabilitado... la historia cambia.

Y aquí es donde la BIOS vuelve a ser relevante. El IOMMU se habilita o deshabilita desde la configuración. ¿Recuerdas el RTCRST? Empiezan a conectarse los puntos.

# Ataque

Como tal, el paso número uno requeriría tener conocimientos sólidos sobre el Root Complex y entender a profundidad la arquitectura de una computadora moderna.

Tranquilo...

Al controlar el hardware a este nivel, esto te permite realizar tareas de naturaleza muy particular. Pero, ¿qué podemos hacer en concreto?

Sencillo, querido lector: una inyección para un **Bootkit** es una técnica avanzada que modifica el firmware del sistema durante el proceso de arranque, antes de que cargue el sistema operativo. Al aprovechar la interfaz, estos bootkits logran un nivel extremo de persistencia y evasión, ya que operan en una capa más baja que el sistema operativo y los antivirus tradicionales.

# Conclusión

Sé que no es lo esperado en mi blog, pero si comprendieras la magnitud del impacto que puede tener todo esto, entenderías por qué no se completó el post.

Yo especialmente quisiera escribir todo lo que aquí se explica, pero por eso les he facilitado los conceptos clave. Y no uses IA: eso arruinaría tu aprendizaje. Agarra esa computadora viejita que seguramente has pensado en tirar y juega con el Root Complex. Tal vez después de eso podrías escribir tu primer bootkit en C.

---
author: Adonai Diaz / Arnold Morales
pubDatetime: 2025-06-19T21:30:00Z
modDatetime: 2025-06-19T21:37:45.934Z
title: Introducción a DMA por hardware
slug: DMA-Introduction
featured: true
draft: false
tags:
  - Hardware
  - DMA
  - FPGA
  - Kernel
  - PCILeech 
description:
  Acceso directo a memoria por medio de harware, cómo una FPGA puede ofrecernos una ventana a un nuevo ataque de kernel.
---

## Introducción a Dynamic-Memory-Access (DMA) 

En muchas ocasiones cómo pentesters nos aferramos a la idea de buscar multiples técnicas de ataque de manera "virtual", buscando software especializado o creando scripts que nos ayuden a identificar una vulnerabilidad para acceder a un programa o dispositivo en el que nos enfoquemos, pasamos tanto tiempo enfrente de nuestra pantalla, lanzando comandos a lo bastardo hasta ver que podemos encontrar que a veces ignoramos que existen soluciones alternativas y no simplemente de manera virtual, sino de una manera en que podemos tocar, armar y desarmar (esto suele ser menos buscado por pentester, entonces tambien hay menos documentacion).

Para nosotros el hardware también es una parte en la que podemos encontrar vulnerabilidades y solo basta con ver cómo trabaja el dispositivo al que realizaremos pentest, identificando cada uno de los protocolos con los que se relaciona de manera física.
con lenguajes como System Verilog, Verilog y VHDL, y la PCILeech contiene un chip de este tipo.
En esta ocasión nos interesa compartir sobre un tema que nos tomo mucho de investigación. DMA (Dynamic Memory Access) es un método que nos permite acceder a memoria directamente sin la necesidad de credenciales de nuestro sistema operativo Linux o Windows, a través de los puertos PCI/PCIe y usando su protocolo.

Esto nace a partir de que en pruebas de penetración a videojuegos llegamos a identificar el dispositivo PCILeech, una herramienta de hardware que nos permite realizar el DMA.

Este dispositivo tiene diversos repositorios donde entrega software, recursos e instrucciones para saber cómo utilizarlo. Aunque podríamos dar las instrucciones de cómo podemos usarlo, deseamos enfocar este artículo más a tema de hardware para entender cómo es que este dispositivo funciona a nivel físico.

### Conozcamos la PCILeech

El dispositivo PCILeech puede conectarse a una interfaz PCI/PCIe (cómo lo dice su mismo nombre) y este interactúa con el mismo protocolo ¿Pero que lo conforma para poder trabajar a ese nivel? Hablar del protocolo PCIe no es un tema sencillo, es muy extendido y conocerlo por completo es conocer una rama entera, pero daremos una explicación resumida.

La PCILeech tiene un chip importante que le permite tener comunicación con el protocolo, este es un FPGA que son chips usados para el diseño a nivel silicio mediante la programación de hardware con lenguajes cómo VHDL, Verilog y SystemVerilog. Los CPUs o ASIC (cualquier chip encapsulado con pines) son productos ya fabricados con una funcionalidad ya especificada, pero las FPGA aún después de ser producidas pueden reprogramarse por el usuario dando total manipulación para cualquier uso.

Aunque no todas las FPGAs puedan trabajar con PCI Express por el motivo de las velocidades de transmisión del protocolo, PCILeech integra una XILINX-7 que ya tiene una Capa Física para implementar el estandar de PCIe y soportar el protocolo, haciendolo eficiente para el trabajo de DMA.

Aparte de tener la FPGA, tiene dos componentes para interfaz JTAG, uno para la programación de la FPGA (aunque no todos los modelos lo tienen) y otra para la comunicación entre FPGA y la computadora. Estos son chips FTDI que son componentes especializados en un funcionamiento de USB-Bridge que nos permiten interactuar con la FPGA integrada. Ya el resto del funcionamiento depende de la programación en SystemVerilog que se le haya dado a la FPGA, cada modelo de PCILeech encontramos su programación en el repositorio de [pcileech-fpga](https://github.com/ufrisk/pcileech-fpga).

### Funcionamiento

El protocolo PCIe nos permite realizar lectura directamente a la memoria RAM, no por CPU sino por el mismo bus de PCIe

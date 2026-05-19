---
author: Arnold Morales
pubDatetime: 2026-04-05T14:47:00Z
modDatetime: 2026-04-05T14:51:45.934Z
title: Bypassing secure boot
slug: bypass-SecureBoot
featured: true
draft: false
tags:
  - UEFI
  - BOOT
  - bypass
  - Evasion
description:
    PROXIMAMENTE.
---

# INICIO

Con la actual era de la IA y los sistemas acelerados por hardware, han surgido plataformas diseñadas para ejecutar múltiples redes neuronales en paralelo, permitiendo cargas de trabajo como clasificación de imágenes, detección de objetos, segmentación semántica y procesamiento de voz en tiempo real. Estas arquitecturas se han convertido en la base ideal para el desarrollo rápido de productos basados en inteligencia artificial, reduciendo significativamente los tiempos de prototipado y despliegue hacia producción.

Esta tecnología constituye la base operativa de múltiples industrias y proyectos modernos, incluyendo:

* robótica
* drones
* sistemas autónomos
* vehículos autónomos
* entornos OT
* equipos médicos
* infraestructura inteligente
* y prácticamente cualquier plataforma comercializada como “inteligente”, excepto la del CEO que cree haber revolucionado el sector únicamente integrando APIs de OpenAI

Secure Boot, tal como suele representarse en diagramas de arquitectura y documentación de ingeniería, transmite exactamente la misma sensación de confianza silenciosa y control absoluto.

Con sus claves cuidadosamente aprovisionadas, sus mecanismos de validación criptográfica y su aparente cadena de confianza perfectamente estructurada, el sistema convence a todos los involucrados de que la plataforma ha desarrollado algún tipo de criterio propio Sin embargo, lo único que realmente ha desarrollado es una secuencia rígida de decisiones automatizadas que aparentan ser inteligentes únicamente mientras nadie cuestione qué ocurre cuando una de esas decisiones se ejecuta bajo un supuesto incorrecto NVIDIA reconoció dos vulnerabilidades, publicó parches, actualizó su documentación y otorgó crédito a th3_h1tchh1ker. La descripción pública de estas vulnerabilidades es técnicamente correcta, limpia y cuidadosamente controlada, describiendo problemas durante etapas tempranas del arranque relacionados con inyección de argumentos y posible divulgación de información bajo condiciones de acceso físico.

Todo eso es correcto.
Al mismo tiempo, la explicación omite casi por completo el mecanismo real que convierte estos hallazgos en algo relevante.

Desde la perspectiva de Secure Boot, la plataforma está diseñada para implementar una cadena de confianza clásica basada en hardware y, sobre el papel, lo hace correctamente.
La ejecución comienza en BootROM inmutable, que ancla la confianza utilizando secretos fusionados y verifica la primera etapa mutable. Luego, el control fluye a través de las primeras etapas de arranque específicas de NVIDIA y hacia el entorno de firmware UEFI, donde se aplican políticas, configuraciones y lógica de verificación adicionales. El gestor de arranque verifica y carga el kernel de Linux, y el kernel transforma la ejecución en initrd, que es responsable de la inicialización temprana del espacio de usuario, incluido el descubrimiento del dispositivo, el descifrado y el montaje del sistema de archivos raíz. Sólo después de que se completa esta secuencia, el sistema gira hacia el sistema de archivos raíz final y controla manualmente el entorno operativo estándar.

# El verdadero comienzo

Nadamas como este subtitulo. lo que mostrare aqui es la carga directa o modificacion por nivel grub antes del sistema operativo, esto solo aplica a nivel linux.

Comencemos...

*Secure Boot* (o Arranque Seguro) es una función de seguridad integrada en el firmware UEFI de los ordenadores modernos que garantiza que el sistema arranque únicamente con software legítimo y firmado digitalmente.  Su objetivo principal es prevenir la ejecución de malware, rootkits o bootkits durante la fase inicial del encendido, antes de que se cargue el sistema operativo. 

Para ello, el firmware verifica la firma digital de cada componente de la cadena de arranque (como el cargador del sistema operativo y los controladores).  Si el software no está certificado por una entidad de confianza o ha sido manipulado, el equipo bloquea el inicio para mantener la integridad del sistema

*GRUB* (GNU GRand Unified Bootloader) es un cargador de arranque de software libre desarrollado por el Proyecto GNU que gestiona el proceso de inicio de los sistemas operativos, actuando como puente entre el firmware (BIOS o UEFI) y el núcleo del sistema.  Es el gestor de arranque predeterminado en la mayoría de las distribuciones de Linux (como Ubuntu, Debian, Fedora y Arch Linux) y permite seleccionar qué sistema operativo iniciar en equipos con configuración de doble arranque (por ejemplo, Windows y Linux). 

Esto es lo unico que necesitas saber.. claro ser linuxero de corazon...

# Progreso



20 de mayo lo publico


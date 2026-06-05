---
author: Arnold Morales
pubDatetime: 2026-06-03T14:47:00Z
modDatetime: 2026-06-04T14:51:45.934Z
title: Explotación del MCPJam inspector
slug: MCPJam-inspector
featured: true
draft: false
tags:
  - web
  - RCE
  - blind
  - MCPJam
description:
    CVE-2026-23744 - explotacion del MCPJam
---
# CVE-2026-23744 - explotacion del MCPJam

Esta investigacion fue derivada por la curiosidad en un puerto. A diferencia de aplicaciones web tradicionales, el servicio parecía estar relacionado con MCP (Model Context Protocol), una tecnología utilizada para conectar modelos de inteligencia artificial con herramientas externas y procesos del sistema operativo.

Inicialmente el servicio no mostraba una interfaz especialmente interesante. Sin embargo, al inspeccionar las peticiones utilizadas internamente por la aplicación apareció un endpoint que llamó inmediatamente mi atención:

POST /api/mcp/connect

A simple vista parecía un endpoint diseñado para registrar o conectar herramientas MCP. No obstante, tras analizar el formato de las solicitudes, quedó claro que el servidor estaba permitiendo algo mucho más delicado: recibir instrucciones sobre qué proceso debía ejecutarse.

# problema

MCPJam Inspector está diseñado para lanzar herramientas externas bajo demanda. La idea es sencilla: cuando un modelo de IA necesita interactuar con una herramienta, el Inspector inicia un proceso y establece comunicación con él.

El problema aparece cuando la aplicación permite que el cliente controle directamente los parámetros utilizados para crear dicho proceso.

Durante las pruebas observé que el servidor aceptaba estructuras JSON similares a la siguiente:

{
  "serverConfig": {
    "command": "bash",
    "args": ["-c", "comando"],
    "env": {}
  }
}

Desde una perspectiva defensiva esto representa una señal de alarma inmediata.

El servidor no estaba limitando qué binarios podían ejecutarse, tampoco validaba argumentos ni requería autenticación previa. En otras palabras, cualquier usuario con acceso al endpoint podía influir directamente sobre procesos ejecutados por el sistema operativo.

# Análisis y explotación

La primera hipótesis fue sencilla: si el backend utilizaba los valores recibidos para generar procesos, entonces debería ser posible ejecutar comandos arbitrarios.

Las pruebas iniciales parecían indicar lo contrario.

Al enviar comandos simples, el servidor respondía con errores HTTP 500, sugiriendo que algo había fallado durante la ejecución.

Sin embargo, tras analizar el comportamiento del servicio, la situación era diferente.

MCPJam esperaba que los procesos iniciados permanecieran activos y participaran en una sesión MCP válida. Cuando un comando terminaba inmediatamente, la aplicación interpretaba que la conexión había fallado y cerraba la sesión.

Esto generaba un escenario clásico de Blind RCE:

El comando se ejecuta.
El proceso finaliza.
La salida nunca llega al cliente.
El servidor devuelve un error.

La ejecución existe, pero el atacante no puede observar directamente el resultado.

# Construyendo el exploit 

Para validar completamente la vulnerabilidad desarrollé una prueba de concepto en Bash orientada a automatizar la explotación.

La lógica del exploit es extremadamente simple:

Construir una configuración MCP manipulada.
Sustituir la herramienta legítima por Bash.
Ejecutar una reverse shell.
Forzar una conexión saliente hacia el equipo atacante.

En lugar de depender de la respuesta HTTP, la confirmación de ejecución se obtiene mediante una conexión interactiva recibida en el listener.

El flujo final es:

Attacker
    │
POST /api/mcp/connect
    │
MCPJam Inspector
    │
bash -c "<payload>"
    │
Reverse Shell
    │
Attacker

Una vez establecida la conexión, el atacante obtiene ejecución remota bajo el contexto de la aplicación vulnerable.

# vulnerabilidad?

La raíz del problema no es Bash, curl o la reverse shell utilizada.

La verdadera causa es un fallo de diseño.

El sistema asume que los datos enviados por el cliente representan configuraciones legítimas para herramientas MCP. Esa confianza permite que información completamente controlada por el usuario termine convirtiéndose en instrucciones de ejecución dentro del sistema operativo.

Cuando una aplicación cruza ese límite sin implementar controles adecuados, la diferencia entre "configuración" y "código" desaparece.

Y precisamente ahí nace CVE-2026-23744.


# opensource 
He automatizado esto y se encuentra en este [repositorio(https://github.com/MrR0b0t19/CVE-2026-23744-PoC/)]


espero te diviertas y tengas mas retos que cruzar.

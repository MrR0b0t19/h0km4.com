---
author: Arnold Morales
pubDatetime: 2020-11-11T14:47:00Z
modDatetime: 2020-11-11T14:51:45.934Z
title: Hacking a Equipos médicos
slug: H-equipos-medicos
featured: true
draft: false
tags:
  - Equipo medicos
  - RIS/PACS
  - RCE
description:
  Comprometiendo equipos medicos y a hospitales.
---

# Mi historia

Esta vulnerabilidad, después de 6 años de haberla encontrado, la estoy publicando por diversos motivos. Como cualquier hacker curioso de lo desconocido, me introduje en un proyecto sobre reparación de estos equipos, pero también existía la oportunidad de navegar hacia lo desconocido en un proyecto de innovacion. En este recorrido fui un técnico muy bueno tanto en software como en hardware de estos sistemas, pero siempre que aprendemos algo a un nivel mayor que especializado debemos innovar. La clave era sencilla: poder compartir esta información almacenada.

¿Por qué? Si un equipo se rompía, el respaldo demoraba mucho en llegar y los pacientes podían perder demasiado tiempo en su espera, y cualquier radiografía podría afectar su estado de salud, por decir lo menos... Tuve la fortuna o la mala suerte de jugármela solo... esto fue cuando tenía 17/19 años. Ya sé, completamente joven, pero nunca es tarde ni temprano para hacer algo. Así que, como en cualquier cosa en mi vida, decidí iniciar esto de la mejor manera: **INVESTIGANDO**... de esto se trata.


# El camino

Cabe resaltar que nadie conocía realmente cómo funcionaba todo. El hospital tenía un preproyecto, pero las personas que lo realizaron ya no se encontraban ahí, así que fue un proyecto con muchos problemas y fallos. Entonces opté por ver todo el panorama completo y comenzar desde cero.


# Teoría¿?

Lo principal es conocer los equipos médicos y qué datos envían. Existen múltiples protocolos de transmisión, pero el que abordaré aquí será **DICOM**, de sus siglas en inglés *Digital Imaging and Communication in Medicine*. Tal vez no lo conozcas, pero es un estándar de transmisión de imágenes médicas y datos entre hardware de propósito médico.

Un archivo DICOM contiene la imagen (Pixel Data) y una gran cantidad de metadatos estructurados llamados **Data Elements**, donde cada elemento tiene un Tag, Value Representation (VR), longitud y valor, permitiendo almacenar información del paciente, del estudio y del dispositivo. Los datos se organizan jerárquicamente en **Patient → Study → Series → Instance**, identificados mediante UID únicos.

El archivo puede codificarse con distintas **Transfer Syntax**, que definen endianness y compresión (por ejemplo JPEG o JPEG2000). En red, DICOM utiliza el protocolo **DIMSE sobre TCP/IP**, donde los sistemas llamados **Application Entities** negocian una **Association** antes de intercambiar operaciones como **C-STORE** (envío de imágenes), **C-FIND** (búsqueda) o **C-MOVE** (transferencia).

Dentro del archivo existen miles de tags posibles, incluyendo extensiones privadas de fabricantes, lo que hace que el formato sea extremadamente flexible. Esta combinación de contenedor de datos clínicos, protocolo de red y extensibilidad convierte a DICOM en la base de la infraestructura **PACS/RIS** hospitalaria, pero también en un sistema complejo cuya correcta validación e interpretación es crítica para la seguridad y confiabilidad de los sistemas médicos.

Independientemente del uso, siempre se utiliza el mismo formato, incluyendo el uso de ficheros y de red. DICOM se diferencia de otros formatos de datos en que agrupa la información dentro de un conjunto de datos. Es decir, una radiografía de **tórax** contiene el ID del paciente junto con ella, de manera que la imagen no puede separarse por error de su información.

Los ficheros DICOM consisten en una cabecera con campos estandarizados y de forma libre, y un cuerpo con datos de imagen. Un objeto DICOM simple puede contener solamente una imagen, pero esta imagen puede tener múltiples **fotogramas (frames)**, permitiendo el almacenamiento de bloques de cine o cualquier otro dato con varios fotogramas. Los datos de imagen pueden estar comprimidos usando una gran variedad de estándares.

# Hardware

Cualquier equipo médico actual cuenta con componentes conocidos para su generador de energía encargado del disparo del rayo X, pero también existen tarjetas de transmisión de datos que llegan a equipos directamente de arquitecturas como **x86/x64** o, en algunas ocasiones, **SPARC**. Soy del año 2002, así que nunca me había tocado escuchar de ellas hasta ese momento, así que tuve una pequeña clase de historia bastante hermosa en Google y de ingeniería bella... pero continuemos...

En su mayoría tenían **tres conexiones importantes**:

* **Fibra óptica:** utilizada para enviar las imágenes tomadas del detector.
* **Tarjeta de red:** utilizada para comunicación entre módulos del equipo.
* **Otra tarjeta de red:** utilizada para conexión a la red y envío de logs, datos, etc.

Lo más importante era la interfaz que podía conectarse a una red, pero como cualquier proyecto esto no es sencillo. Estos equipos fueron creados prácticamente para ser complicados; debíamos modificar las interfaces de Linux directamente, pero si agregábamos mal los datos tanto de aplicación como de hosts era romperlo por completo. Tuve la fortuna de romperlos… pero aprendí a hacerlo bien jajajaja xD.

Una vez configurado, el reto ya no era ese, sino revisar todas las conexiones existentes y poder compartir los datos. En Google no hay mucho sobre esto, pero investigué de varias maneras y algunos ingenieros me explicaron **“cómo se supone que funciona”** (tuve que hacer reversing a la aplicación xD). La terminología utilizada para esto es **RIS/PACS**.

* **RIS (Radiology Information System)**
* **PACS (Picture Archiving and Communication System)**

Son los dos sistemas centrales que gestionan el flujo de trabajo y almacenamiento de imágenes médicas dentro de un hospital. El **RIS** se encarga principalmente de la gestión administrativa y clínica de radiología, incluyendo la programación de estudios, registro de pacientes, generación de órdenes médicas, reportes radiológicos y seguimiento del historial clínico.

Por otro lado, el **PACS** está diseñado para almacenar, indexar y distribuir imágenes médicas en formato DICOM provenientes de equipos como CT, MRI o rayos X, permitiendo que médicos y radiólogos accedan a los estudios desde estaciones de diagnóstico.

Ambos sistemas se integran mediante estándares como **DICOM y HL7**, donde el RIS gestiona la información del paciente y el flujo de trabajo, mientras que el PACS maneja el almacenamiento y la visualización de las imágenes. En una arquitectura hospitalaria típica, los equipos de imagen envían los estudios al PACS, este los almacena y los asocia con la información clínica proveniente del RIS, permitiendo que los especialistas consulten las imágenes y generen diagnósticos dentro de un entorno digital integrado.

En resumen, uno sirve para **almacenar las imágenes en un servidor (PACS)** y el otro para **gestionar la información del paciente y las citas médicas (RIS)**.


# ¿Por qué los hackeaste?

En realidad **“fue sin querer queriendo”**... dentro de esta investigación el **RIS/PACS** fue un punto crucial, porque no solo representaba innovación sino también la necesidad de protegerlo.

Un estudio de rayos X (radiografía) es realizado por un equipo médico que lo almacena localmente, pero tiene la opción de exportarlo a un servidor...

Este servidor solicitaba únicamente estos datos: **AE TITLE, IP y PUERTO**. Así es, solo eso. Durante mi análisis de tráfico me encontré con que había un protocolo llamado **DICOM**, con la información de la imagen y los frames expuestos (sí, es una vulnerabilidad, pero ese no es el punto).

Lo primero que pensé desde el lado de la innovación fue: *esto será sencillo, envío la imagen con los datos correctos y listo*. Pero mi lado de seguridad dijo: **esto es vulnerable desde cualquier ángulo**.

Continué avanzando y programé algunas demos tanto de servidor como de envío (en mi repositorio dejo todo completo)
[demos](https://github.com/MrR0b0t19/radiografihack)


# Compromiso

El script **enviar.py**, como vemos, solo añade los datos mencionados, envía la imagen y listo... el servidor la recibe. No hay validación, ni TLS, ni nada.

Obviamente, si no hay validación de recepción de datos, tampoco hay validación de integridad o de las imágenes. Entonces pensé en mis técnicas de shell dentro de SVG o JPG, pero aplicadas a DICOM.

Antes de llegar a este punto hay muchas maneras de hacerlo, pero como esto es público no me introduciré en esa sección. Antes de meter una inyección debes saber **dónde se ejecuta y quién lo ejecuta**...

Como mencioné, había un proyecto inicial donde la idea era que el médico pudiera ver las imágenes en su **workstation**. En mi caso había una web hecha en **React** y no sé por qué tenía **Python** (viva el vibe coding).

Cuando me percaté de esto necesitaba una ejecución o activación en Linux, claro: un `.elf`. O en Windows lo más fácil sería inyectar directamente shellcode. Pero aquí era distinto.

Durante la investigación encontré una función curiosa relacionada con **movimientos en 3D**. La mejor manera de ver algo similar es aquí:
[OHIF](https://viewer.ohif.org/) Este proyecto no es el mencionado en esta publicacion, pero durante mi investigación fue el que más me ayudó a entender muchas cosas. Agradezco infinitamente la investigación de esta organización; el impacto que tuvieron en mí fue excepcional. Logré muchas cosas y, sobre todo, proteger datos médicos como lo marca **HIPAA**.

Volviendo al punto, del otro lado tenía ejecución de movimientos con Python, lo que me permitió ejecutar código de cierta manera. Cuando se activaba… ejecutaba el código y listo.

# ¿De verdad fue todo?

Algo así… por razones privadas no puedo mostrar todo el código, pero en mi repo dejo un ejemplo primordial:
[REPO](https://github.com/MrR0b0t19/radiografihack)

Lo más importante es entender todo en general. En cualquier pentest debemos saber **cómo funciona algo para saber cómo protegerlo y cómo atacarlo**.

Cuando me introduje en quién recibía estos datos, mi punto de partida fue buscar quién podía ejecutarlos o verlos. Teniendo esta información sabía que mi objetivo era la **WORKSTATION**. Al ser Windows sabía cuál era el sistema operativo, pero quien ejecutaba el procesamiento era Python. Así que, con lectura de archivos, podía extraer información.

Solo quedaba escapar al sistema operativo original. Lo más sencillo fue descargar un binario (**Beacon / netcat**) y establecer la ejecución. Ese fue el primer punto de apoyo que desencadenó en compromiso de **Active Directory** y, sobre todo, acceso a datos médicos.

# ¿Hay más?

Durante toda la investigación pasé por muchas experiencias que quizá más adelante dedicaré a otro post. En un **mastógrafo** logré realizar escalación de privilegios por servicios desactualizados; en un **TAC** fue directamente por Windows con escalación mediante **DLL injection y duplicación de tokens**; en **electrocardiógrafos** fue dumpeo de firmware y modificación para obtener ejecución de código… etc.

Pero eso no es lo más importante.

Más allá de las vulnerabilidades mencionadas, quiero que tú, lector, si te encuentras en un momento difícil o frente a un reto que parece imposible, recuerdes que muchas cosas interesantes se han descubierto precisamente cuando alguien decidió cuestionar lo que parecía imposible.

Los datos médicos son extremadamente delicados, porque más allá de afectar infraestructura tecnológica… **afectan vidas**.

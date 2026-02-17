---
author: Arnold Morales
pubDatetime: 2026-02-15T21:30:00Z
modDatetime: 2026-02-15T21:37:45.934Z
title: Ataques de deserialización
slug: Deserializacion-avanzada
featured: true
draft: false
tags:
  - Json
  - Deserializacion
  - web
  - XML 
  - .NET
description:
  Deserialización avanzada, lo que tienes que saber.
---

## Ataques de deserialización

Antes de comenzar, debo resaltar que para comprender mejor este tema es recomendable contar con conocimientos sobre aplicaciones web, .NET y, tal vez, saber decompilar ensamblados. Nada que con mayor investigación no puedas resolver.

## Qué es?

La serialización es el proceso de convertir un objeto en memoria en una secuencia de bytes. Estos datos luego pueden almacenarse o transmitirse a través de una red. Posteriormente, pueden reconstruirse mediante otro programa o incluso en un entorno de máquina diferente.  

Por el contrario, la deserialización es el proceso inverso, en el cual los datos serializados se reconstruyen nuevamente en el objeto original.

Sin embargo, cuando una aplicación deserializa datos controlados por el usuario, existe el riesgo de que se produzcan vulnerabilidades de deserialización. Estas pueden explotarse para lograr objetivos como: remote code execution, object injection, arbitrary file read y denial of service.

Existen tres principales [tecnologías de serialización en .NET](https://learn.microsoft.com/en-us/dotnet/standard/serialization/):

- [Serialización JSON](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview)
- [Serialización XML y SOAP](https://learn.microsoft.com/en-us/dotnet/standard/serialization/xml-and-soap-serialization)
- [Serialización binaria](https://learn.microsoft.com/en-us/previous-versions/dotnet/fundamentals/serialization/binary/binary-serialization)

- **Serialización JSON:** serializa objetos .NET hacia y desde la notación de objetos JavaScript (JSON).
- **Serialización XML y SOAP:** serializa únicamente las propiedades públicas y campos de los objetos, sin preservar completamente la fidelidad del tipo.
- **Serialización binaria:** registra el estado completo del objeto y preserva la fidelidad del tipo; al deserializar, se crea una copia exacta del objeto original.

Cabe resaltar que, para lograr este tipo de hallazgos, en la mayoría de los casos se requiere un enfoque de caja blanca o caja gris. En mi experiencia, también es posible encontrarlo en caja negra, especialmente si se logra la lectura de archivos que permita identificar manualmente estos patrones.

## Desde Adán y Eva? (Historia)

Como cualquier tipo de vulnerabilidad, hubo alguien que marcó el inicio de este vector de ataque:

- **2007:** Primera vulnerabilidad de deserialización registrada [CVE-2007-1701](https://nvd.nist.gov/vuln/detail/CVE-2007-1701), que permitía ejecutar código arbitrario a través de `PHP session_decode`.
- **2011:** Primera vulnerabilidad de deserialización basada en gadgets [CVE-2011-2894](https://nvd.nist.gov/vuln/detail/CVE-2011-2894), utilizando `Proxy` e `InvocationHandler` para lograr ejecución de código tras la deserialización.
- **2012:** Se publica el whitepaper [¿Eres mi tipo?](https://paper.bobylive.com/Meeting_Papers/BlackHat/USA-2012/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf), que discute la serialización en .NET y referencia [CVE-2012-0160](https://nvd.nist.gov/vuln/detail/CVE-2012-0160), vulnerabilidad que conduce a ejecución de código arbitrario en .NET Framework.
- **2015:** Se descubre el gadget Apache Commons Collections ([CVE-2015-4852](https://nvd.nist.gov/vuln/detail/CVE-2015-4852), [CVE-2015-7501](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)), permitiendo ejecución de código arbitrario contra múltiples aplicaciones Java.
- **2017:** Se publica el whitepaper [Friday the 13th JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf), abordando vulnerabilidades de deserialización en .NET. También se introduce [YSoSerial.NET](https://github.com/pwntester/ysoserial.net), herramienta para generar payloads de deserialización usando distintos gadgets.

## Identificar o cazar?

Como mencioné al inicio, normalmente se identifica mediante análisis estático con los permisos adecuados. En mi experiencia encontré cinco casos derivados de caja negra, donde fue posible la lectura y descarga de archivos.

Si este no es tu caso, o estás comenzando a incluir esto en tu arsenal técnico, puedes montar un laboratorio. No recomendaré ysoserial en esta etapa —no porque no sea útil— sino porque antes de automatizar debes entender cómo y por qué ocurren las cosas.

En el escenario que elijas, primero debes conocer herramientas clave para decompilar .NET:

- [JetBrains](https://www.jetbrains.com/decompiler/) – Solo Windows.
- [ILSpy](https://github.com/icsharpcode/ILSpy) – Multiplataforma.
- [dnSpy](https://github.com/dnSpy/dnSpy) – Solo Windows.
- [DeSearch](https://github.com/MrR0b0t19/Desearch) – Script creado por mí.

Existen múltiples serializadores en C#/.NET, incluyendo binarios, YAML y JSON. Afortunadamente —o desafortunadamente— muchos pueden ser vulnerables y explotarse de forma muy similar.

En Desearch explico qué patrones buscar. Si mi desarrollo probablemente es un desastre, te dejo el [readme](https://github.com/MrR0b0t19/Desearch/blob/main/README.md) de la publicación y además la siguiente tabla para referencia.

## Common Deserialization APIs and Implementations

| Serializer                         | Example Method                               | Reference       |
|------------------------------------|----------------------------------------------|-----------------|
| BinaryFormatter                    | `.Deserialize(...)`                          | [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter?view=net-7.0) |
| FastJSON                           | `JSON.ToObject(...)`                         | [GitHub](https://github.com/mgholam/fastJSON) |
| JavaScriptSerializer               | `.Deserialize(...)`                          | [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.web.script.serialization.javascriptserializer?view=netframework-4.8.1) |
| Json.NET                           | `JsonConvert.DeserializeObject(...)`         | [Newtonsoft](https://www.newtonsoft.com/json) |
| LosFormatter                       | `.Deserialize(...)`                          | [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter?view=netframework-4.8.1) |
| NetDataContractSerializer          | `.ReadObject(...)`                           | [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer?view=netframework-4.8.1) |
| ObjectStateFormatter               | `.Deserialize(...)`                          | [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.objectstateformatter?view=netframework-4.8.1) |
| SoapFormatter                      | `.Deserialize(...)`                          | [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter?view=netframework-4.8.1) |
| XmlSerializer                      | `.Deserialize(...)`                          | [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.xml.serialization.xmlserializer?view=net-7.0) |
| YamlDotNet                         | `.Deserialize<...>(...)`                     | [GitHub](https://github.com/aaubry/YamlDotNet) |

## Caja ?

Dependiendo del tipo de interacción, es posible que no siempre tengamos acceso al código fuente o a los binarios. Por lo tanto, para identificar funciones de deserialización, debemos buscar bytes o patrones específicos (magic bytes) en los datos enviados desde el cliente al servidor. Esto se encuentra automatizado en el script Desearch.

Para aplicaciones .NET Framework, podemos buscar:

- Cadenas Base64 que comiencen con `AAEAAAD/////`
- Cadenas que contengan `$type`
- Cadenas que contengan `__type`
- Cadenas que contengan `TypeObject`

## No siempre es vulnerable

Es importante tenerlo claro: no todos los usos de una biblioteca de deserialización son vulnerables.

Supongamos que queremos crear una clase llamada ExampleClass que implementa la función Deserialize utilizando JavaScriptSerializer para deserializar un objeto Prueba:

```csharp
public class Prueba
{
    public string Name { get; set; }
    public int Age { get; set; }
}
````

Primera implementación:

```csharp
using System.Web.Script.Serialization;

public class Ejemplo
{
    public JavaScriptSerializer Serializer { get; set; }

    public Prueba Deserialize<Prueba>(string str)
    {
        return this.Serializer.Deserialize<Prueba>(str);
    }
}
```

Otra representación:

```csharp
using System.Web.Script.Serialization;

public class Ejemplo
{
    public Prueba Deserialize<Prueba>(string str)
    {
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        return serializer.Deserialize<Prueba>(str);
    }
}
```

La diferencia es mínima, pero el primer ejemplo es potencialmente vulnerable y el segundo es seguro. En el primer caso, un atacante puede controlar la instanciación del objeto Serializer. Si se utiliza SimpleTypeResolver al crear la instancia, la deserialización puede volverse explotable.

```csharp
ExampleClass demo = new Ejemplo();
example.Serializer = new JavaScriptSerializer(new SimpleTypeResolver());
example.Deserialize("...[pwned]...");Explotación de vulnerabilidades de deserialización

```

Este ejemplo está basado en la regla de análisis de código [CA2322](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2322). El punto clave es que las librerías de deserialización no son inherentemente vulnerables; el contexto determina la exposición.

## ¿Qué es un gadget?

Para lograr objetivos como escrituras arbitrarias de archivos o ejecución remota de código mediante deserialización, es necesario utilizar un gadget o una cadena de gadgets (gadget chain).

Un gadget es un objeto configurado de forma específica para que ejecute acciones deseadas tras la deserialización.

* [Gadget Chains](https://i.blackhat.com/us-18/Thu-August-9/us-18-Haken-Automated-Discovery-of-Deserialization-Gadget-Chains-wp.pdf)
* [HackTricks](http://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html#references-3)
* [Project Zero](https://googleprojectzero.blogspot.com/2017/04/)
* [Eres mi tipo?](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)

Nota: Estos recursos fueron, para mí, de los más complejos de encontrar y comprender; por eso los referencio directamente.

## ObjectDataProvider

Según [Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.windows.data.objectdataprovider?view=windowsdesktop-7.0), ObjectDataProvider es una clase utilizada para “envolver y crear un objeto que pueda usarse como fuente de enlace”.

Claro, es Microsoft... pero para mi... es una clase del namespace `System.Windows.Data` (ensamblado `PresentationFramework.dll`) utilizada en WPF para crear y exponer objetos como fuentes de datos directamente desde XAML.

Permite:

* Instanciar objetos dinámicamente.
* Invocar métodos sobre esos objetos.
* Pasar parámetros al constructor o a métodos.
* Exponer el resultado como fuente de binding.

Internamente hereda de DataSourceProvider y ejecuta el siguiente flujo:

1. Se inicializa.
2. Ejecuta `BeginQuery()`.
3. Instancia el objeto mediante reflexión.
4. Invoca el método especificado.
5. Publica el resultado en `Data`.
6. Dispara `DataChanged`.

La palabra clave aquí es reflexión.

Propiedades clave:

* ObjectType
* ObjectInstance
* ConstructorParameters
* MethodName
* MethodParameters
* IsAsynchronous
* Data

Si encontramos `ObjectType`, `MethodName` y `MethodParameters`, podemos instanciar un objeto arbitrario y llamar a un método arbitrario con parámetros arbitrarios sin invocar explícitamente código imperativo.

Ejemplo:

```csharp
using System.Windows.Data;

namespace Ejemplo
{
    internal class Pruebas
    {
        static void Main(string[] args)
        {
            ObjectDataProvider hma = new ObjectDataProvider();
            hma.ObjectType = typeof(System.Diagnostics.Process);
            hma.MethodParameters.Add("C:\\Windows\\System32\\cmd.exe");
            hma.MethodParameters.Add("/c calc.exe");
            hma.MethodName = "Start";
        }
    }
}
```

Este patrón puede convertirse en un gadget que habilite ejecución remota de código.


## Json? pero el destripador.

Pero… ¿cómo lo encontramos?

Es sencillo. Más arriba hice mención de los recursos más importantes durante esta investigación; solo tienes que hacer un:

```bash
grep -r "JsonConvert.DeserializeObject"
````

O en Windows (buscarías de forma muy general la función):

```powershell
PS C:\> Select-String -Pattern "\.Deserialize\(" -Path "*/*" -Include "*.cs"
```

Y como siempre, antes de cortar un árbol, ten afilada tu hacha. Así que cualquier resultado obtenido debemos verificar si esta llamada de deserialización es vulnerable o no.

Con una búsqueda rápida encontraremos lo mencionado anteriormente en [Ataques JSON del viernes 13](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf), libro blanco de Álvaro Muñoz y Oleksandr Mirosh. El artículo analiza varios serializadores Java y .NET que utilizan JSON y explora sus vulnerabilidades y cuándo son susceptibles. En la página 5 podemos ver el siguiente párrafo sobre Json.Net.

Json.Net
Project Site: [http://www.newtonsoft.com/json](http://www.newtonsoft.com/json)
NuGet Downloads: 64,836,516

Json.Net is probably the most popular JSON library for .NET. In its default configuration, it will not include type discriminators on the serialized data which prevents this type of attacks. However, developers can configure it to do so by either passing a JsonSerializerSettings instance with TypeNameHandling property set to a non-None value:

```csharp
var deser = JsonConvert.DeserializeObject<Expected>(json, new
JsonSerializerSettings
{
 TypeNameHandling = TypeNameHandling.All
});
```

Or by annotating a property of a type to be serialized with the [JsonProperty] annotation:

```csharp
[JsonProperty(TypeNameHandling = TypeNameHandling.All)]
public object Body { get; set; }
```

Esto es de suma importancia en tu prueba porque, dependiendo del escenario, sabrás qué realizar o qué invalidar. En mi experiencia puedo comentar que, en la mayor parte de los casos, está configurado como "All". ¡Así que parece que esta llamada de deserialización debería ser vulnerable! ¿O no?...

Algo que debes saber es que, en la mayoría de los casos, los desarrolladores cometen el error de utilizar una DLL. Esto es muy interesante porque me saldré unos segundos del tema para explicar este hermoso beneficio...

## Evasión sin querer...

¿Por qué crees que cuando estás escribiendo tu prueba de exploit como el que mostré arriba, necesitarás ver alguna salida en JSON o no? Para ello necesitarás una sección de código como esta:

```csharp
JsonSerializerSettings config = new JsonSerializerSettings()
{
    TypeNameHandling = TypeNameHandling.All
};
string salida = JsonConvert.SerializeObject(hma, config);
Console.WriteLine(salida);
```

Tu entorno te dirá que está mal… porque Json.NET no es un paquete oficial de Microsoft y, por lo tanto, no está instalado de forma predeterminada.

¿Cómo solucionarlo? Igual que un developer, jajaja…

Tienes dos opciones. La primera es instalarlo con `Install-Package Newtonsoft.Json` desde PowerShell, claro ;).

La opción más fácil es descargar la DLL y, dentro de Visual Studio, navegar a Project > Add Reference…, seleccionar Browse y encontrar tu\ruta\dedescarga\Newtonsoft.Json.dll.

No diré mucho sobre la segunda opción, pero vuélvelo a leer… si logras ver esto… ¡PELIGROOOOO! (pero para el dev xD).

¿Y la evasión?

Claro. Lo importante: te expliqué cómo lo hace un dev. Ahora adivina: en una dependencia como Windows utilizan sus mejores AV/EDR… pero ¿qué crees? Existen procesos padres y componentes permitidos para su uso. Ese proceso padre puede generar procesos hijos y, si esto no se tiene mapeado correctamente… así es, podrás mandar a llamar la DLL y ejecutar código sin restricción desde un .exe (ACLARO QUE ES EVASIÓN… es decir, que ya estás dentro y buscas persistencia o estabilidad para no ser detectado).

## Volviendo a web

Muy bien, ya entendiste e hiciste tu primer exploit. ¡Felicidades! Ya pasaste lo más difícil. Ahora viene lo más cabrón: ¿dónde inyecto y qué inyecto? xD…

Depende de tu escenario. Es decir, tienes que revisar el código y encontrar la sección que utilice algo de lo que mencioné en el documento. Te daré dos ejemplos que me he encontrado 2-3 veces.




En unos dias continuo.... (**Explotación de vulnerabilidades de deserialización**)

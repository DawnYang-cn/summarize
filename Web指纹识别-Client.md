# Web客户端指纹识别
## 概述
一个设备的操作者一般都是一个人或特定的几个人。基于这种共识，Web客户端指纹识别技术的最主要功能就是追踪用户，我暂时把他的应用分为三个方面：
+ 电商或新闻业务可以通过客户端指纹识别技术来跟踪用户进行推送。目前铺天盖地，阴魂不散的广告早已把我们淹没，我也是中了好多次招了。
+ 银行业务或游戏客户端登陆时可以通过指纹识别技术来判断用户是否在常用设备登陆，如果不是则会要求提供额外的邮件验证码或手机验证码。个人感觉这是安全性（特别是多因素认证）向实用性的妥协，毕竟没人想每次登陆的时候都那么麻烦。
+ 在Web应用入侵防御方面，服务可以通过指纹识别黑客的设备或者僵尸网络设备进行针对性的封禁或者反向追溯请他喝茶。这样会补充单纯通过IP识别客户端的不足，及时黑客挂了代理也可以识别。

## 方法
### 基于Cookie的识别
严格的说Cookie可能不能算是客户端指纹识别的一种，但Cookie识别可能是客户端追踪的一个起始点。首先将信息放在客户端必然更加节省服务端资源，其次Cookie的识别十分的精确，因为Cookie值是确切地保存在设备中的。
对抗Cookie识别的方法也很简答，老司机可以自行删除设备上的Cookie，菜鸡可以使用浏览器无痕模式（老司机也是直接用无痕浏览器....应该没人闲的手动清）。
### EverCookie
我认为EverCookie就是一种乱拳打死老师傅的方式。他是GitHub上的一个开源项目，核心思想就是在各种能操作的位置想尽办法留下类似Cookie的识别信息，是要你用的不是IE6。他可以利用的点包括下面这些：
+ Standard HTTP Cookies
+ Flash Local Shared Objects
+ Silverlight Isolated Storage
+ CSS History Knocking
+ Storing cookies in HTTP ETags (Backend server required)
+ Storing cookies in Web cache (Backend server required)
+ HTTP Strict Transport Security (HSTS) Pinning (works in Incognito mode)
+ window.name caching
+ Internet Explorer userData storage
+ HTML5 Session Storage
+ HTML5 Local Storage
+ HTML5 Global Storage
+ HTML5 Database Storage via SQLite
+ HTML5 Canvas - Cookie values stored in RGB data of auto-generated, force-cached PNG images (Backend server required)
+ HTML5 IndexedDB
+ Java JNLP PersistenceService
+ Java exploit CVE-2013-0422 - Attempts to escape the applet sandbox and write cookie data directly to the user's hard drive.
### canvas
html5新增了很多交互性的功能，canvas就是其中一个，简单地说canvas是一套绘图的API。但是通过他怎么能进行指纹识别呢？这就是一个很骚的操作了。相同的HTML5Canvas元素绘制操作，在不同操作系统、不同浏览器上，产生的图片内容不完全相同。在图片格式上，不同浏览器使用了不同的图形处理引擎、不同的图片导出选项、不同的默认压缩级别等。在像素级别来看，操作系统各自使用了不同的设置和算法来进行抗锯齿和子像素渲染操作。即使相同的绘图操作，产生的图片数据的CRC检验也不相同。更详细的图片的矢量性质会与硬件的图形芯片产生联系，图片渲染的素的会与CPU的性能相关，所以canvas已经可以不单单局限于浏览器层面，甚至已经可以通过硬件来识别客户端指纹了。</br>
防御方面canvas的防御相对来说比较麻烦
+ 浏览器方面可以对图片进行统一的重新渲染，忽略客户端的影响。
+ 在生成的图片中加入随机的混淆值，这类似hash中的盐，但是另一方面主机的盐值不同可能更加帮助了指纹识别

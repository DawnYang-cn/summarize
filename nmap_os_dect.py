import nmap

ip_range = input("please input ip or ip range:")
print("Scanning "+ip_range+"...... Have a cup of coffee ?")
f=open('result.txt','a')

def getIplist(ip_range):
    ip_list=[]
    ip_range= ip_range.split('-')

    start_ip = ip_range[0].split('.')[3]
    end_ip = ip_range[1]

    ip_prefix = ip_range[0].split('.')[0]+'.'+ip_range[0].split('.')[1]+'.'+ip_range[0].split('.')[2]+'.'

    for i in range (int(start_ip),int(end_ip)+1):
        ip_list.append(ip_prefix+str(i))
    return ip_list

def scan(ip_list):
    nm = nmap.PortScanner()
    for ip in ip_list:
        print('\r scanning '+ip+' ',end='')
        nm.scan(hosts=ip,arguments='-sS -O')
        try:
            result = ip + " : " + nm[ip]['osmatch'][0]['osclass'][0]['osfamily']
            print(result)
            f.write(result+'\n')
        except:
            continue

ip_list = getIplist(ip_range)
scan(ip_list)
f.close()



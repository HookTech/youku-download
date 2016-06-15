#coding:utf-8
'''
Created on 2014/3/26

@author: philo
'''
import urllib2
import httplib
from HTMLParser import HTMLParser
import re
import threading
import pcap
import dpkt
from Queue import Queue
from time import sleep,ctime
from threading import Timer
import socket

q=Queue(32)

historylist=[]

address_dir={}

l=threading.Lock()

lk=None
tag=1

t=None

monitor_thread=None
arrange_thread=None
do_thread=None

class proxy(object):
    
    def __init__(self, params=None):
        '''
        Constructor
        '''
    '''
    classdocs
    '''
    def getURL_ByProxy(self,url,ProxyIP,ProxyPort):
        socket.setdefaulttimeout(20)
        proxy_handler=urllib2.ProxyHandler({'http': 'http://'+ProxyIP+':'+ProxyPort+'/'});
        #cj=cookielib.CookieJar()
        #proxy_auth_handler=urllib2.ProxyBasicAuthHandler()
        #opener=urllib2.build_opener(proxy_handler,proxy_auth_handler);
        opener=urllib2.build_opener(proxy_handler);
        opener.addheaders=[('User-Agent','Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0'),
                           ('Host','k.youku.com'),
                           ('Connection','keep-alive'),
                           ('Accept-Language','zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3'),
                           ('Accept-Encoding','gzip, deflate'),
                           ('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                           ]
        #urllib2.install_opener(opener)
        st=None
        response=None
        try:
            response=opener.open(url);
        except Exception,e:
            print str(e)
            #info=response.info()
        #for key,value in info.items():
            #print "%s = %s" %(key,value)
            #print "\n"
        #print response.geturl()
        if response is not None:
            st=str(response.read())
            m=re.search('400 Bad Request',st)
            if m is not None:
                st=None
            else:
                m=re.search('http://.*\.flv|http://.*\.mp4', st)
                if m is not None:
                    st=m.group()
        return st

class WorkThread(threading.Thread):
    def __init__(self,func,args,name=''):
        threading.Thread.__init__(self)
        self.name=name
        self.func=func
        self.args=args
    def getResult(self):
        return self.res
    def run(self):
        print 'starting',self.name,'at:',ctime()
        self.res=apply(self.func,self.args)
        print self.name,'finished at:',ctime()

class tabParser(HTMLParser):
    def __init__(self):
        self.content=''
        self.readingtab=0
        HTMLParser.__init__(self)
    
    def handle_starttag(self,tag,attrs):
        if tag=='tbody':
            self.readingtab=1
            
    def handle_data(self,data):
        if self.readingtab:
            self.content+=data
            
    def handle_endtag(self,tag):
        if tag=='tbody':
            self.readingtab=0
            
    def gettab(self):
        return self.content.strip()

class locker(object):
    def __init__(self):
        self.mux1=threading.Lock()
        self.mux2=threading.Lock()
    def acquire(self,tag):
        l.acquire()
        if tag==0:
            self.mux1.acquire()
        else:
            pass
        l.release()
    def release(self,tag):
        l.acquire()
        if tag==0:
            self.mux1.release()
        else:
            pass
        l.release()

def addressdir():
    return address_dir

def getURL(url):
    req=urllib2.Request(url)
    fd=urllib2.urlopen(req)
    '''
    info=fd.info()
    for key,value in info.items():
        print "%s = %s" %(key,value)
    print "\n"
    '''
    #print fd.geturl()
    return fd

def getURL_2(url,body):
    conn=httplib.HTTPConnection(url)
    conn.request("GET",body)
    result=conn.getresponse()
    print result.status
    
def thread_proxy_get_url(url,proxyip,proxyport):
    lk.acquire(tag)
    try:
        address_dir[url]=[]
        p=proxy()
        address=p.getURL_ByProxy(url,proxyip,proxyport)
        if address is not None:
            m=re.search('http', address)
            if m is not None:
                address_dir[url].append(address)
    except Exception,e:
        print str(e)
    lk.release(tag)
    
def get_proxy_dir():
    #num=randint(1,5)
    rawlines=''
    for i in range(5):
        url="http://www.kuaidaili.com/proxylist/"+str(i)+"/"
        try:
            result=getURL(url)
            html=result.read();
            tp=tabParser()
            tp.feed(html)
            rawlines+=tp.gettab()
        except Exception,e:
            print str(e)
            return None
    #print rawlines
    lines=re.split('\s+|\n+', rawlines)
    #print lines
    newlines=[]
    for eachline in lines:
        m=re.match('\d+\.\d+\.\d+\.\d+|\d{2,8}',eachline)
        if m is not None:
            newlines.append(m.group())
    #print newlines
    ipportdir={}
    for i in range(len(newlines)):
        r=re.match('\d+\.\d+\.\d+\.\d+',newlines[i])
        if r is not None:
            ipportdir[newlines[i]]=newlines[i+1]
    print 'proxy list('+str(len(ipportdir))+')',ipportdir
    return ipportdir

def queue_monitor():
    while 1:
        sleep(5)

def do_work():
    try:
        while 1:
            ret=readQ(q)
            queryurl='http://k.youku.com'+ret
            print queryurl
            ipportdir=get_proxy_dir()
            while ipportdir is None:
                sleep(1)
                ipportdir=get_proxy_dir()
            #print len(ipportdir)
            threads=[]
            for i in range(len(ipportdir)):
                workthread=threading.Thread(target=thread_proxy_get_url,args=(queryurl,ipportdir.keys()[i],ipportdir.values()[i]))
                threads.append(workthread)
            for th in threads:
                th.start()
            for th in threads:
                th.join()
            #print addressdir.keys()
            
    except Exception,e:
        print str(e)
        
def arrange_work():
    pc=pcap.pcap()
    #pc.setfilter("tcp port 80")
    for p_time,p_data in pc:
        #out_format="%s\t%s\t%s\t%s\t%s\tHTTP/%s"
        p = dpkt.ethernet.Ethernet(p_data) 
        ret = None  
        if p.data.__class__.__name__ == 'IP':
            ip_data = p.data
            #src_ip = '%d.%d.%d.%d' % tuple(map(ord,list(ip_data.src)))
            #dst_ip = '%d.%d.%d.%d' % tuple(map(ord,list(ip_data.dst)))
            if (ip_data.data.__class__.__name__=='TCP'):
                tcp_data = p.data.data
                if tcp_data!=None and tcp_data!="" and tcp_data.dport==80:
                    http_data=tcp_data.data
                    par_str=str(http_data)
                    m=re.search('/player/getFlvPath.*special=true.*|/player/getScreenShot/.*',par_str)
                    if m is not None:
                        ret=m.group()
                        r=re.search('(.*)( HTTP.*)', ret)
                        if r is not None:
                            ret=r.group(1)
                            writeQ(q,ret)

def readQ(queue):
    val=queue.get(1)
    return val
                                                        
def writeQ(queue,thing):
    for item in historylist:
        if 0==cmp(item,thing):
            return
    queue.put(thing,1)
    historylist.append(thing)
    
def kill_all():
    #do_thread.__stop()
    #arrange_thread.__stop()
    #monitor_thread.__stop()
    tag=0
    lk.acquire(tag)
    file_path='rawdata_'+ctime().replace(' ','-').replace(':','-')
    f=open(file_path,'w+')
    for key in address_dir.keys():
        f.write(key+':\n')
        for item in address_dir[key]:
            f.write(item)
            f.write('\n')
        f.write('\t\t\tSPLIT_TAG\n')
    f.close()
    address_dir.clear()
    lk.release(tag)
    deal_rawdata(file_path)
    timer_interval=480
    t=Timer(timer_interval,kill_all)
    t.start()
    tag=1
    #os._exit(0)
    
def deal_rawdata(path):
    #china_YD=[]
    #china_LT=[]
    #china_DX=[]
    #china_TT=[]
    iplist=[]
    addresslist=[]
    f=open(path,'r')
    for eachline in f:
        m=re.search('(http://)(\d+\.\d+\.\d+\.\d+)(/)', eachline)
        if m is not None:
            ip=m.group(2)
            iplist.append(ip)
            addresslist.append(eachline)
        print eachline
        t=re.search('SPLIT_TAG',eachline)
        if t is not None:
            iplist.append('tag')
            addresslist.append('tag')
    f.close()
    num=0
    file_path='location_'+ctime().replace(' ','-').replace(':','-')+'.txt'
    f=open(file_path,'w+')
    f.write(str(num)+' number video address:\n')
    for i in range(len(iplist)):
        eachip=iplist[i]
        if eachip=='tag':
            num+=1
            f.write(str(num)+' number video address:\n')
            continue
        url='http://www.ip138.com/ips1388.asp?ip='+eachip+'&action=1'
        try:
            result=getURL(url)
            html=result.read()
            html = unicode(html, "gb2312").encode("utf8")
            m=re.search('(<li>)(.*)(</li>)(.*)(<li>)(.*)(</li>)',str(html))
            if m is not None:
                info=m.group(2)
                #print info
                if -1!=info.find('移动'):
                    #china_YD.append(info)
                    f.write(info+':\n'+addresslist[i])
                elif -1!=info.find('联通'):
                    #china_LT.append(info)
                    f.write(info+':\n'+addresslist[i])
                elif -1!=info.find('电信'):
                    #china_DX.append(info)
                    f.write(info+':\n'+addresslist[i])
                elif -1!=info.find('铁通'):
                    #china_TT.append(info)
                    f.write(info+':\n'+addresslist[i])
        except Exception,e:
            print str(e)
    f.close()
    '''
    for item in china_YD:
        print item
    for item in china_LT:
        print item
    for item in china_DX:
        print item
    for item in china_TT:
        print item
    '''

if __name__ == '__main__':
    
    lk=locker()
    monitor_thread=WorkThread(queue_monitor,(),'monitor_work')
    arrange_thread=WorkThread(arrange_work,(),'arrange_work')
    do_thread=WorkThread(do_work,(),'do_work')
    monitor_thread.start()
    arrange_thread.start()
    sleep(1)
    do_thread.start()
    
    timer_interval=480
    t=Timer(timer_interval,kill_all)
    t.start()
    

    
    
    
    
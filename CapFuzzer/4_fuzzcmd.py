#assemble test commands
#usage:python 4_fuzzcmd.py cmdlist.txt
#requires output/man-res.txt which should be ready after 3_parse.py
#output: fuzzcmds dir, contains 4 files: cmdsdict.txt,UIcmds.txt, scripts.txt, notinstall.txt,
from ast import arguments
import datetime
from inspect import getargs
import json
import os
import shutil
import subprocess
import sys
# commands related to SELinux have a series of specific argument vaules. 
maccmds=['runcon','chcon','mkhomedir_helper','semodule', 'semanage', 'chcat', 'semodule_link', 'fixfiles', 'setenforce', 'semanage-port', 'load_policy', 'semanage-permissive', 'getenforce', 'semanage-login', 'semanage-dontaudit', 'sandbox', 'semanage-module', 'sepolicy-network', 'setfiles', 'matchpathcon', 'semanage-ibendport', 'semodule_unpackage', 'seunshare', 'sepolicy', 'sefcontext_compile', 'selinuxexeccon', 'sestatus', 'togglesebool', 'selinuxenabled', 'sepolicy-interface', 'avcstat', 'restorecon', 'semanage-import', 'setsebool', 'run_init', 'semanage-node', 'semanage-user', 'sepolicy-communicate', 'sepolgen', 'mcstransd', 'semanage-interface', 'sepolicy-gui', 'semodule_expand', 'semodule_package', 'semanage-export', 'sepolicy-manpage', 'semanage-boolean', 'checkmodule', 'semanage-ibpkey', 'sepolicy-booleans', 'restorecond', 'semanage-fcontext', 'getsebool', 'sepolicy-transition', 'checkpolicy']
#commands with a unusual manual we don't consider for now.
black_list=['tc','bpfc','bridge','btrfs']
argus=[]
opt_argname=[]# arg name for options
cmddict={}
longcmd=[]
#dictionary:2 dict
#parameter name and their synonyms
syno_dict={'ipaddr':'hostname,destination,ip,ipaddr,server,address,host,peer,maddress,addr,src,dest','macaddr':'hw_addr,mac,macaddr,token,lladdr','device':'device,interface,ifname,dev,if','terminal':'terminal,tty',"zramdev":"zramdev",'string':'word,repository,header,title,re,str,other,set,input,keyword,md5,string,text,phone,tag,comment,reason,info,location,field,prompt,message','label':'label','category':'category','uuid':'uuid',
'integer':'msgid,increment,lo-hi,span,duration,start,length,len,port,integer,uid,count,size,sector,number,num,id,identifier,vid,offset,sector,interval,list,delay,revision,prefix,ttl,max_ttl,first_ttl,fd,max,min,first,last,inactive,rate,mark,tos,action,bytes,version,recs,chunk,val,ldisc,column,cols,edition,cpus,accmulatdecay,major,minor,col,rows,code,int',"pattern":"pattern,pat",
'program':'program,cmd,application,command','filesystem':'filesystem,fs,filesys,what','kind':'kind',"percent":"percent,percentage","algorithm":"algorithm,algo","proto":"proto,protocol","range":"range","zone":"zone","blockrange":"blockrange",
'file':'f,part,log,file,filename,member,script,out,target,dbase,journal,conf,outfile','directory':'directory,dir,path,source,put_old,root','user':'user,group,g_list,login,name,owner','mask':'mask','fstype':'type,fstype,fs-type','daytime':'mmddhhmm,day,now,date,time,daytime','mount':'where,mount,mountpoint','disk':'disk','partition':'partition,partition-number',
'node':'node','chunk':'chunk_kb,limit,block-softlimit,block-hardlimit,inode-softlimit,inode-hardlimit','pad':'pad','keyring':'keyring','policy':'policy',"class":"class","pid":"pid","baud_rate":"baud_rate,speed","term":"term","blocks_at_once":"blocks_at_once","mode":"mode","media":"media",
'symvers':'Module.symvers','System.map':'System.map,map','format':'format','pem':'pem',"y|n":"y|n","anacrontab":"anacrontab","shadow":"shadow","passwd":"passwd","capabilities":"capabilities,capability,value,capname","state":"state","family":"family,fam"
,"pam":"pam,separators,noaudit,sep,1,expose_authtok,quiet,ignore,nosec,force,revoke,never,showfailed,set_all,utmp_early,noaudit,require_auditd,close,empty,noenv,nopen,standard,require_selinux,gen_hash,ignore_config_error,successok,use_authtok,enforce_for_root,open,close,restore,nottys,verbose,env_params,use_current_range,<,condition,change,deny,root_only,trust,pmtudisc_option,sndbuf,hop"
# ,"selinux":"store,equal,range,modpkg2,level,domain,transition_role,selinux"
,'ibdev_name':'ibdev_name','signal':'signal','default':'policyvers,rpmpackagename,equal,first_block,last_block,expression,regexp,vni','netmask':'netmask',"handle_unknown":'handle_unknown',"priority":"priority"
,"boolean":"boolean,bool","auto":"auto","modulename":"modulename,module","source-file":"source-file","mnt":"mnt","kernel-version":"kernel-version","kernel-image":"kernel-image,image"
#unknown arg use default
,"pv":"pv,pvname","vg":"vg,vgname","lvm":"lvm,lv,lvname","unit":"unit","flag":"flag","radix":"radix","variable":"variable","url":"url","urlregex":"urlregex"
,"rpmpackage":"package,package_file,package_name",'isofile':'iso9660_image_file','type':'type','second':"sec,second,seconds,timeout,block-grace,inode-grace"
,'switch':'switch','args':'args,arg,method,key','blank':'unknown,default,s,cs,cn,option,longopt,dpkg,palette,parameter,name=value,action,matches,instance,to-code,page,template,link,msgid-plural,exit-code,replacement,archive,property,init,undo_log,function,encoding,blank,transport,external-journal,domain,shell,password,ListOfRealms,job,nm,vlan,status,subcommand,new,base,of,parameters,compressor,hertz,e2undo,console,locale,container,realm,formerly,tarball,summary,font.orig,attribute,signal,filter,tty,tolerance,window,packet,gate,generation,options,all,|,modalias,leds,regexp,project,prog,record,=,encap,pfn,2019'
,"subsystem":"subsystem","operand":"operand","lfmt":"lfmt",'gfmt':'gfmt','slash':"slash",'style':'style',"handling":"handling"
,"suffix":"suff,suffix","service":"service","when":"when",'shape':'shape',"namespace":"namespace,ns","family":"family",'syscall':'syscall'
,'table':'table','chain':'chain','fd':'fd',"delimiter":"delimiter,delim,cc,x"
#,"ch":"ch","n":"n"
}
#parameter name and their values 
typeval_dict={'ipaddr':'127.0.0.1,192.168.119.138,182.61.200.7,10.0.2.10,/home/test/cmdfiles/normalfile','macaddr':'00:0c:29:0d:19:d6,aa:bb:cc:dd:00:01','user':'user1,test',
'device':'/dev/loop0,/dev/loop0p1,eth0,eth1,/dev/tty',"zramdev":"/dev/zram0",'integer':'0,1,63,512,0x01,3G,000001',
# 'program':'/bin/ls,/sbin/auditd,/usr/bin/clockdiff 1.1.1.1,cat /etc/shadow,/usr/bin/ping',
# 'file':'/home/test/cmdfiles/cello.spec,/home/test/cmdfiles/gparted-live-1.1.0-6-i686.iso,/home/test/cmdfiles/users.txt,HelloWorld.ko,/home/test/cmdfiles/normalfile.txt, /home/test/cmdfiles/arpdl.txt,/home/test/cmdfiles/auditrules,/home/test/cmdfiles/myarpdb.db,/home/test/cmdfiles/myissue,/home/test/nonexsit.txt,/home/test/cmdfiles/testhello.py,/home/test/cmdfiles/myiptables,/home/test/cmdfiles/privfile.txt',
'program':'/bin/ls','terminal':'/dev/tty','signal':'ALRM',
#/home/test/cmdfiles/privfile.txt,
'file':'/home/test/cmdfiles/normalfile.txt,/home/test/cmdfiles/testhello.py,/home/test/cmdfiles/myiptables,/home/test/cmdfiles/users.txt"
,'isofile':"/home/test/cmdfiles/gparted-live-1.1.0-6-i686.iso"
,'kind':'all,auth,call,general,parse',"percent":"0,0.8","algorithm":"crc32c,sha1,sha256,lzo","proto":"4,47,ipv4,ipv6","range":"0x0000000000000000-0x00000000bfffffff","zone":"DMA32","blockrange":"0-23",
#/root/rootdir
'directory':'/home/test/cmdfiles','string':'hello,18201611248,none,now,"\w"','label':'root,default','filesystem':"/dev/loop0p1,/mnt/img",'uuid':'71ce3613-7ea7-427e-b046-2fb09de08556',
'mask':'barrier,complete,discard,fs,issue,pc,queue,read,requeue,sync,write,notify,drv_data','fstype':'gpt,ext4,default','daytime':'2,Wed Dec 14 19:43:07 CST 2021,2022-03-16 15:20:00','mount':'/dev/loop0p1,/mnt/img','node':'0,127.0.0.1,182.61.200.7',
'System.map':'/home/test/cmdfiles/System.map','Module.symvers':'/home/test/cmdfiles/Module.symvers','format':'+%d,%H:%M:%S.###,ln','pem':'/home/test/scripts/sshkeytest/rsatest','disk':'/dev/loop0','partition':'1,2:3',
"y|n":"y,n",'blank':'','chunk':'1024','pad':'4,8,16,32','keyring':'482735594',"pid":"$$,12345,1","baud_rate":"9600","term":"vt100,linux","anacrontab":"/etc/anacrontab ","blocks_at_once":"64","mode":"horizontal,vertical,+a"
,"modulename":"HelloWorld,HelloWorld.ko",'ibdev_name':'mix5_0','default':'',"policy":"other,fifo,rr","class":"idle,best-effort,real-time","priority":"0,4,7"
,"netmask": "255.255.0.0, ffff::,",'boolean':'0,1',"source-file":"/home/test/cmd/bpfc/test1","mnt":"/dev/loop0p1,/mnt/img"
,"kernel-version":"5.14.0,5.8.10","kernel-image":"/boot/initrd.img-5.14.0+"
,"pv":"/dev/loop0p2","vg":"newvg","lvm":"newlv","unit":"s,B","flag":"boot,root,lvm",'syscall':'read','url':'https://www.baidu.com',"urlregex":" https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)"
,"rpmpackage":"/home/test/cmdfiles/clash-1.8.0-2.fc36.x86_64.rpm",'type':'linux,','second':'3',"variable":"SHELL"
,'switch':'default','args':'default',"shadow":"/etc/shadow","passwd":"/etc/passwd","auto":"auto","media":"100baseT4,100baseTx-FD","pattern":"qemu,","pam":"","selinux":"","capabilities":"0,1","state":"on,off","family":"inet",
"subsystem":"block",'fd':"1,3",'lfmt':'old,new,unchanged','gfmt':'%<,','slash':'/','style':'a,t,full-iso,iso','shape':'2,4,8,16'
,"suffix":".h","service":"mydaemon","when":"never,always,auto","operand":"bs,cbs","namespace":"file,udp,80/tcp","family":"roff,troff"
,'table':'filter,nat,mangle,raw,security','chain':'INPUT,OUTPUT,FORWARD,NEWCHAIN','category':'',"radix":"Decimal,Octal"
,"delimiter":","
#,"ch":"a","n":"1,n"
}

# SElinux dict
se_syno_dict={'range':'range','store':'store','level':'level','interface':'interface','ip':'node','seuser':'seuser'
,'file':'file,outfile','output':'output,outputfile','category':'category','cmd':'cmd,command,application','script':'script','login':'user,group','time':'time'
,'context':'fcontext,context,fcfile,contexts,file contexts','proto':'proto','directory':'dir,directory,path,pathname,rootdir','ibdev_name':'ibdev_name','class':'class','access':'access'
,'role':'role','default':'policyvers,rpmpackagename,equal,','prefix':'prefix','netmask':'netmask',"handle_unknown":'handle_unknown'
,'policy':'policy','module':'module,module_name,modfile','pkg':'basemodpkg,modpkg,pkg','class':'tclass,sourceclass,targetclass','domain':'type,domain,target,source'
,'boolean':'boolean,booleanname,bool','value':'value,val','file_spec':'file_spec','port':'port_name,port_range'}
se_typeval_dict={'range':'s0','level':'s0','store':'/home/test/cmd_files','interface':'eth0,/home/test/cmdfiles/mysepol/mydaemon.if'
,'ip':'127.0.0.1,192.168.119.138,182.61.200.7,10.0.2.10','seuser':'unconfined_u,user_u,system_u,staff_u,root,xdm,','output':'/home/test/cmdfiles/seout'
,'file':'/home/test/cmd_files/normalfile.txt,/home/test/cmdfiles/mysepol/mydaemon.fc,','category':'c0','cmd':'/bin/ls,cat /etc/shadow,/usr/local/bin/mydaemon,/usr/bin/ping','script':'/home/test/cmdfiles/testhello.py'
,'login':'test,root,user1','time':'2022-09-26 00:00','context':'system_u:object_r:user_home_dir_t:SystemLow,/home/test/cmdfiles/mysepol/mydaemon.fc'
,'proto':'ipv4,ipv6','directory':'/home/test/cmdfiles,','ibdev_name':'mix5_0','class':'file','access':'open,read'
,'role':'auditadm_r,dbadm_r,guest_r,object_r,staff_r,sysadm_r,sysadm_r,user_r,unconfined_r,xdm_r','default':'','prefix':'ox00,'
,"netmask": "255.255.0.0, ffff::,",'handle_unknown':'allow,deny,reject','policy':'/usr/share/doc/selinux-policy-dev/examples/example.te,/home/test/cmdfiles/mysepol/mydaemon.te'
,'module':'xfs,mydaemon,/home/test/cmdfiles/mysepol/mydaemon_unpack.mod','pkg':'/home/test/cmdfiles/mysepol/mydaemon.pp','class':'file','domain':'user_t,mydaemon_t,unconfined_t','boolean':'ssh_sysadm_login,allow_java_execstack,user_ping,xen_use_nfs'
,'value':'0,1,on,off','file_spec':'/home/test/cmdfiles/cello.spec','port':'65530,20000-20002'}

special_list=["chmem","zramctl","sudoreplay"]
kmod_list=["kmod","insmod","lsmod","modprobe","modinfo","rmmod","depmod"]
unknown_type=[]

def getargs(line):
	args_dict=json.loads(line)
	for key in args_dict:
		if key not in opt_argname:
			opt_argname.append(key)
def assembleopts(opts_dict,tmpres,args_dict,requiredopts,cur_cmd,synodict,valdict,unknownargs):
	optres=[]
	for i in opts_dict:
		if i in requiredopts or 'command' in i:
			continue	
		arg=opts_dict[i]
		#y for yes
		if arg =="y":
			for item in range(len(tmpres)):
				optres.append(tmpres[item]+i+" y")
			continue
		if arg!="":
			arg=arg.replace(",","")
			# look for possible values for arg in local dict and global dict
			if args_dict.get(arg)!=None:
				tempargs=args_dict.get(arg).split(",")
				for a in tempargs:								
					for item in range(len(tmpres)):
						optres.append(tmpres[item]+i+" "+a+" ")
					
				#todo: add global arg,besides local args
				type=""		
				for key in synodict:
					if arg.lower()=="unknown":
						break
					keys=synodict[key].split(',')
					for tkey in keys:
						if tkey=="":
							continue
						if tkey==arg.lower():
							type=key
							break
					if type=="" and len(arg)>1:
						for tkey in keys:
							if tkey in arg.lower():			
								type=key
								break

				if type:
					for item in range(len(tmpres)):
						optres.append(tmpres[item]+i+" "+type+"<i> ")
		
			elif arg=="unknown":
				for item in range(len(tmpres)):
					optres.append(tmpres[item]+i+" unknown<i> ")
			# arg not in local dict try global 
			else:
				type=""
				for key in synodict:
					keys=synodict[key].split(',')
					for tkey in keys:
						if tkey=="":
							continue
						if tkey in arg.lower():							
							type=key
							break
				if type:
					for item in range(len(tmpres)):
						optres.append(tmpres[item]+i+" "+type+"<i> ")

				else:# record arg names not in global dict
					if arg not in argus and cur_cmd+":"+arg not in argus :
						argus.append(cur_cmd+":"+arg)
					if arg not in unknownargs:
						unknownargs.append(arg)

		else:
			for item in range(len(tmpres)):
				optres.append(tmpres[item]+i+" ")	
	return optres

def assemble(cur_cmd,req,opts,args,example,synodict,valdict,unknownargs):
	# debug_flag=0
	required=json.loads(req)
	opts_dict=json.loads(opts)
	args_dict=json.loads(args)
	example_dict=json.loads(example)
	res=[]
	first_res=[]
	tempres=""
	#require + opt
	for r in required:
		# replace non-required option with lowercase
		rlist=r.split()
		newr=""
		for it in rlist:
			if it.startswith("-"):
				newr=newr+" "+it
			else:
				newr=newr+" "+it.lower()
		r=newr
		#add required anyway
		if r not in res:
			if 'options' in r and 'command' not in r:
				newr=r.replace("[options]","")
				newr=newr.strip()
				res.append(newr)
			if 'option' not in r and '-' not in r:
				r=r.strip()
				if r not in res:
					res.append(r)
				#no option and no subcommand
				if 'command' not in r and len(opts_dict)==0:
					continue
		rwords=r.split()
		wrongformat=False
	
		for rw in rwords:
			for argname in synodict:
				argnames=synodict[argname].split(',')
				for a in argnames:
					if rw==a and '<i>' not in rw:
						index=0
						if rw in rwords:
							index=rwords.index(rw)
						if index!=0:
							rwords[index]=rw+'<i>'
							wrongformat=True
		if wrongformat:
			newr_i=""
			for rw in rwords:
				newr_i=newr_i+rw+" "
			newr_i=newr_i.strip()
			if newr_i:
				if 'options' in newr_i and 'command' not in newr_i:
					newr=newr_i.replace("[options]","")
					newr=newr.strip()
					if newr not in res:
						res.append(newr)
				if 'option' not in newr_i and '-' not in newr_i:
					newr_i=newr_i.strip()
					if newr_i not in res:
						res.append(newr_i)
					# no options and no subcommand 
					if 'command' not in r and len(opts_dict)==0:
						continue
		# unfold command and options in order 
		tmpres=[]
		curres=""
		addopt=False
		# extract required options first
		requiredopts=[]
		for rw in rwords:
			if rw.startswith('-'):

				requiredopts.append(rw)
			
		for rw in rwords:
			if 'command' in rw.lower():
				cmd_flag=False
				for opt in opts_dict:
					if "command" in opt:
						cmd_flag=True
						commands=opts_dict[opt]
						cmds=commands.split(',')
						newtmp=[]
						for cmd in cmds:
							if cmd!="":
								for i in range(len(tmpres)):
									newtmp.append(tmpres[i]+cmd+" ")
						tmpres=newtmp
				if not cmd_flag:
					if tmpres:
						for i in range(len(tmpres)):
							tmpres[i]=tmpres[i]+rw+" "
					#command cant be the first item,should never get there
					else:
						curres=curres+rw+" "
						tmpres.append(curres)
			elif 'option' in rw or '[]' in rw:
				if addopt:
					continue
				addopt=True
				optres=assembleopts(opts_dict,tmpres,args_dict,requiredopts,cur_cmd,synodict,valdict,unknownargs)
				tmpres=optres
			else:
				if tmpres:
					for i in range(len(tmpres)):
						tmpres[i]=tmpres[i]+rw+" "
				else:
					curres=curres+rw+" "
					tmpres.append(curres)					
		# no options in synopsis, but opt_dict has opt
		if addopt==False and len(opts_dict)>0 and " -" not in r:
			optres=assembleopts(opts_dict,tmpres,args_dict,requiredopts,cur_cmd,synodict,valdict,unknownargs)
			tmpres=optres
		res.extend(tmpres)	
	if len(required)==0:
		res.append(cur_cmd)
	for ex in example_dict:
		res.append(ex)
	if res:
		for tres in res:
			id=res.index(tres)
			if tres==None:
				continue
			if '{' in tres:
				tres_list=tres.split()
				tresnew=""
				for tl in tres_list:
					if '{' in tl or '}' in tl:
						tl=tl.replace('{',"")
						tl=tl.replace('}',"")
						tl=tl+'<i>'
					tresnew=tresnew+tl+" "
				tres=tresnew
				res[id]=tres
			if '<i>' in tres:
				tres=tres.replace("<i>","+i+")
				tres=tres.replace('<','')
				tres=tres.replace('>','')
				tres=tres.replace("+i+","<i>")
				res[id]=tres
	first_res.extend(res)
	handleres(cur_cmd,first_res,args_dict,synodict,valdict,unknownargs)

# replace <i> with possible value
def handleres(cur_cmd,res,args_dict,synodict,valdict,unknownargs):	
	sec_res=[]
	c=0
	sec_res.append(cur_cmd)
	for r in res:
		c=c+1
		if r==None:
			continue
		tempres=""
		internal=[]# store intermidate result
		count=r.count("<i>")
		if count>5:
			continue
		if '<i>' in r:# argument need expand and replace
			words=r.split()
			for word in words:
				if '<i>' in word:
					type=""
					arguname=word.replace("<i>","")
					# local dict
					localmatch=False
					for arg in args_dict:
						if arg in arguname:
							argvals=args_dict[arg].split(',')
							ininternal=[]
							if internal:
								for i in range(len(internal)):
									for val in argvals:
										ininternal.append(internal[i]+val+" ")
							internal=ininternal
							localmatch=True
							break
					if localmatch:
						continue
					#
					# use global dict
					for key in synodict:
						if arguname=="unknown":
							break
						keys=synodict[key].split(',')
						for tkey in keys:
							if tkey=="":
								continue
							if tkey==arguname.lower():
								type=key
								break
						if type=="" and len(arguname)>1:
							for tkey in keys:
								if tkey in arguname.lower():							
									type=key
									break
					if type:
						if type in valdict:
							tval=valdict[type]
							tvals=tval.split(',')
							ininternal=[]						
							#argument should not be at the first position
							if internal:
								for i in range(len(internal)):
									for val in tvals:
										ininternal.append(internal[i]+val+" ")
								internal=ininternal
							else:
								break
						else:
							untype=cur_cmd+":"+type
							unknown_type.append(untype)
					else:
						#unknown argu, add to unknown listt
						if arguname not in unknownargs:
							unknownargs.append(arguname)
						#unknown argu,try all values
						if arguname=="unknown":
							ininternal1=[]
							for t in valdict:
								tval=valdict[t]
								tvals=tval.split(',')
								if internal:
									for i in range(len(internal)):
										for val in tvals:
											ininternal1.append(internal[i]+val+" ")
							internal=ininternal1
						elif arguname not in argus and cur_cmd+":"+arguname not in argus :
							argus.append(cur_cmd+":"+arguname)
				else:
					if internal:	
						for i in range(len(internal)):
							internal[i]=internal[i]+word+" "
					else:
						tempres=tempres+word+" "
						internal.append(tempres)
			for temp_internal in internal:
				temp_internal=temp_internal.strip()
				if temp_internal not in sec_res:
					sec_res.append(temp_internal)
		else:
			r=r.strip()
			if r not in sec_res and r!="":
				sec_res.append(r)
	if len(sec_res)>2000:
		longcmd.append(cur_cmd+":"+str(len(sec_res)))
	cmddict.update({cur_cmd:sec_res})

def getcmdtype(cmdset):
	scripts=[]
	UIcmd=[]
	notinstall=[]
	for cmd in cmdset:
		ret=getcmdfile(cmd)
		if ret==1:
			scripts.append(cmd)
		elif ret==2:
			UIcmd.append(cmd)
		elif ret==255:
			notinstall.append(cmd)
	if len(UIcmd)>0:
		with open(current_dir+"UIcmd.txt",'a+') as fui:
			json.dump(UIcmd,fui)
	if len(scripts)>0:
		with open(current_dir+"scripts.txt",'a+') as fspt:
			json.dump(scripts,fspt)
	if len(notinstall)>0:
		with open(current_dir+"notinstall.txt",'a+') as fnotinstall:
			json.dump(notinstall,fnotinstall)
	return scripts,UIcmd

def getlinkedfile(path):
    realpath=""
    filecmd='realpath '+path
    subp1=subprocess.run(filecmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,shell=True)
    realpath=subp1.stdout.strip()
    return realpath
def getcmdfile(cmd):
	#scripts:1 UIcmd:2
	type=0
	whichcmd="which "+cmd
	subp = subprocess.run(whichcmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,shell=True)
	out=subp.stdout.strip()
	if out:
		filecmd='file '+out
		subp1=subprocess.run(filecmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,shell=True)
		fileout=subp1.stdout.strip()
		#scripts file
		if "ASCII" in fileout or 'text' in fileout or 'script' in fileout:
			type=1
		#link file
		elif 'link' in fileout:
			linked=getlinkedfile(out)
			if linked:
				filecmd2='file '+linked
				subp2=subprocess.run(filecmd2,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,shell=True)
				fileout2=subp2.stdout.strip()
				if "ASCII" in fileout2 or 'text' in fileout2 or 'script' in fileout2:
					type=1
		#judge wether command is a UI-cmd
		lddcmd="ldd "+out
		subp2=subprocess.run(lddcmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,shell=True)
		lddout=subp2.stdout.strip()
		if "curse" in lddout:
			type=2
	else:
		type=255
	return type

def getfuzzcmdsdict(targets):
	with open('output/man-res.txt') as res:
		i=0
		required=''
		opts=''
		args=''
		example=''
		flag=False #only fuzz cmd in target
		cur_synodict={}
		cur_valdict={}
		while True:
			line=res.readline()
			if not line:
				break
			if i%5==0:
				cur_cmd=""		
				if "****"in line:
					cur_cmd=line.split(' ')[1].strip()
					cur_cmd=cur_cmd.replace("*","")
					if 'resolving' in cur_cmd:
						break
					if cur_cmd in targets:
						flag=True
						if cur_cmd not in maccmds:
							cur_synodict=syno_dict
							cur_valdict=typeval_dict
						else:
							cur_synodict=se_syno_dict
							cur_valdict=se_typeval_dict					
					else:
						flag=False
			#get first word in require list,jump cmd if first in blklist 
			elif flag and i%5==1:
				required=line.strip()
				req=json.loads(required)
			elif flag and i%5 ==2:
				opts=line.strip()
			elif flag and i%5==3:
				args=line.strip()
				getargs(line)
			elif flag and i%5==4:
				example=line
				unknownargs=[]
				assemble(cur_cmd,required,opts,args,example,cur_synodict,cur_valdict,unknownargs)
				if len(unknownargs)>0:
					unargdict.update({cur_cmd:unknownargs})
			i=i+1
		# handleres()
		newdiscover=[]	
		for arg in argus:
			new=True
			for it in cur_synodict:
				arg=arg.lower().replace("<i>","")
				if arg not in cur_synodict[it]:
					continue
				else:
					new=False
			if arg not in newdiscover and new==True:
				newdiscover.append(arg)
		for optarg in opt_argname:
			new=True
			for it in cur_synodict:
				if optarg not in cur_synodict[it]:
					continue
				else:
					new=False
			if optarg not in newdiscover and new==True:
				newdiscover.append(optarg)
		f = open(current_dir+'/cmdsdict.txt','a+',encoding="UTF8")
		json.dump(cmddict,f)
		f.write('\n')
		f.write("***********arguments are:**************\n")
		json.dump(argus,f)
		f.write('\n')
		f.write("************opt args names are:***********\n")
		json.dump(opt_argname,f)
		f.write("\n************new discover arg not in global dict:***********\n")
		json.dump(newdiscover,f)
		f.write("\n************cmd args not in global dict:***********\n")
		json.dump(unargdict,f)
		f.write("\n************fuzz cmds over 2000s:***********\n")
		json.dump(longcmd,f)
		f.close()

if __name__ == "__main__":	
	starttime = datetime.datetime.now()
	current_dir="output/fuzzcmds/"
	if os.path.exists(current_dir):
		shutil.rmtree(current_dir)
	os.mkdir(current_dir)	
	#read target command list from file 
	targetsnew=[]
	argnum=len(sys.argv)
	if argnum!=2:
		print("get manual error: wrong argument number! Expect 1 file name!")
		sys.exit(1)
	tarfile=sys.argv[1]
	with open(tarfile,'r')as f:
		c=0
		for line in f.readlines():
			c=c+1
			command=line.strip()
			targetsnew.append(command)
	#identify which cmd can not fuzz 
	new_run=set(targetsnew)
	UIcmd=[]
	scripts=[]
	scripts,UIcmd=getcmdtype(new_run)
	#cmd and undefined args
	unargdict={}
	getfuzzcmdsdict(targetsnew)
	print("unknown arg")
	print(unargdict)
	endtime = datetime.datetime.now()
	print(f"start at {starttime},end at {endtime}")
	print(f"get longcmd:{longcmd}")
	# min=(endtime - starttime).seconds/60
	delt=endtime - starttime
	sec=delt.total_seconds()
	print (f"use {sec}")
	if len(unknown_type)>0:
		print(f"unknown type {unknown_type}")


	
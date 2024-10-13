#parse manuals in to elements
#usage:python 3_parse.py cmdlist.txt
#refers to output/getopt-out.txt (options get from libc)
#output: output/man-res.txt

from email.utils import make_msgid
from operator import is_
from pydoc import synopsis
from random import shuffle
from wsgiref import validate
from bs4 import BeautifulSoup
import re
import os
import json
import sys

cmdargs=["host"]
jump_list=["bridge","dcb-app","dcb-buffer","dcb-dcbx","dcb-ets","dcb-maxrate","dcb-pfc","dcb",
"devlink-dev","devlink-dpipe","devlink-health","devlink-monitor","devlink-port","devlink-rate","devlink-region","devlink-resource","devlink-sb","devlink-trap","devlink","findfs ","genl","genpolbools","genpolusers","genhomedircon","ifstat","ip-extensions","ip-address","ip-link","ip-l2tp","ip-macsec","ip-mptcp","ip-neighbour","ip-nexthop","ip-route","ip-rule","ip-tcp_metrics","ip-tunnel","ip-xfrm","ip","ip6tables","iptables",
"rdma-dev","rdma-link","rdma-resource","rdma-statistic","rdma-system","rdma",
"tc-actions","tc-connmark","tc-csum","tc-ematch","tc-flow","tc-flower","tc-hfsc","tc-ife","tc-mirred","tc-mpls","tc-nat","tc-netem","tc-pedit","tc-police","tc-sample","tc-skbmod","tc-tunnel_key","tc-u32","tc-vlan","tc","tipc","vdpa-dev","vdpa-mgmtdev"]
special_list=["chmem","zramctl","sudoreplay"]
kmod_list=["kmod","insmod","lsmod","modprobe","modinfo","rmmod","depmod"]
opts_args=[]
args_dict={}
libres_dict={}
manual=set()
synopsiserr=set()
# extract short options like -a -b
def handleshortopt(line):
	cmd=line.split(" ")[0]
	index=line.find("short opts:")
	opts=line[index+11:]
	opts=opts.replace("\n","")
	opt=""
	for char in opts:
		if char==":":
			index=opt.rfind(";")
			new_opt=opt[:index]+":"+opt[index:]
			opt=new_opt 
		elif char=="-":
			continue
		elif char=='?' or char=='h':
			continue
		else:
			opt=opt+"-"+char+";"
	#add to dict
	temp={cmd:opt}
	libres_dict.update(temp)

def checkOptions(cmd,optdict,dup_opts):
	libopts=libres_dict.get(cmd).split(";")
	for lopt in libopts:
		#prepare for long opts
		arg=""
		if lopt=="":
			continue
		if lopt.startswith("-")!=True and lopt!="":
			lopt="--"+lopt
			if lopt in dup_opts:
				continue
		#print("lib  opt is "+lopt)
		count=lopt.count(":")
		if count==1:
			arg="unknown"
		if count>0:
			lopt=lopt.replace(":","")
		if optdict.get(lopt)==None:
			optdict.update({lopt:arg})

# extract long options like --file, --length
def handlelongopt(line):
	cmd=line.split(" ")[0]
	index=line.find("long opts:")
	opts=line[index+10:]
	opts=opts.replace("\n","")
	old=libres_dict[cmd]
	new=""
	if old!="":
		new=old+opts
	else:
		new=opts
	temp={cmd:new}
	libres_dict.update(temp)

# -*- coding: cp936 -*-
def findStr(string, subStr, findCnt):
	a=string
	listStr = a.split(subStr,findCnt)
	if len(listStr) <= findCnt:
		return -1
	return len(string)-len(listStr[-1])-len(subStr)

def testbr(item,content):
	count=content.count(item)
	prerm=False
	for i in range(count):
		#previous one was deleted
		if i==0:
			ii=1
		else:
			if not prerm:
				ii=ii+1
		index=findStr(content,item,ii)
		new=content[index+5:]
		new=new.strip()
		if new.startswith('[') or new.startswith("-") or new.startswith("{") or new.startswith("("):
			#remove br
			content=content[0:index]+content[index+5:]
			prerm=True
			continue
		for arg in cmdargs:
			if new.startswith(arg):
				#remove <br/>
				prerm=True
				content=content[0:index]+content[index+5:]
				continue
		prerm=False
	return content
def addnewline(content):
	content=testbr("<br/>",content)	
	return content

#get content under heading h2
def getSectionContent(h2):
	content=""
	new_content=""
	for next in h2.next_siblings:
		if next.name=="h2":
			break
		if next!=None:
			content=content+str(next)
	new_content=content.replace("\n"," ")
	if "synopsis" in h2.text.lower():
		new_content=addnewline(new_content)
	if "<b><br/>" in content or "<b><br>" in content:
		new_content=new_content.replace("<b><br/>","</p><p><b>")
	if "<i><br/>" in content or "<i><br>" in content:
		new_content=new_content.replace("<i><br/>","</p><p><i>") 
	#consider if there is special format before replacing br
	while "<br/>" in new_content:
		index=new_content.find("<br/>")
		br_content=new_content[:index]
		bclose=br_content.count("</b>")
		bcount=br_content.count("<b>")
		icount=br_content.count("<i>")
		iclose=br_content.count("</i>")
		#check for open <b>
		if bcount>bclose:
			new_content=new_content.replace("<br/>","</b></p><p><b>",1)
		else:
			new_content=new_content.replace("<br/>","</p><p>",1)
		if icount>iclose:
			new_content=new_content.replace("<br/>","</i></p><p><i>",1)
		else:
			new_content=new_content.replace("<br/>","</p><p>",1)
	new_content=new_content.replace("<big>","")
	new_content=new_content.replace("</big>","")
	return new_content

#return the first word in a string
def getFirstString(p):
	res=""
	for pchild in p.children:
		if pchild.string==None:
			continue
		b_string=pchild.string.strip().replace("\n"," ")
		if b_string=="":
			continue
		b_string=b_string.split()[0]
		if b_string=="":
			continue
		else:
			res= b_string
			#print("get first "+b_string)
			break
	return res

#return the first bold word in a string
def getFirstboldString(p):
	res=""
	for pchild in p.children:
		if pchild.name!="b":
			continue
		if pchild.string==None:
			continue
		b_string=pchild.string.strip().replace("\n"," ")
		if b_string=="":
			continue
		b_string=b_string.split()[0]
		if b_string=="":
			continue
		else:
			res= b_string
			#print("get first "+b_string)
			break
	return res
#handle irregular synopsis
def getAbnormalSynopsis(temps,cmd):
	required=[]
	for temp in temps:
		cur=getNormalSynopsis(temp,cmd).strip()
		if cur!="":
			if not cur.startswith(cmd):     
				if required:
					last=required[-1]
					required.remove(last)
					cur=last+" "+cur
				else:
					print("err:cmd is "+cmd+" and current is "+cur)               
			required.append(cur)
	return required
	
#entry to parsing synposis
def getRequiredfromSyno(h2,cur_cmd):
	new_content=getSectionContent(h2)
	local_soup=BeautifulSoup(new_content,'html.parser')
	temps=local_soup.find_all("p")
	trs=local_soup.find_all("tr")
	table=False
	if len(trs)>=1:
		table=True
	required=[]
	#the first elements in <p>s should be same, should be command
	cmd=""
	model=0
	first_strs=[]
	firstbold_strs=[]
	for temp in temps:
		first=getFirstString(temp)
		first_strs.append(first)
		firstbold=getFirstboldString(temp)
		firstbold_strs.append(firstbold)
	if cur_cmd in first_strs or cur_cmd in firstbold_strs:
		cmd=cur_cmd
	else:
		for item in first_strs:
			if cur_cmd in item or item in cur_cmd:
				cmd=item
		if cmd=="":
			for itemb in firstbold_strs:
				if cur_cmd in itemb or item in cur_cmd:
					cmd=itemb
	#if the manual is using bold format, delte lines without bold 
	bolds=[]
	if table:
		required=getAbnormalSynopsis(temps,cmd)
	else:
		if cur_cmd in firstbold_strs:
			for temp in temps.copy():
				firstb=getFirstboldString(temp)
				if firstb!=cmd:
						temps.remove(temp)
				else:
					bolds.append(firstb)
		if len(bolds)>1:
			boldset=set(bolds)
			if len(boldset)>1:
				model=1
				print(boldset)
		for t in temps:
			res=getNormalSynopsis(t,cmd).strip()
			if '.service' in res:
				continue
			string_encode = res.encode("ascii", "ignore")
			string_decode = string_encode.decode()
			res=string_decode
			if res not in required and res!="":
				required.append(res)
	return required

#input synopsis output args list
def getsimpleSynopsis(h2):
	require=""
	for sibling in h2.next_siblings:
		if sibling.string==None:
			continue
		if sibling.name=="h2":
			break
		if sibling.name=="p":
			p_str=sibling.string.strip().replace("\n","")
			#delete content in [] 
			res=re.sub('\[[\[]*.*?[\]]*\]','',p_str)
			require=require+res+";"
			print("in getsimplesynopsis: "+require)
	return require

#handle nested brackets, only keep the outer one
def delete_multi_brackets(s):
	if "[ " in s:
		s=s.replace("[ ","[")
	if "] " in s:
		s=s.replace(" ]","]") 
	stack = []
	out_res = ''
	for c in s:
		if c == '[':
			stack.append('[')
		elif c == ']':
			if len(stack) == 1:
				top_stack = stack.pop()
				if top_stack[0] == '[':
					top_stack += ']'
				out_res += top_stack
			elif len(stack) > 1:
				stack.pop()				
			else:
				pass
		elif not stack:
			out_res += c
		elif len(stack) == 1:
			stack[-1] += c
		elif len(stack)>1:
			tmptop=stack.pop()+c
			stack.append(tmptop)
	return out_res

#brackets don't come in pair, return false
def check_nested_brackets(old):
	state_stack = []
	# print(f"old is {old}")
	for s in old:
		# [asdfa[123]]
		if s == '[':
			state_stack.append(s)
			if len(state_stack)>1:
				return True
		elif s == ']':
			if state_stack:
				state_stack.pop()
			else:
				return False
	return False

def getOptinBrackets(optstr):
	optarg=""
	opt=""
	if optstr.startswith("-"):
		# optstr=optstr.replace("<","")
		# optstr=optstr.replace(">","")
		olist=optstr.split()
		if olist:
			opt=olist[0]
			optarg=optstr[len(opt)+1:]
			optarg=optarg.strip()
			optarg=optarg.replace("...","")
			if "&lt" in optarg and "&gt" in optarg:
				index1=optarg.find("&lt")
				index2=optarg.find("&gt")
				optarg=optarg[index1+4:index2]
			# print(f"opt:arg {opt}:{optarg}")
	if opt!="":
		#-f,--filename jump
		if opt[-1]==",":
			opt=opt[:len(opt)-1]
		if optarg.startswith("-") or optarg.startswith("|"):
			return
		OptinSyno.update({opt:optarg})

def handleSquarebrackets(pstr):
	newstr=""
	hasopt=False
	#minimum matching
	opts=re.findall(r'[\[](.*?)[\]]',pstr)  
	for opt in opts:
		if opt=="s":
			pstr=pstr.replace('[s]',"")
			continue
		#remove format string
		shouldrm=False       
		opt_new_origin=opt.strip()
		opt_new=opt.strip()
		opt_new=opt_new.replace("<b>","")
		opt_new=opt_new.replace("</b>","")
		opt_new=opt_new.replace("<i>","")
		opt_new=opt_new.replace("</i>","")
		if opt_new.startswith('-') or 'option' in opt.lower():
			getOptinBrackets(opt_new)
			shouldrm=True
			# print(f"opt:{opt} shouldrm {shouldrm}")
		if shouldrm:
			# print(f"hasopt:{hasopt}")
			if hasopt:
				pstr=pstr.replace('['+opt+']','')
			else:
				pstr=pstr.replace('['+opt+']','[options]')
				hasopt=True 
			# print(f"pstr:{pstr}")          
		#remove square brackets add <i> to mark content as parameters
		else:
			opt_i=opt
			if '<b>' in opt_new_origin:
				pstr=pstr.replace('['+opt+']',opt)
			else:
				left=opt_new_origin.count("<i>")
				right=opt_new_origin.count("</i>")
				# print(f"left {left}; right {right}")
				if left>right:
					if '|' not in opt_new_origin:
						opt_i=opt.strip()+"</i>"
					else:
						opt_i=opt_i.replace("|","</i>|")
						opt_i=opt_i+"</i>"
						# print(f"opt_i {opt_i}")
				elif left<right:
					if '|' not in opt_new_origin:
						opt_i="<i>"+opt.strip()
					else:
						opt_i="<i>"+opt.strip()
						opt_i=opt.replace("|","|<i>")
				else:
					if left==0:
						opt_i="<i>"+opt.strip()+"</i>"
				pstr=pstr.replace('['+opt+']',opt_i)
	newstr=pstr 
	return newstr,hasopt

#parse synposis
#Extracts the required part from each <p>, 
#returns the required part, separated by a space,
#use <i> tag if is a parameter
def getNormalSynopsis(p,cmd): 
	# print(f"getNormal {p}")
	prequired=""
	required_joint=""
	pstr=str(p).replace("\n"," ")
	res=pstr
	if "{" in pstr:
		pstr=pstr.replace("{","[")
		pstr=pstr.replace("}","]")
	hasopt=False
	if '"' in pstr:
		pstr=pstr.replace('"','')

	if '[' in pstr:
		checkret=check_nested_brackets(pstr)  
		if checkret>0:
			global cmd2parse
			manual.add(cmd2parse) 
			res=delete_multi_brackets(pstr)
			res,hasopt=handleSquarebrackets(res)
		else:
			res,hasopt=handleSquarebrackets(pstr)
	#remove ()
	res1=re.sub(r'\(.*\)','',res)
	res1=res1.replace("<b>","")
	res1=res1.replace("</b>","")  
	local_soup=BeautifulSoup(res1,'html.parser')
	temp=local_soup.find("p")
	for pchild in temp.children:
		if pchild.string==None:
			continue
		r_str=pchild.string.strip().replace("\n","")
		r_str=r_str.replace("...","")
		#blacklist filtering
		if "Usage:" in r_str:
			r_str=r_str.replace("Usage:","")
		#mark arg's name
		if pchild.name=="i":
			for s in r_str.split():
				if not s.startswith('-') and s!="[]":
					if '/' in s:
						args=s
					else:
						if s!=cmd:
							args=s+"<i>"
							cur_args.append(s)
						else:
							args=s
					if args not in required_joint:
						required_joint=required_joint+" "+args
				else:
					required_joint=required_joint+" "+s
		else:
			required_joint=required_joint+" "+r_str
	if required_joint!="":
		prequired=prequired+required_joint+" "
	return prequired

#，actions bridge，TODO
# handle or in synopsis: -a|-b
def handleOr(required,cur_cmd):
	res=[]
	for req in required:
		#remove <>
		if '<i>' in req:
			id=required.index(req)
			req=req.replace("<i>","+i+")
			if '<' in req:
				req=req.replace("<","")
				req=req.replace(">","")
			req=req.replace("+i+","<i>")
			required[id]=req
		if "[ " in req:
			req=req.replace("[ ","[")
			req=req.replace(" ]","]")
		if '|' in req:
			hasOr.add(cur_cmd)
			ornum=0
			orign_req=req
			# remove blank
			req=req.replace("| ","|")
			req=req.replace(" |","|")
			temps=req.split()
			for t in temps:
				if "|" in t:
					ornum=ornum+1

			opts=[[]]*ornum
			tmp_res=[]#commands after expand 'or'
			cmd=""#same content in front
			i=0
			simple=True
			for t in temps:
				if '|' in t:
					opts[i]=t.split("|")
					opt=False
					arg=False
					for o in opts[i]:
						o_len=len(o.split())
						if o_len>1:
							if o.startswith('-'):
								opt=True
							else:
								arg=True
					if opt==True and arg==True:
						simple=False
						break
					i=i+1 
			#-a apple|-b banana
			if simple==False:
				#merge options and argument
				preopt=False
				#split by blank, replace blank in opt and arg with '+' at first
				orign_req=orign_req.replace("|"," | ")
				temps=orign_req.split()
				for t in temps:
					if preopt:
						if '<i>' in t:	
							id=temps.index(t)
							popt=temps[id-1]
							temps[id-1]=popt+"+"+t#replace' 'with +, --uid uid<i> --> --uid+uid<i>
							temps.remove(t)
							preopt=False
					if t.startswith("-"):
						preopt=True
					if t.startswith('|-'):
						preopt=True
				# merge 
				temps_new=""
				for t in temps:
					temps_new=temps_new+t+" "
				temps_new=temps_new.replace("| ","|")
				temps_new=temps_new.replace(" |","|")
				temps_new=temps_new.split()
				opts=[[]]*ornum
				i=0
				#replace '+' back to blank
				for t in temps_new:
					if '|' in t:
						t=t.replace("+"," ")
						opts[i]=t.split("|")
						i=i+1               
				m=0
				for t in temps_new:
					if t==" ":
						continue
					if '|' in t:
						if tmp_res:
							for index in range(len(tmp_res)):
								for o in opts[m]:
									tmp_res[index]=tmp_res[index]+" "+o
						else:
							for o in opts[m]:
								tmp_res.append(cmd+" "+o)
						m=m+1
					else:
						if tmp_res:
							for index in range(len(tmp_res)):
								tmp_res[index]=tmp_res[index]+" "+t
						else:
							cmd=cmd+" "+t
				res.extend(tmp_res)
			#-a|-b|-c 
			else:
				m=0
				for t in temps:
					if t==" ":
						continue
					if '|' in t:
						if tmp_res:
							for index in range(len(tmp_res)):
								for o in opts[m]:
									tmp_res[index]=tmp_res[index]+" "+o
						else:
							for o in opts[m]:
								tmp_res.append(cmd+" "+o)
						m=m+1
					else:
						if tmp_res:
							for index in range(len(tmp_res)):
								tmp_res[index]=tmp_res[index]+" "+t
						else:
							cmd=cmd+" "+t
				res.extend(tmp_res)           
		else:
			res.append(req)
	return res

#extract bold word as command candidate
def getCommands(h,dict,arg_dict):
	content=getSectionContent(h)
	local_soup=BeautifulSoup(content,'html.parser')
	temps=local_soup.find_all("p")
	look_next=""
	for temp in temps:
		first=getFirstString(temp)
		for t in temp.children:
			if t.name=="b":
				if t.string!=None:
					b_str=t.string.split()[0]
				if first==b_str and first!="":
					cmd_arg=""
					for ie in t.next_siblings:
						if ie.name=="i":
							i_str=ie.string
							newstr=""
							if i_str!=None:
								istrs=i_str.split()
								for str in istrs:
									if str!="":
										newstr=newstr+str+"<i> "
							cmd_arg=cmd_arg+newstr
					if cmd_arg:
						b_str=b_str+" "+cmd_arg
						look_next=cmd_arg
					#add to arg_dict<command:b_str>
					old=dict.get("command")
					new=""
					if old!=None:
						if old.find(b_str)==-1:
							new=old+b_str+","
						else:
							new=old
					else:
						new=b_str+","
					item='{"command":new}'
					item_dd=eval(item)
					dict.update(item_dd)
			elif look_next:
				getArgsinP(temp,look_next,arg_dict) 

#some options are only show in synopsis, so we extract options from synopsis for completeness
def hasOptinSyno(h2):
	new_content=getSectionContent(h2)
	if 'option' in new_content.lower():
		return True
	local_soup=BeautifulSoup(new_content,'html.parser')
	temps=local_soup.find_all("p")
	flag=False
	for temp in temps:
		p_str=str(temp).replace("\n","")
		raw=re.sub('\<.*?\>','',p_str)
		opts=re.findall(r'[\[](.*?)[\]]',raw)       
		for opt in opts:
			if opt.startswith('-'):
				flag=True
	return flag

def addto_dicts(res,options_dict):
	opt=res.split(":")[0]
	#options end with '='
	if opt[-1]=="=":
		opt=opt.replace("=","")
	#options contain '<>'
	if '\u00a0' in opt:
		opt=opt.replace('\u00a0',"")
	opt_arg=""
	look_next=""
	if res.endswith(":"):
		look_next=""
	else:
		opt_arg=res.split(":")[1]
		look_next=opt_arg
	if options_dict.get(opt)==None:
		item='{opt:opt_arg}'
		item_dd=eval(item)
		options_dict.update(item_dd)
	return look_next

def mergelabel(pstr):
	newsoup=BeautifulSoup(pstr,'html.parser')
	current=newsoup.find("p")
	current_tag=""
	current_content=""
	for child in current.children:
		current_content=child.text
		if child.name=="b":
			if child.name==current_tag:
				oldstr="<b>"+child.text+"</b>"
				pstr=pstr.replace(oldstr,current_content)
		current_tag=child.name
	return pstr

#extract options and their parameters
def getOptins(h2,options_dict,arg_dict,dup_opts,level):
	new_content=getSectionContent(h2)
	local_soup=BeautifulSoup(new_content,'html.parser')
	temps=local_soup.find_all("p")
	look_next=""
	for temp in temps:
		# remove [], merge label,<b>--</b>[<b>no-</b>]<b>debug-logging</b>
		tempstr=str(temp)
		tmpstr_rm=re.sub('\[[\[]*.*?[\]]*\]','',tempstr)
		newstr=mergelabel(tmpstr_rm)
		tmp_soup=BeautifulSoup(newstr,'html.parser')
		current=tmp_soup.find("p")
		res=extractfromP(current,dup_opts,level)
		if res!="":
			#add to dict
			look_next=addto_dicts(res,options_dict)
			#if opt is not begin with '-',goto description to find arg's value
			if level==1:
				look_next=res.split(":")[0]
		else:
			if look_next:
				getArgsinP(temp,look_next,arg_dict) 

#extract special format in description as argument candidate
def getArgsinP(p,arg_name,dict):
	for pchild in p.children:
		if pchild.string==None:
			continue
		string=pchild.string.replace("\n" ," ")
		#handle special format 
		if pchild.name=="b" or pchild.name=="i":
			if string:
				if string[-1]==".":
					string=string.strip('.')
				#ignore string that maybe options
				if string.startswith("-"):
					continue
				old=dict.get(arg_name)
				if old!=None: 
					if old.find(string)==-1:
						string=old+string+","
					else:
						string=old
				else:
					string=string+","
				if arg_name not in string:
					item='{arg_name:string}'
					item_arg=eval(item)
					dict.update(item_arg)            
		#special format,handling filename and numbers 
		else:
			old=dict.get(arg_name)
			potential=""
			# extract file path 
			expr=r'/[/\w\.]+'
			m=re.findall(expr,str(pchild.string))
			ms=set(m)
			if ms:
				for i in ms:
					if old:
						if i in old:
							continue
					potential=potential+i+","
			# extract numbers
			int_expr=r'\b\d+\b'
			int_m=re.findall(int_expr,pchild.string)
			ints=set(int_m)
			if ints:
				for i in ints:
					if old:
						if i in old:
							continue
					potential=potential+i+","
			# extract ip
			ip = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", pchild.string)
			ips=set(ip)
			if ips:
				for i in ips:
					if old:
						if i in old:
							continue
					potential=potential+i+","

			if potential:
				new=""
				old=dict.get(arg_name)
				if old!=None: 
					new=old+potential
				else:
					new=potential
				if arg_name!=string:
					item='{arg_name:new}'
					item_arg=eval(item)
					dict.update(item_arg) 

#extract examples       
def getExamples(h,cmd):
	examples=[]
	content=getSectionContent(h)
	local_soup=BeautifulSoup(content,'html.parser')
	temps=local_soup.find_all("p")
	for t in temps:
		for pchild in t.children:
			#example is bold
			b_string=pchild.string
			if b_string==None:
				continue
			if pchild.name=="b":
				# print(f"in example:chile is bold! {b_string}")
				if '#' in b_string or '$' in b_string:
					index=b_string.find('#')
					if index==-1:
						index=b_string.find('$')
					if index!=-1 and '$$' not in b_string:
						b_string=b_string[index+1:]
				string_encode = b_string.encode("ascii", "ignore")
				string_decode = string_encode.decode()
				b_string=string_decode
				examples.append(b_string)
			else:
				#root@machine:~#
				if '#' in b_string or '$' in b_string:
					index=b_string.find('#')
					if index==-1:
						index=b_string.find('$')
					exp=b_string[index+1:]
					if '@' in b_string:
						# print(b_string)
						examples.append(exp)
	if not examples:
	#example is not bold,see if first word is cmd 
		for t in temps:
			tmp=t.text
			fword=getFirstString(t)
			if fword==cmd:
				examples.append(tmp)
			elif "#" in fword or "$" in fword:
				string_encode = tmp.encode("ascii", "ignore")
				string_decode = string_encode.decode()
				tmp=string_decode
				index=tmp.find('#')
				if index==-1:
					index=tmp.find('$')
				exp=tmp[index+1:]
				examples.append(exp)
	return examples

#extract options and argument from <p>. 
#standard is options should be bold, argument should be italic. return "option:arg"
#-l loglevel j
def extractfromP(child,dup_opts,level):
	# debug_flag=0
	pre_parent=None
	opt_arg="" 
	res=""
	first=0
	for pchild in child.children:
		#options may not be bold. try first element in <p>,begining with '-'
		#one option may contain several children
		if pchild.text==None:
			continue
		b_string=pchild.text.strip().replace("\n"," ")
		if b_string=="":
			continue
		else:
			first=first+1
		if b_string.startswith("-") or level==1:
			if pchild.parent is pre_parent:
				continue
			#in order to filter options, assume opt is the first element in p,it should be the first element except '\n'
			#if pchild.previous_element.name!="p":
			if first!=1:
				continue
			if level==1 :
				if pchild.name!="b" and pchild.name !='i': 
					continue
			if b_string.find(" ")!=-1:
				opt_arg=b_string.split(" ")[1]
				if opt_arg.startswith("-"):
					dup_opts.append(opt_arg)
					opt_arg=""
				b_string=b_string.split(" ")[0]
			index=b_string.find(",")
			if index!=-1:
				b_string=b_string[0:index]
				dupopt=b_string[index:]
				if dupopt:
					dup_opts.append(dupopt)
			else:
				index=b_string.find("|")
				if index!=-1:
					b_string=b_string[0:index]
			#extract argument in '<>'
			if "<" in b_string:
				index1=b_string.find("<")
				opt_args=re.findall(r'[<](.*?)[>]',b_string)
				if len(opt_args)==1:
					opt_arg=opt_args[0]
				b_string=b_string[0:index1]
			pre_parent=pchild #??
			for ie in pchild.next_siblings:
				if ie.string==None:
					continue
				if ie.name=="i":
					opt_arg=ie.string.replace("\n"," ")
					if "<" in opt_arg:
						opt_arg=opt_arg.replace("<","")
						opt_arg=opt_arg.replace(">","")
					break
			res=b_string+":"+opt_arg
	return res

#supplement optdict
def ValidateOptions(optdict):
	for sopt in OptinSyno:
		optarginSyno=OptinSyno[sopt]
		if sopt not in optdict:
			if not len(sopt)>2: #-d?h should not be added to opt_dict
				optdict.update({sopt:optarginSyno})
		else:
			optarg=optdict[sopt]
			if optarginSyno not in optarg:
				optdict.update({sopt:optarginSyno})
				print(f"udate opt:{sopt}:{optarg} to {optarginSyno}")

#resolve a manual section by section
def resolve_cmd(html,outf):
	with open(html,"r") as f:
		cur_cmd=html.split("/")[-1]
		cur_cmd=cur_cmd.split(".html")[0]
		global cmd2parse
		cmd2parse=cur_cmd                 
		print("*****resolve begin*****"+cur_cmd)
		options_dict={}
		#globel dict <arg:value>
		arg_dict={}
		dup_opts=[]
		content=f.read()
		required_all=[] 
		soup=BeautifulSoup(content,'html.parser')	
		name_content=""
		heads=soup.find_all("h2")
		opt_flag=False
		opt_sec=False
		options=None
		descript=None
		examples=[]
		for h in heads:
			# extract required arg and command in synposis
			if "NAME" in h.text:
				name_content=""
				for child in h.next_siblings:
					if child.string!=None:
						name_content=child.string.strip().split(' ')[0].strip()
						if name_content:
							break
						if child.name=="h2":
							print("name section end")
							if name_content=="":
								print("Name not resolved")
					
			elif "SYNOPSIS" in h.text:
				required_all= getRequiredfromSyno(h,cur_cmd)
				opt_flag=hasOptinSyno(h)
				if required_all:
					required_all= handleOr(required_all,cur_cmd)
					duplicate=True
					for req in required_all:
						if cur_cmd  in req:
							duplicate=False
							break
					if duplicate:
						duplicatecmd.append(cur_cmd)
                 
			elif 'SYNTAX' in h.text:
				if required_all:
					continue
				else:
					required_all= getRequiredfromSyno(h,cur_cmd)
					opt_flag=hasOptinSyno(h)
					if required_all:
						required_all= handleOr(required_all,cur_cmd)
						duplicate=True
						for req in required_all:
							if cur_cmd  in req:
								duplicate=False
								break
						if duplicate:
							duplicatecmd.append(cur_cmd)
			elif "DESCRIPTION" in h.text:
				descript=h
				#getOptins(descript,options_dict,arg_dict)              
			# extract opt and arg from options
			elif "OPTIONS" in h.text:
				opt_sec=True
				options=h
				getOptins(h,options_dict,arg_dict,dup_opts,0)
				# print(f"getoptions:{options_dict}")
			elif "PARAMETERS" in h.text:
				if options_dict:
					continue
				else:
					opt_sec=True
					options=h
					getOptins(h,options_dict,arg_dict,dup_opts,0)
					print(f"getoptions:{options_dict}")
			elif "COMMAND" in h.text:
				if "COMMAND LINE" in h.text:
					opt_sec=True
					options=h
					getOptins(h,options_dict,arg_dict,dup_opts,0)
				else:
					getCommands(h,options_dict,arg_dict)

			elif "EXAMPLE" in h.text:
				tmp_examples=getExamples(h,cur_cmd)
				if len(tmp_examples)>1:
					examples=examples+tmp_examples
		if not bool(options_dict):
			if opt_sec:
				print("didnt resolve option section,consider options startswithout -")
				getOptins(options,options_dict,arg_dict,dup_opts,1)
			if opt_flag:
				if descript!=None:
					getOptins(descript,options_dict,arg_dict,dup_opts,0)
		#optimize with res from getopt.h remove to the end of options analyze
		if not bool(options_dict) and libres_dict.get(cur_cmd)!=None:
			print("manual resolve is null , try getopt res!")
			checkOptions(cur_cmd,options_dict,dup_opts)
		if len(OptinSyno)>0 :#and len(options_dict)==0:
			ValidateOptions(options_dict)	   
		if not required_all:
			synopsiserr.add(cur_cmd)	
			required_all.append(cur_cmd) 		
		f = open(outf,'a+')
		f.write("*********resolving "+cur_cmd+"******\n")
		json.dump(required_all,f)
		f.write("\n")
		json.dump(options_dict,f)
		f.write("\n")
		json.dump(arg_dict,f)
		f.write("\n")
		json.dump(examples,f)
		f.write("\n")
		if options_dict:
			for o in options_dict:
				tmparg=options_dict[o]
				if tmparg:
					tmparg=tmparg.replace("<","")
					tmparg=tmparg.replace(">","")
					if tmparg not in opts_args:
						opts_args.append(tmparg) 
		if arg_dict:
			for arg in arg_dict:
				item={arg:arg_dict[arg]}
				args_dict.update(item) 
				if arg in cur_args:
					cur_args.remove(arg)    
		f.close()

# we put the intermediate results in the out dir
if __name__ == "__main__":
	#handle results of libgetopt 
	if os.path.exists('output/getopt-out.txt'):
		with open("output/getopt-out.txt","r",encoding="utf-8") as libres:
			content=libres.readlines()
			for line in content:
				if "short opts:" in line:
					handleshortopt(line)
				elif "long opts:" in line:
					handlelongopt(line)
	outfile="output/man-res.txt"
	#rely on manualpages obtained by 1_getmanuals.py
	root_dir='man-htmls'
	if os.path.exists(outfile):
		os.remove(outfile)
	html_list = os.listdir(root_dir)
	unresolved=0
	cmd2parse=""
	hasOr=set() 
	targetcmds=[] 
	duplicatecmd=[] 
	noman=[]
	cmdargs={}
	argnum=len(sys.argv)
	if argnum!=2:
		print("get manual error: wrong argument number! Expect 1 file name!")
		sys.exit(1)
	tarfile=sys.argv[1]
	with open(tarfile,'r')as f:
		c=0
		for line in f.readlines():
			if "(8)" in line:
			# c=c+1
				idx=line.index("(8)")
				command=line[0:idx]
			command=line.strip()
			targetcmds.append(command)
	for target in targetcmds:
		path=os.path.join(root_dir,target+".html")
		OptinSyno={}
		if os.path.isfile(path):
			size = os.path.getsize(path)
			if size==0:
				unresolved=unresolved+1
				noman.append(target)
			else:
				cur_args=[]
				resolve_cmd(path,outfile)
				if cur_args:
					cmdargs.update({target:cur_args})
	if unresolved>0:
		print("man is null can not resolve:"+str(unresolved))
	if len(duplicatecmd)>0:
		print(f"potential duplicate cmds are:{duplicatecmd}")
	#print(f"manual effort is needed {manual}")
	if len(hasOr)>0:
		print(f"hasor:{hasOr}") #verify manually if there is a or between options
	if len(synopsiserr)>0:
		print(f"can not analyze command in synopsis {synopsiserr}")
	f=open(outfile,'a')
	f.write("********* resolving end ******\n")
	f.write("*********opt argu******\n")
	json.dump(opts_args,f)      
	f.write("\n")
	f.write("*********argu and value******\n")
	json.dump(args_dict,f)
	f.write("\n")
	f.write("********total cmds are **************\n")
	for target in targetcmds:
		f.write(target)
		f.write('\n')
	f.write("*********synopsis need manual effort*******\n")
	manual_list=list(manual)
	json.dump(manual_list,f)
	f.write("\n")
	f.write("*********has or*******\n")
	hasOr_list=list(hasOr)
	json.dump(hasOr_list,f)
	f.write("\n")
	f.write("*********can not analyze synopsis*******\n")
	synopsis_list=list(synopsiserr)
	json.dump(synopsis_list,f)
	f.write("\n")
	f.write("***********manual page is empty**********\n")
	json.dump(noman,f)
	f.write("\n")
	f.write("***********cmd and undefined args**********\n")
	json.dump(cmdargs,f)
	f.close()
	# print("************* [3]:resolve manual finished! ************")


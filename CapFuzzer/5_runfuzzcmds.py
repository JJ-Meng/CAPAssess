#python 5_xx.py cmdlist 
#In file cmdlist is the commands to fuzz.
#input: fuzzcmds dir
#output: output/results dir and a total results res.csv, 
#contains 3 subdirs for detiled informations of each command sepcmd-root/ sepcmd-normal/ sepcmd-normal-null, each dir contains
from cmath import inf
import csv
from itertools import count
import json
from locale import currency
from plistlib import UID
from random import random
import shutil
from signal import SIGKILL
import subprocess
import os
import sys
import random
import datetime
import pandas as pd
import cProfile
import pstats

# performance analysis--not enabled
def do_cprofile(filename):
    """
    Decorator for function profiling.
    """
    def wrapper(func):
        def profiled_func(*args, **kwargs):
            # Flag for do profiling or not.
            DO_PROF = os.getenv("PROFILING")
            if DO_PROF:
                profile = cProfile.Profile()
                profile.enable()
                result = func(*args, **kwargs)
                profile.disable()
                # Sort stat by internal time.
                sortby = "tottime"
                ps = pstats.Stats(profile).sort_stats(sortby)
                ps.dump_stats(filename)
            else:
                result = func(*args, **kwargs)
            return result
        return profiled_func
    return wrapper

def timeshow(func):
    from time import time
    def newfunc(*arg, **kw):
        t1 = time()
        res = func(*arg, **kw)
        t2 = time()
        print(f"{func.__name__: >10} : {t2-t1:.6f} sec")
        return res
    return newfunc

#commands in dangercmd can be fuzzed by ordinary privilege only, executing with root privilege may result in system crash
dangercmd=["crash","vigr",'halt','poweroff','shutdown','reboot','kexec',"vipw","start-stop-daemon","umount","telinit","ifconfig","chmem","lvm"
,"kill","skill","pkill","killall","bash","fusermount3",'telinit']
uidonlycmd=set()
uidcmdanderrs={}
#user level check cap
cmdgetcap=set()
cmdsetcap=set()
cmdusecap=set()
getcapfuzzcmds=[]
setcapfuzzcmds=[]
usecapfuzzcmds=[]
#manualname-realname inconsist
manual2realname={"30-systemd-environment-d-generator": "/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator",
"autofs": "/etc/init.d/autofs", "ip-addrlabel": "ip addrlabel", "ip-fou": "ip fou", "ip-maddress": "ip maddress", "ip-monitor": "ip monitor",
 "ip-mroute": "ip mroute", "ip-netconf": "ip netconf", "ip-ntable": "ip ntable", "ip-sr": "ip sr", "ip-token": "ip token",
  "ip-vrf": "ip vrf", "iptables-extensions": "iptables extensions", "lvm-fullreport": "lvm fullreport", 
  "lvm-lvpoll": "lvm lvpoll", "lvm2-activation-generator": "/usr/lib/systemd/system-generators/lvm2-activation-generator", 
  "mkinitrd-suse": "mkinitrd", "pppd-radattr": "pppd", "pppd-radius": "pppd", "rpm-misc": "rpm", 
  "semanage-port": "semanage port", "semanage-permissive": "semanage permissive", "semanage-login": "semanage login", 
  "semanage-dontaudit": "semanage dontaudit", "semanage-module": "semanage module", "sepolicy-network": "sepolicy network", 
  "semanage-ibendport": "semanage ibendport", "sepolicy-interface": "sepolicy interface", "semanage-import": "semanage import", 
  "semanage-node": "semanage node", "semanage-user": "semanage user", "sepolicy-communicate": "sepolicy communicate", 
  "semanage-interface": "semanage interface", "sepolicy-gui": "sepolicy gui", "semanage-export": "semanage export", 
  "sepolicy-manpage": "sepolicy manpage", "semanage-boolean": "semanage boolean", "semanage-ibpkey": "semanage ibpkey", 
  "sepolicy-booleans": "sepolicy booleans", "semanage-fcontext": "semanage fcontext", "sepolicy-transition": "sepolicy transition",
  "arptables-nft-save":"arptables-save","ip-route":"ip route","ip-xfrm":"ip xfrm","ip-mptcp":"ip mptcp","ip-address":"ip address","ip-tunnel":"ip tunnel"
  ,"devlink-trap":"devlink trap","devlink-health":"devlink health","rdma-statistic":"rdma statistic","rdma-dev":"rdma dev",
   "ip-nexthop":"ip nexthop", "devlink-monitor":"devlink monitor", "devlink-dev":"devlink dev", "devlink-region":"devlink region", "ip-netns":"ip netns", "ip-link":"ip link", 
   "devlink-port":"devlink port", "devlink-resource":"devlink resource", "ip-tcp_metrics":"ip tcp_metrics", "devlink-dpipe":"devlink dpipe", "ip-l2tp":"ip l2tp", "ip-neighbour":"ip neighbour",
   "ip-macsec":"ip macsec", "rdma-link":"rdma link", "devlink-sb":"devlink sb", "ip-rule":"ip rule", "rdma-resource":"rdma resource", "rdma-system":"rdma system",
   "ebtable-nft":"ebtables" }


res=[] #potential privilege cmd and outputs
err="" #log err message
#cmd:fuzz cmds
cmd_dict={}

#get all decendant process
def findalldespid_capable(pid):
	outs=[]
	findchildpid="dmesg | grep '(#cap_capable# realparentpid:'"+str(pid)
	subpc = subprocess.run(findchildpid,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,shell=True,text=True)
	if subpc.stdout.strip()!="":
		outchild=subpc.stdout.strip().split('\n')
	else:
		return outs
	#add child process cap log
	if len(outchild)>0:
		outs.extend(outchild)
	#get all child process pid
	currentpids=set()
	for line in outchild:
		current=line.split("current:")[1]
		index=current.find("(realparentpid")
		currentpid=current[0:index-1]
		currentpids.add(currentpid)
	#get grandchildren proces cap log
	for cpid in currentpids:
		childouts=findalldespid_capable(cpid)
		if len(childouts)>0:
			outs.extend(childouts)
	return outs
#remove bash|capsh
import re
bash_pat = re.compile(r'command:((bash)|(capsh))\b')
remove_bash_func = lambda s: not bool(bash_pat.search(s))
#def getcaps(pid,cmd,output):
#@timeshow
def getcaps(pid,cmd,dict,subpriv):
	#journald 138
	# findpid="dmesg | grep '#cap_capable# current:139'"
	findpid="dmesg | grep '#cap_capable# current:'"+str(pid)
	subp = subprocess.run(findpid,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,shell=True,text=True)
	out=subp.stdout.strip().split('\n')
	out = list(filter(remove_bash_func,out))
	childouts=findalldespid_capable(pid)
	if len(childouts)>0:
		out.extend(childouts)
	caps=[]#all capabilities being checked
	caps_unique=set()#unique set
	cmdres=""
	if not out:
		return False
	for o in out:
		if o=="":
			continue
		strcap=o.split(" ")[-1]
		caps.append(strcap)
		caps_unique.add(strcap)
	
	for cap in caps_unique:
		cap_num=caps.count(cap)
		#cap8 -123
		if cap=="8" and subpriv=="root-null":
			cap_num=cap_num-123
		if cap=="8" and subpriv=="normal":
			# print(f"check cap8 for {cap_num} times!!!!")
			cap_num=cap_num-88
		if cap=="8" and subpriv== "normal-null":
			# print(f"check cap8 for {cap_num} times!!!!")
			cap_num=cap_num-4

		if cap=="6" and "normal" in subpriv:
			# print(f"check cap6 for {cap_num} times!!!!")
			cap_num=cap_num-2

		if cap=="7" and "normal" in subpriv:
			# print(f"check cap7 for {cap_num} times!!!!")
			cap_num=cap_num-1
		#add for cap1
		if cap=="8" and subpriv=='root':
			cap_num=cap_num-3
		if cap_num<=0:
			continue
		cmdres=cmdres+"check cap "+cap+" for "+str(cap_num)+" times,"
	if cmdres:
		result={cmd:cmdres}
		dict.update(result)
		return True
	return False

#level0:uid0+all cap    level1:uid0+14cap   level3:uid0+no cap
#level4:uid normal+all  
# def runcmds(cmdspath,outfp,targets):
#@timeshow
def runcmds(cmd,cmds,outfp,userset,subpriv):
	# cmdshaschanged=False
	#fuzzcmd:pid
	cmdpid={}
	pids=[]
	result_dict={}
	# priv_count=0
	# total_count=0
	stdout_dict={}
	stderr_dict={}
	ret_dict={}
	realname=""
	if cmd in manual2realname:
		realname=manual2realname[cmd]
	else:
		realname=cmd
	for tcmd in cmds:
		#root 14
		# cmdall="capsh --caps=CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FSETID,CAP_FOWNER,CAP_MKNOD,CAP_NET_RAW,CAP_SETGID,CAP_SETUID,CAP_SETFCAP,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_SYS_CHROOT,CAP_KILL,CAP_AUDIT_WRITE+eip -- -c "			
		if subpriv=="root-null":
			cmdall="capsh --drop=all -- -c"
			cmd_list=cmdall.split()
			cmd_list.append(tcmd)
		#root->normal 
		elif subpriv=="normal":
			cmdall="capsh --keep=1 --user=test --inh=all --addamb=all -- -c"
			# cmdall="capsh --keep=1 --user=test --inh=0,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40 --addamb=0,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40 -- -c"
			cmd_list=cmdall.split()
			cmd_list.append(tcmd)
		elif subpriv=="normal-null":
			cmdall="capsh --user=test -- -c"
			cmd_list=cmdall.split()
			cmd_list.append(tcmd)
			# cmd_list=tcmd.split()
		elif subpriv=="root":
			#add for cap1 test
			# cmdall='capsh --drop=1 -- -c '
			# cmd_list=cmdall.split()
			# cmd_list.append(tcmd)
			cmd_list=tcmd.split()
		outs=""
		errs=""
		retcode=""
		timeout=False
		# cmd_list=['capsh', '--caps=CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FSETID,CAP_FOWNER,CAP_MKNOD,CAP_NET_RAW,CAP_SETGID,CAP_SETUID,CAP_SETFCAP,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_SYS_CHROOT,CAP_KILL,CAP_AUDIT_WRITE+eip', '--', '-c', 'accton on']
		try:
			global total			
			total=total+1
			subp = subprocess.Popen(cmd_list,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
			pid=subp.pid
			print(f"cmd:{tcmd} pid is {pid}")
			# outs, errs=subp.communicate(timeout=0.2)
			subp.wait(timeout=0.2)
			retcode=str(subp.returncode)

		except subprocess.TimeoutExpired:
			global timeout_count
			timeout_count=timeout_count+1
			os.system("sudo kill %s" % (pid))
			print(f'!timeout! cmd: {tcmd}')
			#outs, errs=subp.communicate()
			#continue
		except UnicodeDecodeError:
			# subp.kill()
			print(f"some encoding fault!")
			continue
		except FileNotFoundError:
			# subp.kill()
			print(f"file not found!")
			continue
		except PermissionError:
			print(f"permission error {tcmd}")
			uidonlycmd.add(cmd)
			uidcmdanderrs.update({tcmd:"permission error exception"})
			continue
		#check cap in log 
		if realname in tcmd:
			getcaps(pid,tcmd,result_dict,subpriv)
	if len(result_dict)>0:
		f = open(outfp,'w',encoding="UTF8")
		for item in result_dict:
			f.write(f"{item}:{result_dict[item]}\n")
			f.write('\n')
		f.close()

#use for manual prepared fuzz commands
def prepare_dict(cmdfile):
	cmddict={}
	with open(cmdfile,'r')as f:
		content=f.readlines()
		lastcmd=""
		fuzzcmd=[]
		for line in content:
			line=line.strip()
			index=line.find(" ")
			if line=="":
				print("jump empty line")
				continue
			curcmd=""
			fuzz=line
			if index!=-1:
				curcmd=line.split(' ',1)[0]
			else:
				curcmd=line
			if "/" in curcmd:
				index=curcmd.rfind("/")
				curcmd=curcmd[index+1:]
			if lastcmd:
				if curcmd==lastcmd:
					fuzzcmd.append(fuzz)
				else:
					#new cmd
					cmddict.update({lastcmd:fuzzcmd})
					fuzzcmd=[]
					lastcmd=curcmd
			else:#first time
				lastcmd=curcmd
				fuzzcmd.append(fuzz)
				print(f"first cmd is {curcmd}")
		cmddict.update({lastcmd:fuzzcmd})
	return cmddict

#input internal file and return capability(unsorted)
def getfinalres(interfp):
	caps=[]
	if not os.path.exists(interfp):
		return caps
	with open(interfp,'r') as f:
		content=f.readlines()
	# i=0
	# cmd_caps_dict={}
	for line in content:
		# i=i+1
		if ':check cap' in line:
			# cmd_origin=""
			tmps=line.split('check cap ')
			j=0
			for t in tmps:
				j=j+1
				if j==1:
					continue
				# print(t)
				cap=t.split(' ')[0]
				cap_int=int(cap)
				if cap_int not in caps:
					caps.append(cap_int)
	return caps

#new
def runfuzzcmds(cmd,cmds,userset,sub_priv):
	cmd_caps={}
	if sub_priv=="root":
		infile="output/results/sepcmd-root/"+cmd+"-i.txt"
	elif sub_priv=="root-null":
		infile="output/results/sepcmd-root-null/"+cmd+"-i.txt"
	elif sub_priv=="normal":
		infile="output/results/sepcmd-normal/"+cmd+"-i.txt"
	else:
		infile="output/results/sepcmd-normal-null/"+cmd+"-i.txt"
	runcmds(cmd,cmds,infile,userset,sub_priv) #execute
	caps_final=getfinalres(infile) #analyze
	cmd_caps.update({cmd:caps_final})
	return cmd_caps

def RunFuzzAsNormal(tarcmd,cmds,userset):
	cmdupperbound_normal=[]
	#round1 normal-null
	cmd_caps_normal=runfuzzcmds(tarcmd,cmds,userset,"normal-null")
	normal_null.update(cmd_caps_normal)
	if cmd_caps_normal:
		print(f"normal-null:{cmd_caps_normal}")
		normal_caps=cmd_caps_normal[tarcmd]
		cmdupperbound_normal.extend(normal_caps)
	if tarcmd not in dangercmd:
		#round2 normal allcap
		cmd_caps=runfuzzcmds(tarcmd,cmds,userset,"normal")
		normal_all.update(cmd_caps)
		if cmd_caps:
			print(f"normal-allcap:{cmd_caps}")
			cmd_caps_allcap=cmd_caps[tarcmd]
			for cap in cmd_caps_allcap:
				if cap not in cmdupperbound_normal:
					cmdupperbound_normal.append(cap)
	else:
		normal_all.update({tarcmd:["BL"]})
	print(f"upperbound {cmdupperbound_normal}")
	return cmdupperbound_normal


def RunFuzzAsRoot(tarcmd,cmds,userset):
	cmdupperbound_root=[]
	cmd_caps_null={}
	if tarcmd not in dangercmd: 
		cmd_caps_null=runfuzzcmds(tarcmd,cmds,userset,"root-null")
		root_null.update(cmd_caps_null)
	else:
		root_null.update({tarcmd:['BL']})
	if cmd_caps_null:
		normal_caps=cmd_caps_null[tarcmd]
		cmdupperbound_root.extend(normal_caps)
	if tarcmd not in dangercmd:
		cmd_caps=runfuzzcmds(tarcmd,cmds,userset,"root")
		root.update(cmd_caps)
		if cmd_caps:
			cmd_caps_allcap=cmd_caps[tarcmd]
			for cap in cmd_caps_allcap:
				if cap not in cmdupperbound_root:
					cmdupperbound_root.append(cap)
	else:
		root.update({tarcmd:["BL"]})
	# print(f"upperbound {cmdupperbound_root}")
	return cmdupperbound_root	

def mkresdirs(cur_dir):
	if not os.path.exists(cur_dir):
		os.mkdir(cur_dir)
	else:
		shutil.rmtree(cur_dir)
		os.mkdir(cur_dir)

def prepare_dirs():
	cur_dir_root="output/results/sepcmd-root/"
	if os.path.exists(cur_dir_root):
		shutil.rmtree(cur_dir_root)
	mkresdirs(cur_dir_root)
	cur_dir_normal="output/results/sepcmd-normal/"
	if os.path.exists(cur_dir_normal):
		shutil.rmtree(cur_dir_normal)
	mkresdirs(cur_dir_normal)
	cur_dir_normal_null="output/results/sepcmd-normal-null/"
	if os.path.exists(cur_dir_normal_null):
		shutil.rmtree(cur_dir_normal_null)
	mkresdirs(cur_dir_normal_null)
	cur_dir_root_null="output/results/sepcmd-root-null/"
	if os.path.exists(cur_dir_root_null):
		shutil.rmtree(cur_dir_root_null)
	mkresdirs(cur_dir_root_null)

def getcmds_dict(targets):
	cmd_dict={}
	tardict={}
	cannotfuzz=[]
	dict_file=open('output/fuzzcmds/cmdsdict.txt','r')
	dict_content=""
	for line in dict_file:
		if "***********" in line:
			break
		dict_content=dict_content+line
	cmd_dict=json.loads(dict_content)
	for target in targets:
		if target in cmd_dict:
			tardict.update({target:cmd_dict[target]})
		else:
			cannotfuzz.append(target)
			print(f"err:cmd {target} dose not have fuzz cmd!")
	# print(f"targetdict {tardict}")
	return tardict,cannotfuzz

def getUIcmdfromfile(file):
	UIcmd=[]
	if not os.path.exists(file):
		return UIcmd
	with open(file,'r')as fUI:
		content=fUI.read()
		UIcmd=json.loads(content)
	return UIcmd

if __name__ == "__main__":
	if not os.path.exists('output/results'):
		os.mkdir('output/results')
	#global var
	timeout_count=0
	total=0
	#result dict
	normal_null={}
	normal_all={}
	root={}
	root_null={}
	# sub_priv=sys.argv[1]
	starttime = datetime.datetime.now()
	userset={}#cmd:tcmd
	roottargets=set()
	cmdscaps_final={}
	#get cmds_dict {cmd:fuzz cmds}
	tardict={}
	cannotfuzz=[]
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
	tardict,cannotfuzz=getcmds_dict(targetsnew)
	# tardict=prepare_dict("/home/test/scripts/output/fuzzcmds/cmdsdict.txt")
	prepare_dirs()
	UIcmd=[]
	UIcmd=getUIcmdfromfile('output/fuzzcmds/UIcmd.txt')
	runcmd=[]
	for tarcmd in tardict:
		runcmd.append(tarcmd)
	for tarcmd in tardict:
		cmdupperbound_normal=[]
		if tarcmd in UIcmd:
			normal_null.update({tarcmd:['UI']})
			normal_all.update({tarcmd:['UI']})
			cmdscaps_final.update({tarcmd:['UI']})
			continue		
		print(f"target cmd is {tarcmd}")
		fuzzcmds=tardict[tarcmd]
		# record run count when use filecap
		cmdupperbound_normal= RunFuzzAsNormal(tarcmd,fuzzcmds,userset)	
		cmdscaps_final.update({tarcmd:cmdupperbound_normal})
	outfile='output/results/sepcmd-normal/total.txt'
	with open(outfile,'w') as outf:
		json.dump(cmdscaps_final,outf)

	print(f"**********************Run as normal user finished********************")		
	cmdscaps_final={}	
	for tarcmd in tardict:
		cmdupperbound_root=[]
		if tarcmd in UIcmd:
			root_null.update({tarcmd:['UI']})
			root.update({tarcmd:['UI']})
			cmdscaps_final.update({tarcmd:['UI']})
			continue	
		fuzzcmds=tardict[tarcmd]		
		cmdupperbound_root=RunFuzzAsRoot(tarcmd,fuzzcmds,userset)
		cmdscaps_final.update({tarcmd:cmdupperbound_root})
	outfile='output/results/sepcmd-root/total.txt'
	with open(outfile,'w') as outf:
		json.dump(cmdscaps_final,outf)
	print(f"**********************Run as root user finished********************")
	#write res to csv
	print(f"normal {normal_null}")
	print(f"normal-allcap {normal_all}")
	print(f"root null {root_null}")
	print(f"root {root}")
	normal_null_caps=[]
	normal_all_caps=[]
	root_caps=[]
	root_null_caps=[]
	for tar in tardict:
		normal_null_caps.append(normal_null[tar])
		normal_all_caps.append(normal_all[tar])
		root_caps.append(root[tar])
		root_null_caps.append(root_null[tar])
	dataframe=pd.DataFrame({'command':runcmd,'normal':normal_null_caps,'normal-allcap':normal_all_caps,'root-null':root_null_caps,'root':root_caps})
	dataframe.to_csv(r"output/results/4res.csv", index=False)
	print(f"fuzz cmds: {total}, time out cmds {timeout_count}")
	print('------------------------------------------')
	endtime = datetime.datetime.now()
	print(f"start at {starttime},end at {endtime}")
	# min=(endtime - starttime).seconds/60
	delt=endtime - starttime
	sec=delt.total_seconds()
	print (f"use {sec}")
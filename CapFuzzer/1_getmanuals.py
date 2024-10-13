#install and collect manuals
#usage: python 1_getmanuals.py cmdlist
#cmdlist is a file type argument specifying the commands to be fuzzed.
#output: manuals in dir man-htmls
import os
import subprocess
import re
import sys 

def addcmd(command):
	res='man -Thtml '+command+' > man-htmls/'+command+'.html'
	return res

def cmd(command):
    subp = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out=subp.stdout.readlines()
    err=subp.stderr.readlines()
    return err,out

def installcmd(command):
	err=cmd(command)
	howtoinstall="wget https://command-not-found.com/"+command+" -O 1.html"
	print(howtoinstall)
	errs,outs=cmd(howtoinstall)
	print(errs)
	grep='grep "apt-get install" 1.html'
	err,out=cmd(grep)
	print(out)
	out_str=""
	for i in out:
		out_str=out_str+i.decode("utf-8")
	print(out_str)
	installcmd=""
	for o in out_str.splitlines():
		if "<" in out_str:
			installcmd=re.sub('\<.*?\>','',o)
		if installcmd:
			break
	if installcmd:
		installcmd="sudo "+installcmd
	else:
		print(f"err in get install command {command}")
		return 
	print("installcmd:"+installcmd)
	err,out=cmd(installcmd)
	print("err:")
	print(err)
	print("out:")
	print(out)
 
if __name__ == '__main__':
	failed_install=[]
	no_man=[]
	argnum=len(sys.argv)
	if argnum!=2:
		print("get manual error: wrong argument number! Expect 1 file name!")
		sys.exit(1)
	tarfile=sys.argv[1]
	if not os.path.exists('man-htmls'):
		os.makedirs('man-htmls')
	with open(tarfile,'r')as f:
		for line in f.readlines():
			command=line.strip()
			cmd_all="which "+command
			_s=""#command path
			subp = subprocess.run(cmd_all,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
			_s=subp.stdout.strip()
			if _s=="":
				installcmd(command)
			cmd_all="which "+command
			_s=""#command path
			subp = subprocess.run(cmd_all,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
			_s=subp.stdout.strip()
			if _s=="":
				failed_install.append(command)	
				continue
			cur_cmd=addcmd(command)
			s=""#command path
			subp = subprocess.run(cur_cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
			err=subp.stderr.strip().splitlines()
			for e in err:						
				if "No manual entry" in str(e):
					print(f"can not get manual for command {command}")
					no_man.append(command)
					
	#print("************* [1]:get manual finished! ************")	
	if len(failed_install)!=0:
		print(f"{len(failed_install)} commands fail to install")
		print(f"failed install cmds:{failed_install}")
	if len(no_man)!=0:
		print(f"commands without manual:{no_man}")
	# 	exit(1)
	# else:
	# 	exit(0)


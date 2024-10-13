#install command from argv[1], a file type argument specifying commands to install
import subprocess
import os
import re
import sys
def installcmd(command):
	res=False
	howtoinstall="wget https://command-not-found.com/"+command+" -O 1.html"
	print(howtoinstall)
	subhow = subprocess.run(howtoinstall,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	grep='grep "apt-get install" 1.html'
	subgrep = subprocess.run(grep,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
	out=subgrep.stdout.strip()
	err=subgrep.stderr.split('\n')
	print(out)
	installcmd=""
	for o in out.splitlines():
		if "<" in o:
			installcmd=re.sub('\<.*?\>','',o)
		if installcmd:
			break
	if installcmd:
		installcmd = installcmd + " -y"
	else:
		print("err in get install command")
		return
	#print("installcmd:"+installcmd)
	install_res=os.system(installcmd)
	if install_res==0:
		res=True
		print(command+"install successed")
	else:
		print(command+"install err is "+str(install_res))
	return res 	

if __name__ == '__main__':
	hascmd=0
	install=0
	failtoinstall=[]
	argnum=len(sys.argv)
	if argnum!=2:
		print("install cmd error: wrong argument number!")
		sys.exit(1)
	tarfile=sys.argv[1]
	with open(tarfile,'r')as f:
		c=0
		for line in f.readlines():
			command=line.strip()
			cmd_all="which "+command
			c=c+1
			s=""#command path
			subp = subprocess.run(cmd_all,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
			s=subp.stdout.strip()
			#err=subp.stderr.readlines()
			if s:
				hascmd=hascmd+1						
			else:
				print(f"#cmd to install:{command}")
				res=installcmd(command)
				if res:
					print("#install success")
					install=install+1
				else:
					failtoinstall.append(command)
	print(f"{hascmd} cmd is already on VM")
	print(f"{install} cmd is installed")
	print(f"failed to install {failtoinstall}")
	#print("************* [0]:install cmd finished! ************")
	if len(failtoinstall)!=0:
		exit(1)
	else:
		exit(0)
	

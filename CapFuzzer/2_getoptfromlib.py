# collect opts from getopt library, need install and instrument glibc beforehand
#usage: python 2_getoptfromlib.py cmdlist.txt
#output:getopt-out.txt
import subprocess
import os
import re
import sys
def addcmdwithlibc(command):
	command=command.replace("\n","")
	res='/home/test/build-glibc/testrun.sh '+command+' -h'
	return res
def cmd(command):
	subp = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	out=subp.stdout.readlines()
	err=subp.stderr.readlines()
	return err,out
def extractopts(line):
	line=line.strip()
	index=line.find("gblic2.35 getopt:")
	opts=""
	if index!=-1:
		opts=line[index+17:]
	index1=line.find("gblic2.35 longopt:")
	if index1!=-1:
		opts=line[index1+18:]
	return opts
if __name__ == '__main__':
	uninstall=0
	hasopt=0
	noopt=0
	opt_cmd=""
	uninstall_cmd=""
	no_opt=""
	outfile="output/getopt-out.txt"
	argnum=len(sys.argv)
	if argnum!=2:
		print("get manual error: wrong argument number! Expect 1 file name!")
		sys.exit(1)
	tarfile=sys.argv[1]
	if not os.path.exists('output'):
		os.makedirs('output')
	with open(tarfile,'r')as f:
		for line in f.readlines():
			command=line.strip()
			if '-' in command:
				command=command.replace('-',' ')
			cmd_all="which "+command
			s=""#command path
			subp = subprocess.run(cmd_all,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
			s=subp.stdout.strip()
			print(s)
			if s:
				cur_cmd=addcmdwithlibc(s)
				print(f"current command {cur_cmd}")
				cmd_list=cur_cmd.split()
				try:
					subp1 = subprocess.Popen(cmd_list,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
					pid=subp1.pid
					hasopt_flag=False
					outs, errs=subp1.communicate(timeout=3)
				except subprocess.TimeoutExpired:
					os.system("sudo kill %s" % (pid))
					print(f'!timeout! cmd: {cmd}')
					continue
				print("err:")
				print(errs)
				err=errs.split('\n')
				for o in err:
					#print(o)
					if "gblic2.35 getopt:" in o:
						opts=extractopts(o)
						temp=command+" short opts:"+opts+"\n"
						if temp not in opt_cmd:
							opt_cmd=opt_cmd+temp									
						hasopt_flag=True
					if "gblic2.35 longopt:" in o: 
						opts=extractopts(o)
						temp=command+" long opts:"+opts+"\n"
						if temp not in opt_cmd:
							opt_cmd=opt_cmd+temp
						hasopt_flag=True

				with open(outfile,'a+') as f:
					f.write(opt_cmd)
				opt_cmd=""												
						
				if hasopt_flag==False:
					noopt=noopt+1
					no_opt=no_opt+command+"\n"
				else:
					hasopt=hasopt+1
	
	with open(outfile,'a+') as f:
		f.write(str(hasopt)+" command has opt!\n")
		f.write(str(uninstall)+" command not install!\n")
		f.write("**********res*******\n")
		f.write(f'{hasopt} command has opt!\n')
		f.write(f'{noopt} command has no opt!\n')
		f.write(f'{uninstall} command not install!\n')
		f.write("*****no options******\n")
		f.write(no_opt)
		f.write("*****uninstall command****\n")
	# print("************* [2]:get libopt finished! ************")	


	

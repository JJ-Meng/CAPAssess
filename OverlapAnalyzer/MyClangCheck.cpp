// Declares clang::SyntaxOnlyAction.
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
// Declares llvm::cl::extrahelp.
#include "llvm/Support/CommandLine.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include<vector>
#include <fstream>
#include <iostream>
#include <sstream>


using namespace clang::tooling;
using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;
using namespace std;

typedef set<const Stmt*>StmtSet;
// Apply a custom category to all command-line options so that they are the
// only ones displayed.
static cl::OptionCategory MyToolCategory("my-tool options");

// CommonOptionsParser declares HelpMessage with a description of the common
// command-line options related to the compilation database and input files.
// It's nice to have this help message in all tools.
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);

// A help message for this specific tool can be added afterwards.
static cl::extrahelp MoreHelp("\nMore help text...\n");

//map<string,string> chkp2crits;
//save chkp and resource relationship

//const SourceManager  sourceMgr;
std::string caps[40]={"CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER",
"CAP_FSETID","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_SETPCAP","CAP_LINUX_IMMUTABLE",
"CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST","CAP_NET_ADMIN","CAP_NET_RAW","CAP_IPC_LOCK",
"CAP_IPC_OWNER","CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT","CAP_SYS_PTRACE","CAP_SYS_PACCT",
"CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE","CAP_SYS_RESOURCE","CAP_SYS_TIME","CAP_SYS_TTY_CONFIG",
"CAP_MKNOD","CAP_LEASE","CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP","CAP_MAC_OVERRIDE",
"CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM","CAP_BLOCK_SUSPEND","CAP_AUDIT_READ","CAP_PERFMON",
"CAP_BPF","CAP_CHECKPOINT_RESTORE"};

StatementMatcher FunctionMatcher =callExpr(isExpansionInMainFile(),callee(functionDecl(hasAnyName("netlink_ns_capable",
"has_capability_noaudit","capable_wrt_inode_uidgid","file_ns_capable","sk_ns_capable","map_write","has_ns_capability",
"netlink_net_capable","sk_net_capable","ns_capable","capable","__netlink_ns_capable","has_capability","ns_capable_setid",
"ns_capable_noaudit","has_ns_capability_noaudit","sk_capable","netlink_capable","perf_cap__capable","smack_privileged")))
//,hasName("cmp_wrapper"),hasAncestor(functionDecl().bind("caller"))
,hasAncestor(functionDecl().bind("caller"))).bind("functioncall");
//string CheckFunctions="hascap,hascap2,hascap_wrapper";
string CheckFunctions="netlink_ns_capable,has_capability_noaudit,capable_wrt_inode_uidgid,file_ns_capable,sk_ns_capable,map_write,has_ns_capability,netlink_net_capable,sk_net_capable,ns_capable,capable,__netlink_ns_capable,has_capability,ns_capable_setid,ns_capable_noaudit,has_ns_capability_noaudit,sk_capable,netlink_capable,perf_cap__capable,smack_privileged";
//cap user function with return funname:cap:!；
std::list<string> tobeVisited; //当前要分析的capability检查函数
std::list<string> VisitNextTime;//capability包裹函数，下一次分析
std::list<string> pro_funcs;//这一次发现的保护的函数
int pro_funcs_number=0;
std::list<string> pro_funcs_old;//之前发现的被保护的函数
string firstline="";//所分析的文件名:cap名
string oldcap="";

//string nextVisit="";
//CompilerInstance TheCompInst;
class Chkp2Resource
{
  public:
    string chkp;
    string functions;
    string vars;
    string capname;
    //string condition;
    Chkp2Resource(string loc)
    {
      chkp=loc;
      functions="";
      vars="";
    }
    ~Chkp2Resource()
    {}
    string getChkp()
    {
      return chkp;
    }
    string getFunctions()
    {
      return functions;
    }
    string getVars()
    {
      return vars;
    }
    string getCapName()
    {
      return capname;
    }
    void setFunctions(string newfuncs)
    {
      functions=newfuncs;
    }
    void setVars(string newvars)
    {
      vars=newvars;
    }
    void setCapName(string cap)
    {capname=cap;}
    bool hasCrits()
    {
      if(getFunctions()==""&&getVars()=="")
      {return false;}
      return true;
    }
};

class MyClangCheck:public RecursiveASTVisitor<MyClangCheck> 
{
private:
  /* data */
public:
  const FunctionDecl* funcdecl;
  const CallExpr* call;
  bool hasnot;//对于不是首次分析的函数，标记上次分析的检查是否为非!capable()
  Chkp2Resource* chkp2resource;
  const Stmt* begin;
  const Stmt* end;
  string declvarname;
  map<const Stmt*,const Stmt*>FuncMap;  //<stmt,parentSt>
  //StmtSet visitedst;
  int returnval;
  /*ret 0;解析成功
ret 1，要看上一级，调用了addtoNext
ret 2,3,4 是两个cap的情况
ret 5,直接保护
*/
  MyClangCheck(const FunctionDecl* func,const CallExpr* call,Chkp2Resource* chkp,bool has_not);
  ~MyClangCheck();
  void setend(const Stmt* s);
  void setbegin(const Stmt* s);
  void setdeclvarname(string name);
  const Stmt* getbegin();
  const Stmt* getend();
  const Stmt*getStmtwithVar(const Stmt* st,bool& findcall, int& type);
  string getdeclvarname();
  int analyseFunc(StmtSet& visited);
  void VisitFunc();
  void TranverseStmt(const Stmt* st);
  int analyseStmt(const Stmt* st,bool flag,StmtSet& visitedst);
  void VisitTopStmt();
  void VisitChildStmt(const Stmt* st,bool& findbegin,bool& findend);
  void handleIfStmt(const IfStmt* ifst);
  void handleDirectIf(const Stmt* st);
  void handleLNotIf(const IfStmt* ifst);
  const Stmt* findParent(const Stmt* st,string parent);
  void GetBOPandUOP(const Stmt* branch,int& uop,int& bop,int& first);
  void CountChecks(const Stmt* branch,int& checks);
  void HandleMultipleCaps(const Stmt* branch);
  bool SkipIfStmt(const IfStmt* ifst);
  void VistStmtinDecl(const IfStmt* ifst);
  void VistStmtinDecl(string lname);
  void VistStmtinDecl(const IfStmt* ifst,string lname);
  const Stmt* FindReturnandGoto(const Stmt* st);
  const ReturnStmt* FindLastReturn();
  const Stmt* FindLastStmt(const Stmt* st);
  int ResolveReturnType(const Stmt* st);
  int getIntfromSmt(const Stmt* st);
 // const GotoStmt* FindGoto(const Stmt* compound);
  int FindCall(const Stmt* st);
  bool FindVarDecl(const Stmt* st);
  bool FindUnaryOperator(const Stmt* st,bool flag,string type);
  bool FindInt(const Stmt* st);
  const LabelStmt* FindLabelSt(string lname);
  const LabelStmt* FindNextLabelSt(string lname);
  int getChildNum(const Stmt* st);
  const Stmt* getChildwithCallorVar(const Stmt* st,string type);
  void TryGetCrits(const Stmt* st);
  int getcriticals(const Stmt* compoundst,int depth);
  void updateCrits(int type,string value);
  int getResfromRet(const Stmt* st);
  int getFunwithVar(const Stmt* st,string var);
  int getMember(const Stmt* st);
  string getVarinMember(const Stmt* st);
  int AddToNextTime();
  void printchildSt(const Stmt* st);
};

MyClangCheck::MyClangCheck(const FunctionDecl* func,const CallExpr* callexpr,Chkp2Resource* chkp,bool has_not)
{
  funcdecl=func;
  call=callexpr;
  chkp2resource=chkp;
  declvarname="";
  hasnot=has_not;
}

MyClangCheck::~MyClangCheck()
{
}
const Stmt* MyClangCheck::getend()
{
  return end;
}
const Stmt* MyClangCheck::getbegin()
{
  return begin;
}
string MyClangCheck::getdeclvarname()
{
  return declvarname;
}
void MyClangCheck::setdeclvarname(string name)
{
  declvarname=name;
}
void MyClangCheck::setend(const Stmt* st)
{
  end=st;
}
void MyClangCheck::setbegin(const Stmt* st)
{
  begin=st;
}
int MyClangCheck::AddToNextTime()
{
  string tovisit="";
  if(!hasnot)
  {
    tovisit=funcdecl->getNameInfo().getAsString()+":"+chkp2resource->getCapName()+":";
  }
  else
    tovisit=funcdecl->getNameInfo().getAsString()+":"+chkp2resource->getCapName()+":!";
  // 添加时去重
  list<string>::iterator it=find(VisitNextTime.begin(),VisitNextTime.end(),tovisit);
  if(it==VisitNextTime.end())
    VisitNextTime.push_back(tovisit);
  //errs()<<"add "<<tovisit<<"\n";
  //check if is write already
  /*ifstream infile;
  ostringstream filebuf;
  string old_file="";
  infile.open("/home/zcq/mjz/clang/toVisit.txt",ios::in);
  if(infile.is_open())
  {
    filebuf<<infile.rdbuf();
    old_file=filebuf.str();
  }
  infile.close();
  if(old_file.find(tovisit)==string::npos)
  {
    ofstream outfile;
    outfile.open("/home/zcq/mjz/clang/toVisit.txt",ios::app);
    outfile << tovisit << endl;
    outfile.close();
  }*/
  return 0;
}
//从compound中获取别保护的资源，depth0代表第一次进来，depth1第二次进来，为了处理间接调用。ret0没找到被保护的资源，
//ret1当前已获取到资源还要递归遍历孩子节点，ret2当前获取到资源，不再递归孩子节点
int MyClangCheck::getcriticals(const Stmt* compound,int depth)
{
  int ret=0;
  string funcs="";
  string vars="";
  string tmpfun="";

  /*if(const OpaqueValueExpr* opaque=dyn_cast<OpaqueValueExpr>(compound))
  {
    errs()<<"getcriticals:opaque!\n";
    Expr *SE = opaque->getSourceExpr()->IgnoreImpCasts();
    if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SE)) {
      errs()<<"decl type is "<<DRE->getType().getAsString()<<"\n";
    }
  }*/

  //function call直接函数调用
  if(const CallExpr* callexpr=dyn_cast<CallExpr>(compound))
  {
    const Decl* decl=callexpr->getCalleeDecl();
    if(decl)
    {      
      if(isa<FunctionDecl>(decl))
      {
        tmpfun=callexpr->getDirectCallee()->getNameInfo().getAsString();
      }       
      else
      {
        int ret=getMember(callexpr);
        if(!ret)
          {errs()<<"getMember with call\n";}
      }
    }
    string args="";
    clang::LangOptions LangOpts;
    LangOpts.CPlusPlus = true;
    clang::PrintingPolicy Policy(LangOpts);
    for(int i=0, j=callexpr->getNumArgs(); i<j; i++)
    {
      string type,argname;
      type=callexpr->getArg(i)->getType().getAsString();
      string TypeS;
      llvm::raw_string_ostream s(TypeS);
      callexpr->getArg(i)->printPretty(s, 0, Policy);
      argname=s.str();
      if(type!="")
      {
        args=args+type+" "+argname+",";
      }
    }
    //TODO：过滤一下
    if(tmpfun.find("ERR")!=string::npos)
    {
      tmpfun="";
    }
    if(tmpfun!="")
    {
      if(CheckFunctions.find(tmpfun)==string::npos)
      {
        funcs=funcs+tmpfun+":"+args+";"; 
        ret=1;     
      }
    }
  }
  //保护的变量
  //int var;
  if(const DeclStmt* decl=dyn_cast<DeclStmt>(compound))
  {
    if(const VarDecl *VD = dyn_cast<VarDecl>(decl->getSingleDecl()))
    {
      if(VD->hasInit())
      {
        const Expr* vardecl=VD->getInit();
        string tmpvar=vardecl->getType().getAsString();
        //tmpvar=tmpvar+" "+VD->getQualifiedNameAsString();
        tmpvar=tmpvar+" "+VD->getNameAsString();
        if(tmpvar!="")
        {
          vars=vars+tmpvar+",";
          ret=1;
        }
      }
    }
  }
  //int var=; TODO：如果用函数给变量赋值能否获取到
  if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(compound))
  {
    if(bop->getOpcode()==BinaryOperator::Opcode::BO_Assign)
    {
      const Expr* lhs=bop->getLHS();
      string tmpvar=lhs->getType().getAsString();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(lhs)) {
        // It's a reference to a declaration...
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          // It's a reference to a variable (a local, function parameter, global, or static data member).
          //tmpvar=tmpvar+" "+VD->getQualifiedNameAsString();
          tmpvar=tmpvar+" "+VD->getNameAsString();
        }
      }
      if(tmpvar!="")
      {
        if(tmpvar.find("err")!=string::npos||tmpvar.find("ret")!=string::npos
        ||tmpvar.find("out")!=string::npos)
        {
          return 0;
        }
        vars=vars+tmpvar+",";
        ret=1;
      }
    }
  }
  //return 了敏感资源
  if(const ReturnStmt* retst=dyn_cast<ReturnStmt>(compound))
  {
    ret=2;
    const auto & sourcemanager=funcdecl->getASTContext().getSourceManager();
    SourceLocation ret_loc=retst->getBeginLoc();
    string retloc=ret_loc.printToString(sourcemanager);
    errs()<<retloc<<"\n";
    //printchildSt(retst);
    //if(getIntfromSmt(retst)==999)
    //{
      //errs()<<"111\n";
      for(const auto* child:retst->children())
      {
        //return直接调用
        if(child)
        {
          //忽略 implicitcast
          if(isa<ImplicitCastExpr>(child))
          {
            for(const auto* imchild:child->children())
            {
              if(imchild)
              {
                if(isa<CallExpr>(imchild))
                {
                  const CallExpr* dcall=dyn_cast<CallExpr>(imchild);
                  //errs()<<"call is "<<dcall->getDirectCallee()->getNameInfo().getAsString(); 
                  getcriticals(dcall,0);
                } 
              }
            }
          }
          else if(isa<CallExpr>(child))
          {
            //errs()<<"direct call in retst\n";
            getcriticals(child,0);
          }
          //return间接调用
          else{
            //errs()<<"indirect call in ret\n";
            int retval=getResfromRet(retst);
            if(retval)
            {
              errs()<<"Err:unresolved return stmt\n"; 
              ret=0;     
            }   
          }
        }        
      } 
    //}
    //else{    }
    
  }
  //间接调用 declrefexpr->callexpr? Warning：Findcall问题
  //A->a or A->b()
  if(const DeclRefExpr* declref=dyn_cast<DeclRefExpr>(compound))
  {
    string tmpvar=declref->getType().getAsString();
    if(funcdecl->getNameInfo().getAsString()=="__rtnl_newlink")
    {
      if (const VarDecl *VD = dyn_cast<VarDecl>(declref->getDecl())) {
          //tmpvar=tmpvar+" "+VD->getQualifiedNameAsString();
        string _var=VD->getNameAsString();
        errs()<<tmpvar <<" "<<_var<<"\n";
        if(_var=="ops")
        {
          errs()<<"find declref ops at ";
          const auto & sourcemanager=funcdecl->getASTContext().getSourceManager();
          SourceLocation decl_loc=declref->getBeginLoc();
          string declloc=decl_loc.printToString(sourcemanager);
          errs()<<declloc<<"\n";
        }
      }
    }
    if(FindCall(declref)==2)
    {
      if(funcdecl->getNameInfo().getAsString()=="__rtnl_newlink")
      {
        //print Loc
        const auto & sourcemanager=funcdecl->getASTContext().getSourceManager();
        SourceLocation decl_loc=declref->getBeginLoc();
        string declloc=decl_loc.printToString(sourcemanager);
        //errs()<<"declref loc: "<<declloc<<"\n";
        //errs()<<"find a call in children of declref, var type is "<<tmpvar<<'\n';
      }
      int retval=getMember(declref);
      if(retval)
      {
        errs()<<"resolved indirect call\n";
        ret=2;
      }
      else
        ret=0;
    }
 
    
    if (const VarDecl *VD = dyn_cast<VarDecl>(declref->getDecl())) {
      // It's a reference to a variable (a local, function parameter, global, or static data member).
      //tmpvar=tmpvar+" "+VD->getQualifiedNameAsString();
      tmpvar=tmpvar+" "+VD->getNameAsString();
    }
  }
  //间接调用 X->F
  /*if(depth==1)
  {
    if(const MemberExpr* memexpr=dyn_cast<MemberExpr>(compound))
    {
      const ValueDecl * memdecl=memexpr->getMemberDecl();
      errs()<<"member type is "<<memdecl->getType().getAsString()<<"\n";
      errs()<<"member name is "<<memdecl->getNameAsString()<<"\n";
    }
  }*/
  if(funcs.find(",")!=string::npos)
  {
    string old_funcs=chkp2resource->getFunctions();
    string new_funcs=old_funcs+funcs;
    chkp2resource->setFunctions(new_funcs);
    //去重加入
    list<string>::iterator it=find(pro_funcs_old.begin(),pro_funcs_old.end(),tmpfun);
    list<string>::iterator _it=find(pro_funcs.begin(),pro_funcs.end(),tmpfun);
    if(it==pro_funcs_old.end()&&_it==pro_funcs.end())
    {
      //第一次插入这个检查点被保护的函数时 要标记capability
      //if(pro_funcs.empty())
        //pro_funcs.push_back(chkp2resource->capname+":\n");
      if(chkp2resource->capname!=oldcap)
      {
        pro_funcs.push_back(chkp2resource->capname);
        oldcap=chkp2resource->capname;
      }
      pro_funcs.push_back(tmpfun);
      pro_funcs_number++;
    }
  }
  if(vars.find(",")!=string::npos)
  {
    string old_vars=chkp2resource->getVars();
    string new_vars=old_vars+vars;
    chkp2resource->setVars(new_vars);
    //errs()<<"getcritical find vars "<<new_vars<<"\n";
  }
  return ret;
}
//测试函数
void MyClangCheck:: printchildSt(const Stmt* retst)
{
  errs()<<"getresfromRet:"<<retst->getStmtClassName()<<"\n";
  for(const auto* child:retst->children())
  {
    if(child)
    {
      if(isa<Stmt>(child))
        printchildSt(child);
    }
  }
}
//更新crits
//type 1:function type2:vars
void MyClangCheck::updateCrits(int type,string value)
{
  if(type==1)
  {
    string old_funcs=chkp2resource->getFunctions();
    string new_funcs=old_funcs+value;
    chkp2resource->setFunctions(new_funcs);
    string tmpfun="";
    int pos=value.find(":");
    if(pos!=-1)
    {
      tmpfun=value.substr(0,pos);
    }
    else 
      tmpfun=value;
    //去重加入
    list<string>::iterator it=find(pro_funcs_old.begin(),pro_funcs_old.end(),tmpfun);
    list<string>::iterator _it=find(pro_funcs.begin(),pro_funcs.end(),tmpfun);
    if(it==pro_funcs_old.end()&&_it==pro_funcs.end())
    {
      //if(pro_funcs.empty())
        //pro_funcs.push_back(chkp2resource->capname+":\n");
      if(chkp2resource->capname!=oldcap)
      {
        pro_funcs.push_back(chkp2resource->capname);
        oldcap=chkp2resource->capname;
      }
      pro_funcs.push_back(tmpfun);
      pro_funcs_number++;
    }
  }
  else if(type==2)
  {
    string old_vars=chkp2resource->getVars();
    string new_vars=old_vars+value;
    chkp2resource->setVars(new_vars);
  }
  else{
    errs()<<"ERR:unresolved type!\n";
  } 
}
//从stmt中递归的获取crits
void MyClangCheck::TryGetCrits(const Stmt* st)
{
  for(const auto* child:st->children())
  {
    if(const Stmt* si=dyn_cast<Stmt>(child))
    {
      //errs()<<"get stmt "<<st->getStmtClassName ()<<"\n";
      int retcrits=getcriticals(si,0);
      if(retcrits!=2)
        TryGetCrits(si);
    }
  }
}
string MyClangCheck::getVarinMember(const Stmt* st)
{
  string var;
  string type="";
  if(const DeclRefExpr* declref=dyn_cast<DeclRefExpr>(st))
  {
    type=declref->getType().getAsString();
    return type;
    /*if (const VarDecl *VD = dyn_cast<VarDecl>(declref->getDecl())) {
      var=VD->getNameAsString();
    }   */
  }
  for(const auto* child:st->children())
  {
    if(isa<Stmt>(child))
    {
      type=getVarinMember(child);
      if(type!="")
        break;
    }
  }
  return type;
}
//间接调用处理,从memberexpr中提取敏感资源，ret 0没有返回找到，ret 1找到了
int MyClangCheck::getMember(const Stmt* st)
{
  int ret=0;
  if(const MemberExpr* memexpr=dyn_cast<MemberExpr>(st))
  {
    //errs()<<"getMember catch Memberexpr\n";
    //try get declvar and 
    string stru_type=getVarinMember(memexpr);
    const ValueDecl * memdecl=memexpr->getMemberDecl();
    string func_type=memdecl->getType().getAsString();
    string func_name=memdecl->getNameAsString();
    string indirect=stru_type+"->"+func_name+":"+func_type;
    errs()<<"getMember:"<<func_type<<"\n";
    errs()<<indirect<<"\n";
    //添加到被保护的资源里
    updateCrits(1,indirect); 
    return 1;
  }
  for(const auto* child:st->children())
  {
    if(isa<Stmt>(child))
    {
      ret=getMember(child);
      if(!ret)
        break;
    }
  }
  return ret;
}
//从return中提取敏感资源
int MyClangCheck::getResfromRet(const Stmt* st)
{
  int ret=0;
  //errs()<<"getresfromRet:"<<st->getStmtClassName()<<"\n";
  //err=fun1(); return err; 
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(st)) {
    string tmpvar=DRE->getType().getAsString();
    //getcriticals(VD);
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) { 
      //errs()<<"get vardecl in ret\n";
      string var=VD->getNameAsString();
      //errs()<<"var is "<<var<<"\n";
      tmpvar=tmpvar+" "+var;
      if(funcdecl->hasBody())
      {
        const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
        for(const auto *s:body->body())
        {
          if(s)
          {
            if(isa<Stmt>(s))
            {
              ret=getFunwithVar(s,var);
              if(ret==0)
                break;
            }
          }
        }
      }
    }
  }
  if(const MemberExpr* memexpr=dyn_cast<MemberExpr>(st))
  {
    //try get declvar and 
    string stru_type=getVarinMember(memexpr);
    const ValueDecl * memdecl=memexpr->getMemberDecl();
    string func_type=memdecl->getType().getAsString();
    string func_name=memdecl->getNameAsString();
    string indirect=stru_type+"->"+func_name+":"+func_type;
    errs()<<"getMember:"<<func_type<<"\n";
    errs()<<indirect<<"\n";
    //添加到被保护的资源里
    if(memdecl)
    {
      if(isa<FunctionDecl>(memexpr->getMemberDecl()))
      {
        updateCrits(1,indirect);
      }
      else if(isa<VarDecl>(memexpr->getMemberDecl()))
      {
        updateCrits(2,indirect); 
      }
      else if(isa<FieldDecl>(memexpr->getMemberDecl()))
      {
        errs()<<"is a field\n";
        updateCrits(2,indirect); 
      }
        
    }
    //updateCrits(1,indirect); 
    return 0;
  }
  if(const CallExpr* call=dyn_cast<CallExpr>(st))
  {
    string cur_call=call->getDirectCallee()->getNameInfo().getAsString();
    //if(cur_call.find("ERR")==string::npos||cur_call.find("err")==string::npos)
    getcriticals(call,0);
    return 0;
  }
  for(const auto* child:st->children())
  {
    if(child)
    {
      if(isa<Stmt>(child))
        ret=getResfromRet(child);
    }   
  }
  return ret;
}
//返回值是变量，获取变量被赋值时的函数调用(假设一个函数里变量不重名),
//ret=0,获取到了函数，ret=1未获取到
int MyClangCheck::getFunwithVar(const Stmt* st,string var)
{
  int ret=0;
  //var=funcall();
  if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(st))
  {
    if(bop->getOpcode()==BinaryOperator::Opcode::BO_Assign)
    {
      const Expr* lhs=bop->getLHS();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(lhs)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          string tmpvar=VD->getNameAsString();
          if(tmpvar==var)
          {
            const Expr* rhs=bop->getRHS();
            if(const CallExpr* call=dyn_cast<CallExpr>(rhs))
            {
              ret=getcriticals(call,0);
            }
          }
        }
      }
    }
  }
  //int var=funcall(); warning:untested
  if(const auto* decl=dyn_cast<DeclStmt>(st))
  {
    if(decl->isSingleDecl()){
      if(const VarDecl *VD = dyn_cast<VarDecl>(decl->getSingleDecl()))
      {
        if(VD->hasInit())
        {
          const Expr* vardecl=VD->getInit();
          string tmpvar=VD->getQualifiedNameAsString();
          if(tmpvar==var)
          {
            if(const CallExpr* call=dyn_cast<CallExpr>(vardecl))
            {
              ret=getcriticals(call,0);
            }
          }
        }
      }
    }   
  }
  for(const auto* child:st->children())
  {
    ret=getFunwithVar(child,var);
  }
  return ret;
}
//当前stmt和其孩子stmt中是否有 call,ret1有targetcall;ret2有call;ret0没有callexpr
//sourcelocation比较callexpr是不是一样
int MyClangCheck::FindCall(const Stmt* st)
{
  int ret=0;
  SourceLocation Loc=call->getExprLoc();
  if(const CallExpr* callexpr=dyn_cast<CallExpr>(st))
  {
    SourceLocation tmpLoc=callexpr->getExprLoc();
    if(tmpLoc==Loc)
    {
      return 1;
    }
    else
      return 2;
  }
  for(const auto* child:st->children())
  {
    ret=FindCall(child);
    if(!ret)
      break;
  }
  return ret;
}
/*unused
bool MyClangCheck::FindDeclRef(const Stmt* st)
{
  bool ret=false;
  if(const DeclRefExpr* declexpr=dyn_cast<DeclRefExpr>(st))
  {
    
  }
  for(const auto* child:st->children())
  {
    ret=FindDeclRef(child);
    if(ret)
      break;
  }
  return ret;
}*/
bool MyClangCheck::FindVarDecl(const Stmt* st)
{
  bool ret=false;
  if(const DeclRefExpr* declexpr=dyn_cast<DeclRefExpr>(st))
  {
    if (const VarDecl *VD = dyn_cast<VarDecl>(declexpr->getDecl()))
    {
      string tmpvar=VD->getQualifiedNameAsString();
      if(getdeclvarname().find(tmpvar)!=string::npos)
        return true;
    }
  }
  for(const auto* child:st->children())
  {
    ret=FindVarDecl(child);
    if(ret)
      break;
  }
  return ret;
}
//分支中有UOP(!)或者BOP（！=）并且UOP支配了call
//flag 是否已经找到UOP，ret uop是否支配了call
bool MyClangCheck::FindUnaryOperator(const Stmt* st,bool flag,string type)
{
  int ret=false;
  if(!flag)
  {
    if(type=="!")
    {
      if(const UnaryOperator* uop=dyn_cast<UnaryOperator>(st))
      {
        if(uop->getOpcode()==UnaryOperator::Opcode::UO_LNot)
          flag=true;
      }
    }
    if(type=="-")
    {
      if(const UnaryOperator* uop=dyn_cast<UnaryOperator>(st))
      {
        if(//uop->getOpcode()==UnaryOperator::Opcode::UO_PreDec)
        uop->getOpcode()==UnaryOperator::Opcode::UO_Minus)
        {
          flag=true;
          return true;
        }         
      }
    }
    if(type=="!var")
    {
      if(const UnaryOperator* uop=dyn_cast<UnaryOperator>(st))
      {
        if(uop->getOpcode()==UnaryOperator::Opcode::UO_LNot)
          flag=true;
      }
    }
  }
  else{
    if(type=="!")
    {
      if(const CallExpr* callexpr=dyn_cast<CallExpr>(st))
      {
        if(callexpr->getExprLoc()==call->getExprLoc())
          return true;
      }
    }
    if(type=="!var")
    {
      if(const DeclRefExpr* decl=dyn_cast<DeclRefExpr>(st))
      {
        if (const VarDecl *VD = dyn_cast<VarDecl>(decl->getDecl()))
        {
          string tmpvar=VD->getQualifiedNameAsString();
          if(getdeclvarname().find(tmpvar)!=string::npos)
            return true;
        }
      }
    }  
  }
  for(const auto * child:st->children())
  {
    ret=FindUnaryOperator(child,flag,type);
    if(ret)
      break;
  }
  return ret;
}
//find last Stmt of st(compoundStmt)
const Stmt* MyClangCheck::FindLastStmt(const Stmt* st)
{
  const Stmt* ret=NULL;
  const Stmt* stt=st;
  if(const CompoundStmt* com=dyn_cast<CompoundStmt>(st))
  {
    stt=com->body_back();
    ret=stt;
  }
  for(const auto * s : stt->children())
  {
    ret=FindLastStmt(s);
    if(!ret)
      ret=s;
  }
  return ret;
}
const ReturnStmt* MyClangCheck::FindLastReturn()
{
  const ReturnStmt* ret=NULL;
  //get func return type
  if(funcdecl->getReturnType().getAsString()=="void")
  {
    errs()<<"return is a void\n";
    return ret;
  }
  const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
  const Stmt* res=NULL;
  for(const auto *s:body->body())
  {
    if(const Stmt* st=dyn_cast<Stmt>(s))
    {
      res=FindReturnandGoto(st);
    }
  }
  if(res)
  {
    if(isa<ReturnStmt>(res))
    {
      ret=dyn_cast<ReturnStmt>(res);
    }
  }
  return ret;
}
const Stmt*  MyClangCheck::FindReturnandGoto(const Stmt* st)
{
  const Stmt* ret=NULL;
  if(!st)
    return NULL;
  if(const ReturnStmt* retst=dyn_cast<ReturnStmt>(st))
  {
    return retst;
  }
  if(const GotoStmt* gotost=dyn_cast<GotoStmt>(st))
  {
    return gotost;
  }
  for(const auto * s : st->children())
  {
    ret=FindReturnandGoto(s);
    if(ret)
      break;
  }
  return ret;
}
//find return stmt in compound stmt
/*ret=0,no returnstmt in compound;
ret=1,find returnstmt,retvalue is negative int
ret=2,find return,retvalue is complex type
*/
int MyClangCheck::ResolveReturnType(const Stmt* compound)
{
  int ret=0;
  if(FindUnaryOperator(compound,false,"-"))
  {
   // ret=2;
    //errs()<<"ResolveReturnType:find uop - in ret\n";
    return 2;
  }
  /*if(funcdecl->getReturnType().getAsString()=="_Bool")
  {
    find=true;
  }*/
  if(FindInt(compound))
  {
    //errs()<<"ResolveReturnType:find int\n";
    return 3;
  }
  for(const auto * s : compound->children())
  {
    ret=ResolveReturnType(s);
    if(ret!=0)
      break;
    /*if(isa<ReturnStmt>(s))
    {
      ret=1;
      //errs()<<"FindReturn:find return\n";
      if(FindUnaryOperator(s,false,"-"))
      {
        ret=2;
        break;
        //errs()<<"FindReturn:find uop - in ret\n";
      }
      const IntegerLiteral& intexpr;
      if(FindInt(s,intexpr))
      {
        llvm::APInt retint=intexpr->getValue();
        if(retint==0||retint==1)
      }
      for(auto* child:s->children())
      {
        //return 0/1
        if(isa<IntegerLiteral>(child))
        {

        }
      }
    }*/
  }
  return ret;
}/*
const GotoStmt* MyClangCheck::FindGoto(const Stmt* compound)
{
  const GotoStmt* ret=NULL;
  if(const GotoStmt* gotost=dyn_cast<GotoStmt>(compound))
  {
    return gotost;
  }
  for(const auto * s : compound->children())
  {
    ret=FindGoto(s);
    if(ret!=NULL)
      break;
  }
  return ret;
}*/
int MyClangCheck::getIntfromSmt(const Stmt* st)
{
  int ret=999;
  if(const IntegerLiteral* tmpintl=dyn_cast<IntegerLiteral>(st))
  {   
    llvm::APInt apint=tmpintl->getValue();
    int retint=apint.getZExtValue();
    //errs()<<"getintfromret retint is "<<retint<<"\n";
    return retint;
  }
  if(const DeclRefExpr* declref=dyn_cast<DeclRefExpr>(st))
  {   
    string tmpvar=declref->getType().getAsString();
    errs()<<"getintfromret ret is decl  type "<<tmpvar<<"\n";
    return 0;
  }
  for(const auto * s : st->children())
  {
    ret=getIntfromSmt(s);
    if(ret!=999)
      break;
  }
  return ret;
}
//returnst contains 0/1 T/F
bool MyClangCheck::FindInt(const Stmt* st)
{
  bool find=false;
  if(const IntegerLiteral* tmpintl=dyn_cast<IntegerLiteral>(st))
  {   
    llvm::APInt retint=tmpintl->getValue();
    if(retint==0||retint==1)
    {
      errs()<<"get a integerliteral with value 0 or 1\n";
      return true;
    }
      
  }
  for(const auto * s : st->children())
  {
    find=FindInt(s);
    if(find)
      break;
  }
  return find;
}
const LabelStmt* MyClangCheck::FindNextLabelSt(string lname)
{
  bool findlabel=false;
  const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
  for(const auto *s:body->body())
  {
    if(!findlabel)
    {
      if(const LabelStmt * labelstmt=dyn_cast<LabelStmt>(s))
      {
        LabelDecl* label=labelstmt->getDecl();
        string labelname=label->getNameAsString();
        if(lname==labelname)
        {
          findlabel=true;
        }
      }
    }
    else
    {
      if(const LabelStmt * nextlabel=dyn_cast<LabelStmt>(s))
      {
        return nextlabel;
      }
    }
   
  }
  return NULL;
}
const LabelStmt* MyClangCheck::FindLabelSt(string lname)
{
  const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
  for(const auto *s:body->body())
  {
    if(const LabelStmt * labelstmt=dyn_cast<LabelStmt>(s))
    {
      LabelDecl* label=labelstmt->getDecl();
      string labelname=label->getNameAsString();
      if(lname==labelname)
      {
        return labelstmt;
      }
    } 
  }
  return NULL;
}
//遍历从label开始到函数出口的stmt，从中提取crits
void MyClangCheck::VistStmtinDecl(string lname)
{
  bool flag=false;
  const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
  for(const auto *s:body->body())
  {
    if(!flag)
    {
       if(const LabelStmt * labelstmt=dyn_cast<LabelStmt>(s))
      {
        LabelDecl* label=labelstmt->getDecl();
        string labelname=label->getNameAsString();
        if(lname==labelname)
        {
          flag=true;
        }
      }
    }
   
    if(const Stmt * stmt=dyn_cast<Stmt>(s))
    {
      if(flag)
      {
        errs()<<"in label:"<<stmt->getStmtClassName()<<"\n";
        int retcritis=getcriticals(stmt,0);
        if(retcritis!=2)
          TryGetCrits(stmt);
      }
    }
  }
}
//
void MyClangCheck::VistStmtinDecl(const IfStmt* ifst,string lname)
{
  const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
  SourceLocation tarLoc=ifst->getBeginLoc();
  bool start=false;
  for(const auto *s:body->body())
  {
    if(!start)
    {
      if(const auto* tmpif=dyn_cast<IfStmt>(s))
      {
        SourceLocation curLoc=tmpif->getBeginLoc();
        if(tarLoc==curLoc)
        {
          start=true;
          continue;
        }
      }
    }
    if(start)
    {
      if(const LabelStmt * labelstmt=dyn_cast<LabelStmt>(s))
      {
        LabelDecl* label=labelstmt->getDecl();
        string labelname=label->getNameAsString();
        if(lname==labelname)
        {
          return;
        }
      }
      if(const Stmt * stmt=dyn_cast<Stmt>(s))
      {
        //如果if内返回了Err，跳过这个ifStmt
        //递归遍历stmt，从中提取crits
        int retcritis=getcriticals(stmt,0);
        if(retcritis!=2)
          TryGetCrits(stmt);
      }
    }
  }
}
bool MyClangCheck::SkipIfStmt(const IfStmt* s)
{
  bool flag=false;
  const Stmt* retorgoto=FindReturnandGoto(s);
  if(retorgoto)
  {
    if(isa<ReturnStmt>(retorgoto))
    {
      if(ResolveReturnType(s->getThen())==2)
      {
        flag=true;
        //errs()<<"this return uop -\n";
      }
    }

  }  
  //goto out 
  return flag;
}
//ifStmt has return,care about Stmt after if.
//作用域，根if：整个函数；嵌套的if：局部函数体
void MyClangCheck::VistStmtinDecl(const IfStmt* ifst)
{
  const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
  SourceLocation tarLoc=ifst->getBeginLoc();
  bool flag=false;
  const Stmt* parent=findParent(ifst,"if");
  //根if
  if(parent->getBeginLoc()==ifst->getBeginLoc())
  {
    errs()<<"this if is a root if\n";
    for(const auto *s:body->body())
    {
      if(!flag)
      {      
        if(const auto* tmpif=dyn_cast<IfStmt>(s))
        {
          SourceLocation curLoc=tmpif->getBeginLoc();
          if(tarLoc==curLoc)
          {
            flag=true;
            continue;
          }
        }
      }
      else
      {
        if(const Stmt * stmt=dyn_cast<Stmt>(s))
        {
          //如果if内返回了Err，跳过这个ifStmt
          if(const IfStmt* _ifst=dyn_cast<IfStmt>(stmt))
          {
            if(SkipIfStmt(_ifst))
            {
              errs()<<"this if should skip\n";
              continue;
            }
          }          
          //递归遍历stmt，从中提取crits
          int retcrits=getcriticals(stmt,0);
          if(retcrits!=2)
            TryGetCrits(stmt);
        }
      }
    }
  }
  //target if is in if or swithcase
  else
  {

  }
}
/*
int MyClangCheck::VisitChildStmt(const Stmt* st, bool findbegin,bool findend)
{
  errs()<<st->getStmtClassName()<<": ";
  int ret=0;
  if(!findbegin)
  {
    errs()<<"find begin fase: ";
    if(st->getBeginLoc()==begin->getBeginLoc())
    {
      ret=1;
      //return 1;
    }
    if(ret==1)
    {
      errs()<<"ret==1\n";
      int tmpret=0;
      for(auto *child:st->children())
      {
        tmpret=VisitChildStmt(child,true,false);
        if(tmpret==2)
          ret=2;
      }
    }
    else
    {
      for(auto *child:st->children())
      {
        ret=VisitChildStmt(child,false,false);
        if(ret==1)

      }
    }
  }
  else
  {
    ret=1;
    if(!findend)
    {
      errs()<<"findend false:";
      getcriticals(st);
      if(st->getBeginLoc()==end->getBeginLoc())
      {
        ret=2;
      }
      if(ret!=2)
      {
        errs()<<"ret!=2\n";
        for(auto* child:st->children())
        {
          ret=VisitChildStmt(child,true,false);
          if(ret==2)
            break;
        }
      }
      else
      {
        TryGetCrits(st);
      }
    }
  }
  return ret;
}*/
void MyClangCheck::VisitChildStmt(const Stmt*st,bool& findbegin,bool& findend)
{ 
  if(!st)
    return;
  //errs()<<"VIsitChildStmt:"<<st->getStmtClassName()<<'\n';
  /*const auto & sourcemanager=funcdecl->getASTContext().getSourceManager();
  SourceLocation crits=st->getBeginLoc();
  string cloc=crits.printToString(sourcemanager);
  errs()<<"Loc: "<<cloc<<"\n";*/
  if(!findbegin)
  {
    if(st->getBeginLoc()==begin->getBeginLoc())
    {
      findbegin=true;
    }
    for(const auto* child:st->children())
    {
      VisitChildStmt(child,findbegin,findend);
    }    
  }
  else{
    if(!findend)
    {
      if(funcdecl->getNameInfo().getAsString()=="__rtnl_newlink"){
        const auto & sourcemanager=funcdecl->getASTContext().getSourceManager();
        /*SourceLocation crits=st->getBeginLoc();
        string cloc=crits.printToString(sourcemanager);
        errs()<<"Loc: "<<cloc<<"\n";*/
      }
      //errs()<<"before getcriticals "<<st->getStmtClassName()<<"\n";
      int retcritis=getcriticals(st,0);
      if(st->getStmtClassName()==end->getStmtClassName()&&st->getBeginLoc()==end->getBeginLoc())
      {
        //errs()<<"st is end "<<st->getStmtClassName()<<"\n";
        //errs()<<"end is "<<end->getStmtClassName()<<"\n";
        findend=true;
        return;
      }
      //if(st->getBeginLoc()==end->getBeginLoc()&&st->getEndLoc()==end->getEndLoc())
      if(retcritis!=2)
      {
        for(const auto* child:st->children())
        {
          VisitChildStmt(child,findbegin,findend);
          if(findend==true)
            return;
        }
      }
    
    }
    else
    {
      return;
    }
  }
}
void MyClangCheck::VisitTopStmt()
{
  //errs()<<"VisitTopStmt:\n";
  const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
  bool findbegin=false;
  bool findend=false;
  errs()<<"begin Stmt is "<<getbegin()->getStmtClassName() <<"\n";
  const auto & sourcemanager=funcdecl->getASTContext().getSourceManager();
  SourceLocation begin=getbegin()->getBeginLoc();
  string beginloc=begin.printToString(sourcemanager);
  errs()<<"beginst: "<<beginloc<<"\n";
  errs()<<"end Stmt is "<<getend()->getStmtClassName()<<"\n";
  SourceLocation end=getend()->getBeginLoc();
  string endloc=end.printToString(sourcemanager);
  errs()<<"endst: "<<endloc<<"\n";
  //if begin == end return；当前没有被保护的资源，要看上一级
  if(getbegin()->getBeginLoc()==getend()->getBeginLoc())
  {
   // errs()<<"begin == end \n";
    return;
  }
  for(const auto *s:body->body())
  {
    if(!s)
      return;
    if(isa<Stmt>(s))
    {
      VisitChildStmt(s,findbegin,findend);
      /*if(ret==0)
        ret=VisitChildStmt(s,false,false);
      else if(ret==1)
      {
        //errs()<<"VisitTopStmt: ret is 1\n";
        ret=VisitChildStmt(s,true,false);
      }
        
      else if(ret==2)
        break;*/
    }
  }
}
/*!capable():
(1)else中资源
(2)then has "return -ERR",return到函数出口资源
(3)then has "goto",从检查点到goto的label
(4)then do something,没有（1）~（3）的情况，then中时降低权限的操作，也记录下来
*/
void MyClangCheck::handleLNotIf(const IfStmt* ifst)
{
  const Stmt* elsest=ifst->getElse();
  const Stmt* thenst=ifst->getThen();
  if(elsest)
  {
    int retcritis=getcriticals(elsest,0);
    if(retcritis!=2)
      TryGetCrits(elsest); 
    const Stmt* retorgoto=FindReturnandGoto(thenst);
    if(retorgoto){
      if(const GotoStmt* gotost=dyn_cast<GotoStmt>(retorgoto))
      {
        string label=gotost->getLabel()->getNameAsString();
        const LabelStmt* labelst=FindLabelSt(label);
        if(labelst)
          setbegin(labelst);
      }
    }
    /*
    if(labelname!="")
    {
      VistStmtinDecl(ifst,labelname);
    }*/
    if(chkp2resource->hasCrits())
    {
      returnval=5;
      return;
    }
      
  }
  //get the scope of 
  //return T/F under if,should look up 
  //TODO:modify tobevisited,不应该使用return0/1或者TFpandaUN是否要看上一级 
  //当capability检查的返回值与函数出口返回值不一样时候才需要看上一级
 
  //get parent of target if
  const Stmt* parent_compound=findParent(ifst,"compound");
  if(parent_compound)
  {
   // if(parent_compound->getBeginLoc()!=ifst->getBeginLoc())
    //{
      //errs()<<"find parent comound of if\n";
      if(const CompoundStmt* compound=dyn_cast<CompoundStmt>(parent_compound))
      {
        //嵌套 nest if/case,确定范围下限
        const Stmt* lastst=FindLastStmt(compound);
        if(lastst)
        {
          setend(lastst);
          errs()<<"handleLNotIf->setend: "<<lastst->getStmtClassName()<<"\n";
        }
      }
    //}
  }
  const Stmt* hasretorgoto=FindReturnandGoto(thenst); 
  if(hasretorgoto)
  {
    if(const ReturnStmt* hasret=dyn_cast<ReturnStmt>(hasretorgoto))
    {
      errs()<<"has return in Lnotif\n";
      setbegin(hasret);
      VisitTopStmt();
      /*const ReturnStmt* lastret=FindLastReturn();
      int cur_ret=999;
      int last_ret=999;
      if(lastret)
      {
        last_ret=getIntfromSmt(lastret);
        cur_ret=getIntfromSmt(hasret);
        if(last_ret!=999) 
        {
          errs()<<"return int\n";
          if( last_ret==cur_ret)
          {
            //两个return相同，需要查看上一级找保护资源
            //AddToNextTime();
            errs()<<"equal return\n";
            return;
          }  
          else{
            setbegin(hasret);
            VisitTopStmt();
          }    
        }
        //return 的是资源，不是int
        else{
          //和return —ERR一样
          setbegin(hasret);
          VisitTopStmt();
          return;
        } 
      }*/
    }
    else if(const GotoStmt* gotost=dyn_cast<GotoStmt>(hasretorgoto))
    {
      //handle !capable() then goto
      string label=gotost->getLabel()->getNameAsString();
      const LabelStmt* labelst=FindLabelSt(label);
      setbegin(gotost);
      if(labelst)
        setend(labelst);
      //get crits from begin to end
      VisitTopStmt();
      return;   
    } 
  }   
  //handle !capble() then do a lower permission operation
  else
  {
    int retcritis=getcriticals(thenst,0);
    if(retcritis!=2)
      TryGetCrits(thenst);
  }   
}
void MyClangCheck::handleDirectIf(const Stmt* thenst)
{
 int retcritis= getcriticals(thenst,0);
  //errs()<<"after getcriticals\n";
  if(retcritis!=2)
    TryGetCrits(thenst);
  //find return in if, should look up 
  const Stmt* retorgoto=FindReturnandGoto(thenst);
  if(retorgoto)
  {
    if(isa<ReturnStmt>(retorgoto))
    {
      return;
    }
    //try get label name from goto
    if(const GotoStmt* gotost=dyn_cast<GotoStmt>(retorgoto))
    {
      string label=gotost->getLabel()->getNameAsString();
      const LabelStmt* labelst=FindLabelSt(label);
      //get crits from begin to end
      if(labelst)
        setbegin(labelst);
      const LabelStmt* nextlabel=FindNextLabelSt(label);
      if(nextlabel)
        setend(nextlabel);
      VisitTopStmt();
    }
  }
  //有直接被保护的资源
  if(chkp2resource->hasCrits())
  {
    returnval=5;
  }
  
}
int MyClangCheck::getChildNum(const Stmt* st)
{
  int count =0;
  for(const auto * si : st->children())
  {
    count++;
  }
  //errs()<<st->getStmtClassName()<<" has "<<count<<" child\n";
  return count;
}
//获取if中call所在的分支or var
//string "call" find call ; string "var"
const Stmt* MyClangCheck::getChildwithCallorVar(const Stmt* cond,string type)
{
  const Stmt* ret=cond;
  int child_num=getChildNum(cond);
  if(child_num==1)
  {
    return ret;
  }

  for(const auto * si : cond->children())
  {
    if(isa<Stmt>(si))
    {
      const Stmt* child=si;
      if(type=="call")
      {
        if(FindCall(child)==1)
          ret=getChildwithCallorVar(child,type);
      }
      else if(type=="var")
      {
        if(FindVarDecl(child))
          ret=getChildwithCallorVar(child,type);
      }
    
    }
  }
  return ret;
}
//find parent of stmt,parent type is string
const Stmt* MyClangCheck::findParent(const Stmt* st,string parent_type)
{
  const Stmt* parent=NULL;
  if(FuncMap.find(st)!=FuncMap.end())
    parent=FuncMap[st];
    //const赋值给非const
    //tmp=const_cast<Stmt*>(FuncMap[st]);
  if(!parent)
  {
    return parent;
  }
  if(parent_type=="bop")
  {
    if(isa<BinaryOperator>(parent))
    {
      return parent;
    }
  }
  else if(parent_type=="if")
  {
    if(isa<IfStmt>(parent))
    {
      return parent;
    }
  }
  else if(parent_type=="compound")
  {
    if(isa<CompoundStmt>(parent))
    {
      return parent;
    }
  }
  else if(parent_type=="case")
  {
    if(isa<CaseStmt>(parent))
    {
      return parent;
    }
  }
  //else
      parent= findParent(parent,parent_type);
  return parent; 
}
void MyClangCheck::CountChecks(const Stmt* branch,int& checks)
{
  if(isa<CallExpr>(branch))
  {
    string cur_call=call->getDirectCallee()->getNameInfo().getAsString();
    if(CheckFunctions.find(cur_call)!=string::npos)
    {
      checks++;
    }
  }
  for(const auto *s:branch->children() )
  {
    if(const Stmt* st=dyn_cast<Stmt>(s))
      CountChecks(st,checks);
  }

}
/*uop:0 没有uop(!) uop:1 有uop!
first:1 uop先出现 first:2 bop先出现
bop:1 &&; bop:2||
*/
void MyClangCheck::GetBOPandUOP(const Stmt* branch,int& hasuop,int&hasbop,int& first)
{
  if(first==0)
  {
    if(const UnaryOperator* uop=dyn_cast<UnaryOperator>(branch))
    {
      if(uop->getOpcode()==UnaryOperator::Opcode::UO_LNot)
      {
        first=1;
        hasuop=1;
      }
    }
    if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(branch))
    {       
      if(bop->getOpcode()==BinaryOperator::Opcode::BO_And
      ||bop->getOpcode()==BinaryOperator::Opcode::BO_LAnd)
      {
        first=2;
        hasbop=1;
      }
       if(bop->getOpcode()==BinaryOperator::Opcode::BO_Or
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LOr)
      {
        first=2;
        hasbop=2;
      }
    }
  }
  else{
    if(const UnaryOperator* uop=dyn_cast<UnaryOperator>(branch))
    {
      if(uop->getOpcode()==UnaryOperator::Opcode::UO_LNot)
      {
        hasuop=1;
      }
    }
    if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(branch))
    {       
      if(bop->getOpcode()==BinaryOperator::Opcode::BO_And
      ||bop->getOpcode()==BinaryOperator::Opcode::BO_LAnd)
      {
        hasbop=1;
      }
       if(bop->getOpcode()==BinaryOperator::Opcode::BO_Or
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LOr)
      {
        hasbop=2;
      }
    }

  }  
    for(const auto* s:branch->children())
    {
      if(const Stmt* st=dyn_cast<Stmt>(s))
        GetBOPandUOP(st,hasuop,hasbop,first);
    }
}
//多个capability之间的逻辑关系
void MyClangCheck::HandleMultipleCaps(const Stmt* branch)
{
  //vector<const Expr*>Operators;
  int checks=0;
  CountChecks(branch,checks);
  //get check point call num in branch(include first stmt)
  /*
  if(const CallExpr* callexpr=dyn_cast<CallExpr>(branch))
  {
    string cur_call=call->getDirectCallee()->getNameInfo().getAsString();
    if(CheckFunctions.find(cur_call)!=string::npos)
    {
      checks++;
    }
  }
  for(const auto *s:branch->children() )
  {
    if(const CallExpr* callexpr=dyn_cast<CallExpr>(s))
    {
      string cur_call=call->getDirectCallee()->getNameInfo().getAsString();
      if(CheckFunctions.find(cur_call)!=string::npos)
      {
        checks++;
      }
    }
  }*/
  //errs()<<branch->getStmtClassName()<<" has "<<checks<<"\n";
  //branch only has one cap check function,get uop,and look up for bop
  if(checks==1)
  {
    const Stmt* parent;
    parent=findParent(branch,"bop");
    //!+bop根据bop类型
    if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(parent))
    {
      //errs()<<bop->getOpcodeStr(bop->getOpcode())<<"\n";
      if(FindUnaryOperator(branch,false,"!"))
      {
        //&+!或保护
        if(bop->getOpcode()==BinaryOperator::Opcode::BO_And||
        bop->getOpcode()==BinaryOperator::Opcode::BO_LAnd
        )
        {
          returnval=4;
        }
        //||+!且保护
        if(bop->getOpcode()==BinaryOperator::Opcode::BO_Or
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LOr)
        {
          returnval=3;
        }
      }
      //没有UOP（!）直接看BOP    
      else
      {
        if(bop->getOpcode()==BinaryOperator::Opcode::BO_And
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LAnd)
        {
          returnval=3;
        }
        if(bop->getOpcode()==BinaryOperator::Opcode::BO_Or
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LOr)
        {
          returnval=4;
        }
      }
    }
    else
    {
      errs()<<"Err in MutipleCap:no BOP parent\n";
    }
  }
  //branch has two check functions, tranverse branch to get uop and bop 
  else{
    int first=0;
    int hasuop=0;
    int hasbop=0;
    GetBOPandUOP(branch,hasuop,hasbop,first);
    /*
    if(const UnaryOperator* uop=dyn_cast<UnaryOperator>(branch))
    {
      if(uop->getOpcode()==UnaryOperator::Opcode::UO_LNot)
      {
        first_uop=true;
        hasuop=1;
      }
    }
    if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(branch))
    {       
      if(bop->getOpcode()==BinaryOperator::Opcode::BO_And
      ||bop->getOpcode()==BinaryOperator::Opcode::BO_LAnd)
      {
        first_bop=true;
        hasbop=1;
      }
       if(bop->getOpcode()==BinaryOperator::Opcode::BO_Or
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LOr)
      {
        first_bop=true;
        hasbop=2;
      }
    }
    for(const auto* s:branch->children())
    {

      if(const UnaryOperator* uop=dyn_cast<UnaryOperator>(s))
      {
        if(uop->getOpcode()==UnaryOperator::Opcode::UO_LNot)
        {
          if(!first_uop&&!first_bop)
            first_uop=true;
          hasuop=1;
        }
      }
      if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(s))
      {       
        if(bop->getOpcode()==BinaryOperator::Opcode::BO_And
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LAnd)
        {
          if(!first_uop&&!first_bop)
            first_bop=true;
          hasbop=1;
        }
      }
      if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(s))
      {       
        if(bop->getOpcode()==BinaryOperator::Opcode::BO_Or
        ||bop->getOpcode()==BinaryOperator::Opcode::BO_LOr)
        {
          if(!first_uop&&!first_bop)
            first_bop=true;
          hasbop=2;
        }
      }
    }*/
    if(first==1)
    {
      //errs()<<"first is a uop\n";
      if(hasbop==1)//!+& 与保护
      {
        returnval=3;
      }
      if(hasbop==2)//!+|| 或保护
      {
        returnval=4;
      }
      //errs()<<"hasuop:"<<hasuop<<"hasbop:"<<hasbop<<"\n";
    }
    else if(first==2)
    {
      //errs()<<"first is a bop\n";
      if(hasuop==1)
      {
        if(hasbop==1)//&+!或保护
        { returnval=4;}
        if(hasbop==2) //||+！且保护
        { returnval=3;}
      }
      else{
        if(hasbop==1)
          returnval=3;
        if(hasbop==2)
          returnval=4;
      }
      
    }
    else{
      errs()<<"multiple caps: didnt find uop and bop\n";
    }
  }
}
void MyClangCheck::handleIfStmt( const IfStmt* ifst)
{
  const Expr* cond=ifst->getCond();
  if(!ifst)
    errs()<<"my if is null\n";
  //确认call所在的分支in condition
  const Stmt* target=cond;
  target=getChildwithCallorVar(cond,"call");
  errs()<<"handleif: "<<target->getStmtClassName()<<"\n";
  //是否为一个检查点多个capability的问题
  if(returnval==2)
  {
    HandleMultipleCaps(target);
    return;
  }
  //if(!=)
  const Stmt* parent=NULL;
  if(FuncMap.find(target)!=FuncMap.end())
    parent=FuncMap[target];
  if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(parent))
  {
    if(bop->getOpcode()==BinaryOperator::Opcode::BO_NE)
    {
      hasnot=!hasnot;
    }
    else if(bop->getOpcode()==BinaryOperator::Opcode::BO_EQ)
    {
      /*handleDirectIf(ifst->getThen());
      return*/
    }
  }
  //if(!capable())
  if(FindUnaryOperator(target,false,"!"))
  {
    hasnot=!hasnot;
  }
  if(hasnot)
  {
    handleLNotIf(ifst);
  }
  else
  {
    handleDirectIf(ifst->getThen());
  }
  //如果是switchcase里没找到被保护的资源，就不继续向上看了
  const Stmt* casest=findParent(ifst,"case");
  if(!chkp2resource->hasCrits())
  {
    if(!casest)
    {
      //errs()<<"handle if did not get crits add to next time\n";
      AddToNextTime();
      returnval=1;
      return;
    }
  }
}
//从call开始重新遍历，找到var所在的if或者return Stmt
const Stmt* MyClangCheck::getStmtwithVar(const Stmt* st,bool& findcall,int& type )
{
  //errs()<<"in getstmtwithvar\n";
  const Stmt* s=NULL;
  const IfStmt* myif;
  const ReturnStmt* myret;
  int cases=0;
  if(!findcall)
  {
    if(const CallExpr* callexpr=dyn_cast<CallExpr>(st))
    {
      if(callexpr->getExprLoc()==call->getExprLoc())
      {
        findcall=true;
      }
    }
    for(auto* child:st->children())
    {
      s=getStmtwithVar(child,findcall,type);  
    }
  }
  else
  {
    //errs()<<"after find call "<<st->getStmtClassName()<<"\n";
    if(const IfStmt* ifst=dyn_cast<IfStmt>(st))
    {
      cases=1;
      myif=ifst;
    }
    if(const ReturnStmt* retst=dyn_cast<ReturnStmt>(st))
    {
      cases=2;
      myret=retst;
    }
    if(const DeclRefExpr* decl=dyn_cast<DeclRefExpr>(st))
    {
      if (const VarDecl *VD = dyn_cast<VarDecl>(decl->getDecl()))
      {
        string tmpvar=VD->getQualifiedNameAsString();
        int index=getdeclvarname().find(" ");
        if(index!=-1)
        {
          string varname=getdeclvarname().substr(index+1);
          if(tmpvar==varname)
          {
            return decl;
          }
        }        
      }
    }
    for(const auto* child:st->children())
    {
      s=getStmtwithVar(child,findcall,type);
      if(s)
      {
        if(cases==1)
        {
          type=1;
          s=myif;
        }
        else if(cases==2)
        {
          type=2;
          s=myret;
        }
        else{
          //errs()<<"call in var, unresolved var usage type: "<<type<<"\n";
        }
        break;
      }
    }
   
  }
  return s;
}
int MyClangCheck::analyseStmt(const Stmt* si,bool flag,StmtSet& visitedst)
{
  //errs()<<"analyseSt:"<<si->getStmtClassName()<<"\n";
  SourceLocation tarLoc=call->getExprLoc();
  int ret=0;
  int cases=0;
  const IfStmt* myif;
  const ReturnStmt* myret;
  string tmpvar;
  if(const auto* line=dyn_cast<IfStmt>(si))
  {
    errs()<<"analyseSt:if case\n";
    cases=1;
    myif=line;
  }
  //capable()结果赋值给变量 int err=capabele()
  if(const auto* decl=dyn_cast<DeclStmt>(si))
  {
    if(decl->isSingleDecl()){
      if(const VarDecl *VD = dyn_cast<VarDecl>(decl->getSingleDecl()))
      {
        if(VD->hasInit())
        {
          const Expr* vardecl=VD->getInit();
          tmpvar=vardecl->getType().getAsString();
          tmpvar=tmpvar+" "+VD->getQualifiedNameAsString();
          if(FindCall(vardecl)==1)
          {
            setdeclvarname(tmpvar);
            cases=2;
          }
        }
      }
    }   
  }
  //int err; err=capable();
  if(const auto* bop=dyn_cast<BinaryOperator>(si))
  {
    if(bop->getOpcode()==BinaryOperator::Opcode::BO_Assign)
    {
      const Expr* lhs=bop->getLHS();
      const Expr* rhs=bop->getRHS();
      tmpvar=lhs->getType().getAsString();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(lhs)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          tmpvar=tmpvar+" "+VD->getQualifiedNameAsString();
        }
      }
      if(FindCall(rhs)==1)
      {
        //errs()<<"find call in vardecl inside of BOP： "<<tmpvar<<"\n";
        setdeclvarname(tmpvar);
        cases=2;
      }
    }
  }
  if(const auto* line=dyn_cast<ReturnStmt>(si))
  {
    errs()<<"analyseSt:ret case\n";
    cases=3;
    myret=line;
  }
  if(const auto* expr=dyn_cast<CallExpr>(si))
  {
    SourceLocation tmpLoc=expr->getExprLoc();
    if(tarLoc==tmpLoc)
    {
      flag=true;
      //const Stmt* st=FuncMap[expr];
    }
  }
  if(flag)
    return 1;
  for(const auto* stmt:si->children())
  {
    ret=analyseStmt(stmt,flag,visitedst);
    //ret=1 找到了，要解析case；ret=2 已被解析，直接返回
    if(ret==1&&cases==0)
    {
      //errs()<<"analyseSt: "<<si->getStmtClassName()<<"\n";
      return 1;
    }
    if(ret==1)
    {
      switch (cases)
      {
      case 1:
      {
        if(visitedst.find(myif)!=visitedst.end())
        {
          returnval=2;
        }
        visitedst.insert(myif);
        handleIfStmt(myif);
        break;
      }
      case 2:
      {
        //errs()<<"case == 2\n";
        const Stmt* parent=FuncMap[call];
        //bool isLnot=false;
        if(parent){
          if(isa<UnaryOperator>(parent))
          {
            //isLnot=true;
            hasnot=!hasnot;
          }
        }
        
        const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
        int type=0;
        const Stmt* res;
        bool findcall=false;
        for(const auto *s:body->body())
        {
          if(const Stmt* st=dyn_cast<Stmt>(s))
          {
            res=getStmtwithVar(st,findcall,type);
            if(res)
              break;
          }
        }
        if(type==1)
        {
          //errs()<<"find var in if\n";
          const IfStmt* ifst=dyn_cast<IfStmt>(res);
          const Expr* cond=ifst->getCond();
          const Stmt* target=getChildwithCallorVar(cond,"var");
          if(FindUnaryOperator(cond,false,"!var"))
          {
            //isLnot=!isLnot;
            hasnot=!hasnot;
          }
          //if(!=)
          const Stmt* parent=NULL;
          if(FuncMap.find(target)!=FuncMap.end())
            parent=FuncMap[target];
          if(const BinaryOperator* bop=dyn_cast<BinaryOperator>(parent))
          {
            if(bop->getOpcode()==BinaryOperator::Opcode::BO_NE)
            {
              //isLnot=!isLnot;
              hasnot=!hasnot;
            }
          }
          if(hasnot)
          {
            handleLNotIf(ifst);
          }
          else{
            handleDirectIf(ifst);
          }
          //如果是switchcase里没找到被保护的资源，就不继续向上看了
          const Stmt* casest=findParent(ifst,"case");
          if(!chkp2resource->hasCrits())
          {
            if(!casest)
            {
             //errs()<<"var->if didnt get crits add to next time\n";
              AddToNextTime(); 
              returnval=1;
            }
          }
        }
        else if(type==2)
        {
          //errs()<<"caught a decl in return\n";
          const ReturnStmt* retst=dyn_cast<ReturnStmt>(res);
          if(FindUnaryOperator(retst,false,"!"))
          {
            hasnot=!hasnot;
          }
        }
        else{
          errs()<<"unresolved type "<<type<<"\n";
        }
        break;
      }
      case 3:
      {
        if(FindUnaryOperator(myret,false,"!"))
        {
          hasnot=!hasnot;
        }
        //errs()<<"return type add to next time\n";
        AddToNextTime();
        returnval=1;
        break;
      }     
      default:
        break;
      }
      return 2;
    }
  }
  return ret;
}
void MyClangCheck::TranverseStmt(const Stmt* st)
{
  if(!st)
    return;  
  for(const auto* child:st->children())
  {
    if(!child)
      return;
    if(const Stmt* current=dyn_cast<Stmt>(child))
    {
      FuncMap[current]=st;
      //errs()<<"tranverseStmt insert "<<current->getStmtClassName()<<":"<<st->getStmtClassName()<<"\n";
      for(const auto* grand:current->children())
      {
        if(!grand)
          return;
        if(const Stmt* grand_current=dyn_cast<Stmt>(grand))
        {
          FuncMap[grand_current]=current;
          TranverseStmt(grand_current);
        }         
      }
    } 
  }
}
void MyClangCheck::VisitFunc( )
{
  if(funcdecl->hasBody())
  {
    const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
    //setend(body->body_back());
    const Stmt* last=FindLastStmt(body);
    if(last!=NULL)
    {
      setend(last);
    }
    else{
      errs()<<"didnot find last stmt,setend failed\n";
    }
    
    for(const auto *s:body->body())
    {     
      if(const Stmt* st=dyn_cast<Stmt>(s))
      {
        FuncMap[st]=body;
        TranverseStmt(st);   
            
      }
    }
  }
}
int MyClangCheck::analyseFunc(StmtSet& visitedst)
{
  int ret=0;
  if(const FunctionDecl* fdecl=dyn_cast<FunctionDecl>(funcdecl))
  {
    string fundecl_name=fdecl->getNameAsString().c_str();
    errs()<<"in MyClangCheck analyse function "<<fundecl_name<<"\n";
    //先将caller加入被保护的list
    fundecl_name="caller:"+fundecl_name;
    list<string>::iterator it=find(pro_funcs_old.begin(),pro_funcs_old.end(),fundecl_name);
    list<string>::iterator _it=find(pro_funcs.begin(),pro_funcs.end(),fundecl_name);
    if(it==pro_funcs_old.end()&&_it==pro_funcs.end())
    {
      //if(pro_funcs.empty())
        //pro_funcs.push_back(chkp2resource->capname);
      if(chkp2resource->capname!=oldcap)
      {
        pro_funcs.push_back(chkp2resource->capname);
        oldcap=chkp2resource->capname;
      }
      pro_funcs.push_back("caller:"+fundecl_name);
      pro_funcs_number++;
    }
    //const Stmt* retst=FindLastReturn();
  }
   VisitFunc();
  if(funcdecl->hasBody())
  {
    const auto* body=dyn_cast<CompoundStmt>(funcdecl->getBody());
    //const IfStmt* myif;
    //const ReturnStmt* myret;
    for(const auto *s:body->body())
    {
      if(isa<Stmt>(s))
      {
        ret=analyseStmt(s,false,visitedst);
      }
      if(ret!=0)
        break;
    }
  }
  return 0; 
}

class FunctionCallPrinter : public MatchFinder::MatchCallback {
public :
  int count=0;
  int unresolved=0;
  int count_ret=0;
  int count_direct=0;
  int analysed=0;
  int  And_protect=0;
  int Or_protect=0;
  //string oldcap="";
  //string curcap="";
  string unresolved_chkp="";
  std::string cur_caller=""; 
  //handle one check point has two capability check
  StmtSet visitedst;
  virtual void run(const MatchFinder::MatchResult &Result) {
    if(auto *caller = Result.Nodes.getNodeAs<clang::FunctionDecl>("caller")) 
    {
      if(caller->getNameInfo().getAsString()!=""&&cur_caller!=caller->getNameInfo().getAsString())
        {
          cur_caller=caller->getNameInfo().getAsString();
        }
      //call->dump();
      if(const auto *call = Result.Nodes.getNodeAs<clang::CallExpr>("functioncall")) 
      {
        std::string cur_check=call->getDirectCallee()->getNameInfo().getAsString();
        const auto & sourcemanager=caller->getASTContext().getSourceManager();
        SourceLocation chkp=call->getExprLoc();
        string printloc=chkp.printToString(sourcemanager);
        //const FileEntry* Entry = sourcemanager.getFileEntryForID(sourcemanager.getFileID(caller.getCaretLocation()));
        //const char* FileName = Entry->getName();
        //errs()<<"find check func "<<cur_check<<"\n";
        count++;
        clang::LangOptions LangOpts;
        LangOpts.CPlusPlus = true;
        clang::PrintingPolicy Policy(LangOpts);
        std::string CapArg;
        llvm::raw_string_ostream s(CapArg);
        string cap_name="";
        bool has_not=false;
        if(tobeVisited.empty())
        {
          int cap_pos=42;
          if(cur_check=="netlink_ns_capable")
          {
            call->getArg(2)->printPretty(s, 0, Policy);
          }
          if(cur_check=="has_capability_noaudit"){
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="capable_wrt_inode_uidgid")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="file_ns_capable")
          {
            call->getArg(2)->printPretty(s, 0, Policy);
          }
          if(cur_check=="sk_ns_capable")
          {
            call->getArg(2)->printPretty(s, 0, Policy);
          }
          if(cur_check=="map_write")
          {
            call->getArg(4)->printPretty(s, 0, Policy);
          }
          if(cur_check=="has_ns_capability")
          {
            call->getArg(2)->printPretty(s, 0, Policy);
          }
          if(cur_check=="netlink_net_capable")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="sk_net_capable")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="ns_capable")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="capable")
          {
            call->getArg(0)->printPretty(s, 0, Policy);
          }
          if(cur_check=="__netlink_ns_capable")
          {
            call->getArg(2)->printPretty(s, 0, Policy);
          }
          if(cur_check=="has_capability")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="ns_capable_setid")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="ns_capable_noaudit")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="has_ns_capability_noaudit")
          {
            call->getArg(2)->printPretty(s, 0, Policy);
          }
          if(cur_check=="sk_capable")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="netlink_capable")
          {
            call->getArg(1)->printPretty(s, 0, Policy);
          }
          if(cur_check=="smack_privileged")
          {
            call->getArg(0)->printPretty(s, 0, Policy);
          }
          if(cur_check=="perf_cap__capable")
          {
            call->getArg(0)->printPretty(s, 0, Policy);
          }
          cap_pos=atoi(s.str().c_str());
          errs()<<"cap_pos:"<<cap_pos<<"\n";
          if(cap_pos>=0&&cap_pos<41)
            cap_name=caps[cap_pos];
          else
          {
            errs()<<"unknown cap,cap maybe a arg\n"; 
            ofstream outfile;
            outfile.open("/home/zcq/mjz/clang/res/unresolved.txt",ios::app);
            outfile << "chkp with unknown cap:"+printloc;
          }                    
        }
        else{
          //not the first time analyze
          for(list<string>::iterator it=tobeVisited.begin();it!=tobeVisited.end();it++)
          {
            string TV_cur=*it;
            string fname=TV_cur.substr(0,TV_cur.find_first_of(":")); 
            if(fname==cur_check)
            {
              cap_name=TV_cur.substr(TV_cur.find_first_of(":")+1);
              string last_part=TV_cur.substr(TV_cur.find_last_of(":"));
              cap_name=cap_name.substr(0,cap_name.find_first_of(":"));
              if(last_part.find("!")!=string::npos)
              {
                has_not=true;
                //errs()<<"has not at first!\n";
              } 
            }
          }
        }      
        //llvm::errs() << "arg: " <<call->getArg(0)->getType().getAsString()<<" "<< s.str() << " related cap is "<<caps[cap_pos]<<"\n";    
        //const FileEntry* entry=sourcemanager.getFileEntryForID(sourcemanager.getFileID(chkp));
        //string fname = entry->getName();
        string capname=cap_name;
        if(cap_name.find("!")!=string::npos)
          string capname=cap_name.replace(cap_name.find("!"),1,"");
        //curcap=capname;


        errs()<<"sourceLocation print: "<<printloc+" "+cap_name<<"\n";
        Chkp2Resource cur_chkp=Chkp2Resource(printloc);
        cur_chkp.setCapName(cap_name);
        MyClangCheck mycheck(caller,call,&cur_chkp,has_not);        
        mycheck.analyseFunc(visitedst);

        string criticals="";
        if(cur_chkp.getFunctions()!="")
        {
          criticals=" proteced functions: "+cur_chkp.getFunctions()+"\n";
          errs()<<" proteced functions "<<cur_chkp.getFunctions()<<"\n";
        }
        if(cur_chkp.getVars()!="")
        {
          criticals=criticals+"proteced vars: "+cur_chkp.getVars()+"\n";
          errs()<<" proteced vars "<<cur_chkp.getVars()<<"\n";
        }
        if(cur_chkp.getFunctions()==""&&cur_chkp.getVars()=="")
        {
          if(mycheck.returnval!=1)
          {
            unresolved++;
            unresolved_chkp=printloc+" CAP check function:"+cur_check+" CAP user function:"+cur_caller+"\n";
          }
        }
        if(mycheck.returnval==3)
        {
          And_protect++;
          criticals="same check point, And protection same as above\n";
          errs()<<"######same check point, And protection same as above\n";
          //analysed++;
        }
        if(mycheck.returnval==4)
        {
          Or_protect++;
          criticals="same check point, Or protection same as above\n";
          errs()<<"######same check point, Or protection same as above\n";
          //analysed++;
        }
        if(mycheck.returnval==1)
        {
          count_ret++;
        }
        if(mycheck.returnval==5)
        {
          count_direct++;
        }
        if(criticals!="")
        {
          ofstream outfile;
          outfile.open("/home/zcq/mjz/clang/res/crits.txt",ios::app);
          outfile<<printloc+":"+mycheck.funcdecl->getNameInfo().getAsString()+":"+cap_name+"\n";
          //if(criticals!="")
          //{
          outfile << criticals << endl;
          //}       
          outfile.close();
        } 
      }
    }
  }
  
};

int main(int argc, const char **argv) {
  int ret;
  FunctionCallPrinter Printer;
  MatchFinder Finder;
  CommonOptionsParser OptionsParser(argc, argv, MyToolCategory);
  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());
  Tool.appendArgumentsAdjuster(clang::tooling::getInsertArgumentAdjuster(
    "-ferror-limit=0"));
  //TODO:if tobeVisited not null,should generate functionMactch
  //else is the first time analyze
  ifstream input_Pfuncs;
  input_Pfuncs.open("/home/zcq/mjz/clang/res/protected_functions.txt", ios::in);
  if (input_Pfuncs.is_open())
  {
    string line;
    while(getline(input_Pfuncs,line))
    {
      string current=line;
      if(current!="")
      {
        pro_funcs_old.push_back(current);
      }       
    }
  }
  bool has_tovisit=true;
  ifstream ifs;
  ifs.open("/home/zcq/mjz/clang/res/toVisitNextTime.txt", ios::in);
  if (!ifs.is_open())
  {
	  //cout << "文件不存在！" << endl;
    has_tovisit=false;
  }
  if(has_tovisit)
  {
    string line;
    while(getline(ifs,line))
    {
      string current=line;
      tobeVisited.push_back(current);
    }
    ifs.close();
    list<string>::iterator it;
    vector<string> FunctionNames; 
    for(it=tobeVisited.begin();it!=tobeVisited.end();it++)
    {
      string TV_cur=*it;
      string fname=TV_cur.substr(0,TV_cur.find_first_of(":"));      
      if(fname!="")
      {
        errs()<<"######add tovisted fun name "<<fname<<"\n";
        FunctionNames.push_back(fname);
      }      
    }
    errs()<<"######init FunctionNames, has "<<FunctionNames.size()<<" number \n";
    vector<StringRef> FunctionNameRefs=vector<StringRef>(FunctionNames.begin(),FunctionNames.end());
    StatementMatcher NextFunctionMatcher =callExpr(isExpansionInMainFile(),callee(functionDecl(hasAnyName
    (FunctionNameRefs))),hasAncestor(functionDecl().bind("caller"))).bind("functioncall");
    Finder.addMatcher(NextFunctionMatcher, &Printer);
    ret=Tool.run(newFrontendActionFactory(&Finder).get());
     if(Printer.count==0)
    {
      //errs()<<"did not find function used cap check function,maybe used by struct\n";
      errs()<<"######Pstruct\n";
    }
    //errs()<<"find "<<Printer.count<<" check point,unresolved "<<Printer.unresolved<<" check point \n";  
  }
  else{
    //FunctionCallPrinter Printer;
    //MatchFinder Finder;
    Finder.addMatcher(FunctionMatcher, &Printer);
    ret=Tool.run(newFrontendActionFactory(&Finder).get());
    //record file contains cap check function
    if(Printer.count>0)
    {
      errs()<<"\n######firstnum:total check point:"<<Printer.count<<",unresolved:"<<Printer.unresolved<<", return type:"<<Printer.count_ret
  <<", direct protect:"<<Printer.count_direct<<", And protect:"<<Printer.And_protect<<", Or protect:"<<Printer.Or_protect<<"\n"; 
    } 
  }
 
  errs()<<"######num:total check point:"<<Printer.count<<",unresolved:"<<Printer.unresolved<<", return type:"<<Printer.count_ret
  <<", direct protect:"<<Printer.count_direct<<"\n"; 
  if(Printer.unresolved!=0)
  {
    errs()<<"######unresolved:"<<Printer.unresolved_chkp;
  }
  if(!VisitNextTime.empty())
  {
    errs()<<"######add "<<VisitNextTime.size()<<" functions to visit next time\n";
    string toVisitNext="";
    for(list<string>::iterator it=VisitNextTime.begin();it!=VisitNextTime.end();it++)
    {
      toVisitNext=toVisitNext+*it+"\n";
    }
    if(toVisitNext!="")
    {
      ofstream outfile;
      outfile.open("/home/zcq/mjz/clang/res/toVisitNextTime.txt",ios::out | ios::trunc );
      outfile << toVisitNext << endl;
      outfile.close();
    } 
  }
  else
  {
    errs()<<"######tovisit is emopty now, done\n";
    ifstream f("/home/zcq/mjz/clang/res/toVisitNextTime.txt");
    if(f.good())
    {
      remove("/home/zcq/mjz/clang/res/toVisitNextTime.txt");
    }
  }
  errs()<<"######protected function: "<<pro_funcs_old.size()+pro_funcs_number<<"\n"; 
  if(!pro_funcs.empty())
  {
    string pro_fun_all="";
    for(list<string>::iterator it=pro_funcs.begin();it!=pro_funcs.end();it++)
    {
      pro_fun_all=pro_fun_all+*it+"\n";
    }
    if(pro_fun_all!="")
    {
      ofstream outfile;
      outfile.open("/home/zcq/mjz/clang/res/protected_functions.txt",ios::app);
      outfile << pro_fun_all;
      outfile.close();
    }
  }

  return ret;
}

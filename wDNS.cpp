#include <iostream>
#include <winsock2.h>
#include <vector>
#include <stdio.h>
#include <map>

using namespace std;

#define prt(x) std::cout<<x<<std::endl<<std::flush
#define inp(x) std::cin>>x

#define FASTADDR(a,x,y,z) ((sockaddr_in*)&a)->sin_family=x;\
  ((sockaddr_in*)&a)->sin_addr.s_addr=inet_addr(y);\
  ((sockaddr_in*)&a)->sin_port=htons(z)

#define FASTADDR_ANY(a,x,z) ((sockaddr_in*)&a)->sin_family=x;\
  ((sockaddr_in*)&a)->sin_addr.s_addr=INADDR_ANY;\
  ((sockaddr_in*)&a)->sin_port=htons(z)

#define INITWSA  \
  WORD wVersionRequested;\
  WSADATA wsaData;\
  wVersionRequested=MAKEWORD(1, 1);\
  WSAStartup(wVersionRequested, &wsaData)

#define FASTGETIP(cli) inet_ntoa(((sockaddr_in*)&cli)->sin_addr)

#define FASTGETPORT(cli) ntohs(((sockaddr_in*)&cli)->sin_port)

#define GOOD_TAG 0x8180

sockaddr mdns;

struct dns_header
{
  short ID;
  short TAG;
  short QDCOUNT;
  short ANCOUNT;
  short NSCOUNT;
  short ARCOUNT;
};

struct dns_question
{
  short QTYPE;
  short QCLASS;
};

struct dns_resource
{
  short RTYPE;
  short RCLASS;
  long  TTL;
  short RDLENGTH;
};

std::vector<string> splitstr(string str,char c)
{
  u_long c_pos=0;
  u_long pre=-1;
  vector<string> res;
  while(c_pos!=str.npos)
    {
      c_pos=str.find(c,c_pos+1);
      res.push_back(str.substr(pre+1,c_pos-pre-1));
      pre=c_pos;
    }
  return res;
}

void encodehn(string source,char *dest,int *len)
{
  memset(dest,0,*len);
  char label;
  string tmp;
  vector<string> hostl = splitstr(source,'.');
  for(string i : hostl)
    {
      label=i.length();
      tmp+=label;
      tmp+=i;
    }
  strcpy(dest,tmp.c_str());
  *len=tmp.length()+1;
}

string gethostn(char *pos,int *len)
{
  char *n=pos;
  char res[256]={0};
  int lend=0;
  int sc=0;
  while(*n)
    {
      lend=*n;
      for(int i=0;i<lend;++i)
        {
          *(res+(int)n-(int)pos+i)=*(n+i+1);
        }
      n+=lend+1;
      *(res+(int)n-(int)pos-1)='.';
      ++sc;
    }
  *(res+(int)n-(int)pos-1)=0;
  *len=n-pos+sc;
  return res;
}


struct hdata
{
  char a;
  char b;
  char c;
  char d;
};

vector<string> shlist;
map<string,hdata> shmap;

void gethimone(SOCKET dns_fd,sockaddr *cli,char *buf,int len,string hostn)
{
  ((dns_header*)buf)->TAG=htons(GOOD_TAG);
  ((dns_header*)buf)->ANCOUNT=htons(1);
  char hotn[50];
  int jlen=50;
  encodehn(hostn,hotn,&jlen);
  dns_resource r;
  memset(&r,0,sizeof(r));
  r.TTL=htonl(50);
  r.RTYPE=htons(1);
  r.RCLASS=htons(1);
  r.RDLENGTH=htons(4);
  memmove(buf+len,hotn,jlen);
  memmove(buf+jlen+len,&r,10);
  memmove(buf+jlen+len+10,&(shmap[hostn]),4);
  sendto(dns_fd,buf,len+jlen+10+4,0,cli,sizeof(sockaddr));
}

void fuckhimaway(SOCKET dns_fd,sockaddr *cli,char *buf,int len)
{
  SOCKET sck= socket(AF_INET,SOCK_DGRAM,0);
  int timeout = 3000;
  setsockopt(sck,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
  sendto(sck,buf,len,0,&mdns,sizeof(mdns));
  char buf2[1024]={0};
  int glen=recvfrom(sck,buf2,1024,0,NULL,NULL);
  if(glen>0)
    {
      sendto(dns_fd,buf2,glen,0,cli,sizeof(sockaddr));
    }
}

bool checkthere(string hostn)
{
  for(string i : shlist)
    {
      if(hostn==i)
        return true;
    }
  return false;
}


int main()
{
  prt("wDNS Server");
  prt("Initing...");
  INITWSA;

  shlist.push_back("widesenseshit.com");
  hdata ws;
  ws.a=198;
  ws.b=148;
  ws.c=94;
  ws.d=23;
  shmap["widesenseshit.com"]=ws;
  shlist.push_back("www.widesenseshit.com");
  hdata ws2;
  ws2.a=198;
  ws2.b=148;
  ws2.c=94;
  ws2.d=23;
  shmap["www.widesenseshit.com"]=ws2;

  SOCKET dns_fd= socket(AF_INET,SOCK_DGRAM,0);
  sockaddr tobind;
  FASTADDR(mdns,AF_INET,"114.114.114.114",53);
  FASTADDR_ANY(tobind,AF_INET,53);
  int err = bind(dns_fd,&tobind,sizeof(tobind));
  if(err)
    {
      prt("Unable to bind port 53");
      return -1;
    }
  sockaddr cli;
  memset(&cli,0,sizeof(cli));
  int alen = sizeof(cli);

  prt("Server on");
  int glen;
  char buf[1024]={0};
  while(1)
    {
      glen = recvfrom(dns_fd,buf,1024,0,&cli,&alen);
      string rt = "IP ";
      rt+=FASTGETIP(cli);
      rt+=" ask for ";
      int shit;
      rt+=gethostn(buf+sizeof(dns_header),&shit) + ".";
      if(checkthere(gethostn(buf+sizeof(dns_header),&shit)))
        {
          rt+="SECRET.";
          gethimone(dns_fd,&cli,buf,glen,gethostn(buf+sizeof(dns_header),&shit));
        }
      else
        {
          rt+="NON-SECRET,redirecting to 8.8.8.8.";
          fuckhimaway(dns_fd,&cli,buf,glen);
        }
      memset(&cli,0,sizeof(cli));
      memset(buf,0,1024);
      rt+="Dealed";
      prt(rt);
    }
  return 0;
}

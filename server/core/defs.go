package core

import (
	"github.com/gin-gonic/gin"
	"sync"
)

var (
	TRANSPORT_HTTP uint32 = 0x00000001
	TRANSPORT_PIPE uint32 = 0x00000002

	TypeCheckin  uint32 = 0x7FFFFFFF
	TypeTasking  uint32 = 0x7FFFFFFE
	TypeResponse uint32 = 0x7FFFFFFD
	TypeSegment  uint32 = 0x7FFFFFFC

	CommandDir        uint32 = 0x00000001
	CommandMods       uint32 = 0x00000002
	CommandNoJob      uint32 = 0x00000003
	CommandShutdown   uint32 = 0x00000004
	CommandUpdatePeer uint32 = 0x00000005
)

type Callback struct {
	MsgType string
	Msg     string
}

type Stream struct {
	Buffer []byte
	Length int
}

type TableMap struct {
	Headers []string
	Values  [][]string
}

type Object struct {
	Type                 string
	ConfigName           string
	OutputName           string
	RootDirectory        string
	Linker               string
	Implant              bool
	RsrcScript           string
	RsrcBinary           string
	IncludeDirectories   []string
	Sources              []string
	PreBuildDependencies []string
	Dependencies         []string
	Components           []string
}

type Config struct {
	Arch       string
	Debug      bool
	BuildType  string
	Hostname   string
	EgressPeer string
	Sleeptime  int
	Jitter     int
}

type Threadless struct {
	ConfigName string
	ProcName   string
	ModuleName string
	FuncName   string
	Execute    string
}

type Injection struct {
	Object     *Object
	Threadless *Threadless
}

type InjectConfig struct {
	InjectConfig []byte
	ExecuteObj   string
	Strings      []string
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
	ProfileTypeId uint32
	CurrentTaskId uint32
	IngressPipe   string
	EgressPeer    string
	EgressPipe    string
	LoadedModules []string

	Hostname     string
	Domain       string
	WorkingHours string
	Sleeptime    uint32
	Jitter       uint32
	Killdate     int64
	ProxyBool    bool

	Injection *Injection
}

type CompilerConfig struct {
	Debug          bool
	Arch           string
	Mingw          string
	Linker         string
	Objcopy        string
	Assembler      string
	Windres        string
	Strip          string
	Ar             string
	FileExtension  string
	BuildDirectory string
	Definitions    map[string][]byte
	Source         []string
	Includes       []string
	Flags          []string
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

type HexaneConfig struct {
	ImplantName   string
	GroupId       int
	CurrentTaskId int
	PeerId        uint32
	Mu            sync.Mutex

	Key         []byte
	Shellcode   []byte
	ConfigBytes []byte
	Components  []string
	Active      bool
	BuildType   string

	ImplantCFG  *ImplantConfig
	CompilerCFG *CompilerConfig
	ServerCFG   *ServerConfig
	ProxyCFG    *ProxyConfig
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

type Parser struct {
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
	Username string
	Admin    bool
}

type Headers struct {
	Key string
	Val string
}

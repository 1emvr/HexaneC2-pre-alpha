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

type Module struct {
	Type                 string
	RootDir              string
	OutputDir            string
	OutputName           string
	Linker               string
	Directories          []string
	Sources              []string
	Includes             []string
	Dependencies         []string
	PreBuildDependencies []string
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
	ProcName   string
	ModuleName string
	FuncName   string
	Execute    string
}

type Threadpool struct {
	None string
}

type Injection struct {
	Threadless *Threadless
	Threadpool *Threadpool
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
	PeerId        uint32
	IngressPipe   string
	EgressPeer    string
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
	ProxyBool    bool
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
	Windres        string
	Strip          string
	Ar             string
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
	Mu          sync.Mutex

	Key         []byte
	ConfigBytes []byte
	Components  []string
	Shellcode   string
	Main        string
	Active      bool
	BuildType   string

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

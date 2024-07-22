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

type Threadless struct {
	ProcName   string
	ModuleName string
	FuncName   string
	Execute    string
}

type Json struct {
	Config  *JsonConfig
	Network *JsonNetwork
	Build   *JsonObject
}

type JsonConfig struct {
	Arch       string
	Debug      bool
	Hostname   string
	Sleeptime  int
	Jitter     int
	EgressPeer string
}

type JsonNetwork struct {
	ProfileType string
	Config      interface{}
}

type JsonObject struct {
	Type                 string
	ObjectName           string
	RootDirectory        string
	Linker               string
	Implant              bool
	RsrcScript           string
	RsrcBinary           string
	SourceDirectories    []string
	IncludeDirectories   []string
	Sources              []string
	Flags                []string
	PreBuildDependencies []string
	Dependencies         []string
	Components           []string
	Definitions          map[string][]byte
}

type HttpConfig struct {
	Address   string
	Domain    string
	Port      int
	Useragent string
	Endpoints []string
	Headers   []string
}

type SmbConfig struct {
	EgressPeer     string
	EgressPipename string
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
	LoadedModules []string

	Hostname     string
	Domain       string
	WorkingHours string
	Sleeptime    uint32
	Jitter       uint32
	Killdate     int64
	ProxyBool    bool
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
	GroupId       int
	CurrentTaskId int
	PeerId        uint32
	Mu            sync.Mutex

	Key         []byte
	Shellcode   []byte
	ConfigBytes []byte
	Active      bool

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

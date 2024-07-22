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

type TypedConfig struct {
	Type   string
	Config interface{}
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
	TargetProc   string
	TargetModule string
	TargetFunc   string
	LoaderAsm    string
	Execute      string
}

type Files struct {
	Sources              []string
	IncludeDirectories   []string
	Dependencies         []string
	PreBuildDependencies []string
}

type Loader struct {
	Rsrc          *Rsrc
	RootDirectory string
	InjectionType string
	LinkerScript  string
	MainFile      string
	Config        interface{}
}

type Rsrc struct {
	RsrcScript string
	RsrcBinary string
}

type Module struct {
	BuildType     int
	OutputName    string
	RootDirectory string
	LinkerScript  string
	Rsrc          *Rsrc
	Files         *Files
	Loader        *Loader
	Components    []string
	Definitions   map[string][]byte
}

type Network struct {
	ProfileType string
	IngressPipe string
	IngressPeer uint32
	GroupId     int
	Config      interface{}
}

type Config struct {
	Arch         string
	Debug        bool
	Hostname     string
	WorkingHours string
	Sleeptime    int
	Jitter       int
}

type JsonConfig struct {
	Config  *Config
	Network *Network
	Builder *Module
}

type Http struct {
	GroupId   int
	Address   string
	Domain    string
	Useragent string
	Port      int
	Endpoints []string
	Headers   []string
	Proxy     *Proxy
	Handle    *gin.Engine
	SigTerm   chan bool
	Success   chan bool
	Next      *Http
}

type Smb struct {
	EgressPeer      string
	IngressPeer     string
	EgressPipename  string
	IngressPipename string
}

type Proxy struct {
	Address  string
	Port     string
	Proto    string
	Username string
	Password string
}

type Implant struct {
	NetworkProfile any
	PeerId         uint32
	GroupId        uint32
	ProfileTypeId  uint32
	CurrentTaskId  uint32
	LoadedModules  []string

	Hostname     string
	WorkingHours int32
	Sleeptime    uint32
	Jitter       uint32
	Killdate     int64
	ProxyBool    bool
}

type Compiler struct {
	Debug          bool
	Arch           string
	Mingw          string
	Linker         string
	Objcopy        string
	Assembler      string
	Windres        string
	Strip          string
	FileExtension  string
	BuildDirectory string
	Flags          []string
}

type HexaneConfig struct {
	GroupId       int
	CurrentTaskId int
	BuildType     int
	PeerId        uint32
	Mu            sync.Mutex

	Key         []byte
	Shellcode   []byte
	ConfigBytes []byte
	Active      bool

	Implant     *Implant
	Compiler    *Compiler
	UserSession *Session
	UserConfig  *JsonConfig
	Next        *HexaneConfig
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

type Payloads struct {
	Head  *HexaneConfig
	Group int
}

type ServerList struct {
	Head  *Http
	Group int
}

type Session struct {
	Username string
	Admin    bool
}

type Headers struct {
	Key string
	Val string
}

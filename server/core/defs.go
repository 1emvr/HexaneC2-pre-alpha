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

type Message struct {
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

type Sources struct {
	Sources              []string
	IncludeDirectories   []string
	Dependencies         []string
	PreBuildDependencies []string
}

type Loader struct {
	RootDirectory string
	LinkerScript  string
	RsrcScript    string
	RsrcBinary    string
	Sources       []string
	Injection     *TypedConfig
}

type Module struct {
	BuildType     int
	OutputName    string
	RootDirectory string
	LinkerScript  string
	Files         *Sources
	Loader        *Loader
	Components    []string
	Definitions   map[string][]byte
}

type Config struct {
	Arch         string
	Debug        bool
	Hostname     string
	WorkingHours string
	Sleeptime    int
	Jitter       int
}

type Network struct {
	IngressPipename string
	IngressPeer     uint32
	GroupId         int
	Config          interface{}
}

type Smb struct {
	EgressPipename string
	EgressPeer     string
}

type Http struct {
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

type Proxy struct {
	Address  string
	Port     string
	Proto    string
	Username string
	Password string
}

type JsonConfig struct {
	Config *struct {
		Arch         string
		Debug        bool
		Hostname     string
		WorkingHours string
		Sleeptime    int
		Jitter       int
	}

	Network *TypedConfig

	Builder *struct {
		OutputName         string
		RootDirectory      string
		LinkerScript       string
		Sources            []string
		Dependencies       []string
		IncludeDirectories []string
	}

	Loader *struct {
		RootDirectory string
		LinkerScript  string
		RsrcScript    string
		RsrcBinary    string
		Sources       []string
		Dependencies  []string
		Injection     *TypedConfig
	}
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

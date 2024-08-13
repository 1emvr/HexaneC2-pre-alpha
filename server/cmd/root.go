package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/spf13/cobra"
	"hexane_server/core"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var banner = `
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗     ██████╗██████╗ 
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝    ██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗█████╗██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝╚════╝██║     ██╔═══╝ 
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗    ╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝     ╚═════╝╚══════╝`

var rootCmd = &cobra.Command{
	Use:   "HexaneC2",
	Short: "Minimal command & control framework",
	Long:  "Minimal command & control framework",
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "d", false, "debug mode")
	rootCmd.PersistentFlags().BoolVarP(&core.ShowCommands, "show-commands", "c", false, "debug command mode")
	rootCmd.PersistentFlags().BoolVarP(&core.ShowConfigs, "show-configs", "j", false, "debug json configs")
	rootCmd.AddCommand(Implants)
}

func PrintChannel(cb chan core.Message, exit chan bool) {

	for {
		select {
		case x := <-exit:
			if x {
				return
			}
		case m := <-cb:
			if !core.Debug && m.MsgType == "DBG" {
				continue
			}

			fmt.Println(fmt.Sprintf("[%s] %s", m.MsgType, m.Msg))
		}
	}
}

func HookVCVars() error {
	var (
		err      error
		vcvars   []byte
		env_vars []byte
	)

	err = filepath.Walk(core.VCVarsInstall, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Name() == "vcvars64.bat" {
			core.VCVarsInstall = path
			return filepath.SkipDir
		}

		return nil
	})
	if err != nil {
		return err
	}

	if vcvars, err = ioutil.ReadFile(core.VCVarsInstall); err != nil {
		return err
	}

	hook := []byte("set > %TMP%\vcvars.txt")

	if !bytes.Contains(vcvars, hook) {
		vcvars = append(vcvars, []byte("\n")...)
		vcvars = append(vcvars, hook...)
	}

	if err = ioutil.WriteFile(core.VCVarsInstall, vcvars, 0644); err != nil {
		return err
	}

	if err = core.RunCommand(core.VCVarsInstall, "hook_vcvars"); err != nil {
		return err
	}

	if env_vars, err = ioutil.ReadFile(core.VCVarsInstall); err != nil {
		return err
	}

	lines := strings.Split(string(env_vars), "\n")

	for _, line := range lines {
		parts := bytes.SplitN([]byte(line), []byte("="), 2)

		if len(parts) == 2 {
			k := string(parts[0])
			v := string(parts[1])

			if err = os.Setenv(k, v); err != nil {
				return err
			}
		}
	}

	core.WrapMessage("INF", "msvc environment context loaded")
	return nil
}

func RootInit() error {
	var err error

	if err = rootCmd.ParseFlags(os.Args[1:]); err != nil {
		return err
	}
	if core.Debug {
		core.WrapMessage("INF", "running in debug mode")
	}
	if core.ShowCommands {
		core.WrapMessage("INF", "running with command output")
	}
	if core.ShowConfigs {
		core.WrapMessage("INF", "running with json config output")
	}

	if err = core.CreatePath(core.LogsPath, os.ModePerm); err != nil {
		return err
	}
	if err = core.CreatePath(core.BuildPath, os.ModePerm); err != nil {
		return err
	}

	err = filepath.Walk(core.NetFXSDK, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Name() == "metahost.h" {
			core.NetFXSDK = filepath.Dir(path)
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		return err
	}
	if core.NetFXSDK == "C:/Program Files(x86)/Windows Kits/NETFXSDK/" {
		return fmt.Errorf("metahost.h not found anywhere in %s", core.NetFXSDK)
	}

	return err
}

func Run() error {
	var (
		err    error
		input  string
		args   []string
		reader = bufio.NewReader(os.Stdin)
	)

	fmt.Println(banner)
	go PrintChannel(core.Cb, core.Exit)

	if err = RootInit(); err != nil {
		return err
	}

	for {
		if input, err = reader.ReadString('\n'); err != nil {
			core.WrapMessage("ERR", err.Error())
			continue
		}

		input = strings.TrimSpace(input)
		if args = strings.Split(input, " "); args[0] == "exit" {
			core.Exit <- true
			break
		}

		rootCmd.SetArgs(args)

		if err = rootCmd.Execute(); err != nil {
			core.WrapMessage("ERR", err.Error())
			continue
		}
	}
	return nil
}

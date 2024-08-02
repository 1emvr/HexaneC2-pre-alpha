package core

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/net/context"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func ParseHeaders(context *gin.Context) []Headers {
	var heads []Headers

	for key, headers := range context.Request.Header {
		for _, value := range headers {

			vals := Headers{key, value}
			heads = append(heads, vals)
		}
	}
	return heads
}

func (h *HexaneConfig) ServerRoutine(context *gin.Context) {
	var (
		err       error
		body, rsp []byte
	)

	if body, err = ioutil.ReadAll(context.Request.Body); err != nil {
		WrapMessage("ERR", err.Error())
	}

	if rsp, err = ResponseWorker(body); err != nil {
		WrapMessage("ERR", err.Error())
	}

	//context.String(200, base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(rsp))
	context.String(200, string(rsp))
}

func (h *HexaneConfig) UpdateServerEndpoints(profile *Http) {

	chanNewEndp := make(chan string)
	defer close(chanNewEndp)

	go func() {
		for endp := range chanNewEndp {
			profile.Handle.GET(endp, func(context *gin.Context) {
				h.ServerRoutine(context)
			})
		}
	}()

	for _, newEndp := range profile.Endpoints {
		endpointExists := false

		for _, existingEndp := range profile.Endpoints {
			if existingEndp == newEndp {

				endpointExists = true
				break
			}
		}
		if !endpointExists {
			profile.Endpoints = append(profile.Endpoints, newEndp)
			chanNewEndp <- newEndp
		}
	}
}

func (h *HexaneConfig) StartNewServer(profile *Http) error {
	var err error

	profile.Handle = gin.Default()
	if !Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	for _, endp := range profile.Endpoints {
		profile.Handle.GET(endp, func(context *gin.Context) {
			h.ServerRoutine(context)
		})
	}

	server := &http.Server{
		Addr:    profile.Address + ":" + strconv.Itoa(profile.Port),
		Handler: profile.Handle,
	}

	go func() {
		if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return
		}
	}()
	if err != nil {
		return err
	}

	go func() {
		<-profile.SigTerm

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		WrapMessage("INF", "shutting down "+server.Addr)
		if err = server.Shutdown(ctx); err != nil {
			return
		}
	}()
	if err != nil {
		return err
	}

	WrapMessage("INF", fmt.Sprintf("server started on %s:%d", profile.Address, profile.Port))
	return nil
}

func (h *HexaneConfig) HttpServerHandler(profile *Http) error {
	var err error

	serverExists := false

	for Head := HexaneServers.Head; Head != nil; Head = Head.Next {
		if Head.Address == profile.Address && Head.Port == profile.Port {

			serverExists = true
			h.UpdateServerEndpoints(Head)
			break
		}
	}
	if !serverExists {
		if err = h.StartNewServer(profile); err != nil {
			return err
		}
		AddServer(profile)
	}

	profile.Ready <- true
	return err
}

func (h *HexaneConfig) RunServer() error {
	var (
		err     error
		profile *Http
	)

	profile = new(Http)

	if err = MapToStruct(h.UserConfig.Network.Config, profile); err != nil {
		return err
	}

	profile.SigTerm = make(chan bool)
	profile.Ready = make(chan bool)

	go func() {
		err = h.HttpServerHandler(profile)
	}()

	<-profile.Ready
	if err != nil {
		return err
	}

	AddConfig(h)

	return nil
}

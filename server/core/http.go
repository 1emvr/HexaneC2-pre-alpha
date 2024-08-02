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

func ParseHeaders(c *gin.Context) []Headers {
	var heads []Headers

	for key, headers := range c.Request.Header {
		for _, value := range headers {

			vals := Headers{key, value}
			heads = append(heads, vals)
		}
	}
	return heads
}

func (h *HexaneConfig) ServerRoutine(c *gin.Context) {
	var (
		err       error
		body, rsp []byte
	)

	if body, err = ioutil.ReadAll(c.Request.Body); err != nil {
		WrapMessage("ERR", err.Error())
	}

	if rsp, err = ResponseWorker(body); err != nil {
		WrapMessage("ERR", err.Error())
	}

	//c.String(200, base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(rsp))
	c.String(200, string(rsp))
}

func (h *HexaneConfig) UpdateServerEndpoints(p *Http) {

	chanNewEndp := make(chan string)
	defer close(chanNewEndp)

	go func() {
		for endp := range chanNewEndp {
			p.Handle.GET(endp, func(context *gin.Context) {
				h.ServerRoutine(context)
			})
		}
	}()

	for _, newEndp := range p.Endpoints {
		endpointExists := false

		for _, existingEndp := range p.Endpoints {
			if existingEndp == newEndp {

				endpointExists = true
				break
			}
		}
		if !endpointExists {
			p.Endpoints = append(p.Endpoints, newEndp)
			chanNewEndp <- newEndp
		}
	}
}

func (h *HexaneConfig) StartNewServer(p *Http) error {
	var err error

	p.Handle = gin.Default()
	if !Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	for _, endp := range p.Endpoints {
		p.Handle.GET(endp, func(context *gin.Context) {
			h.ServerRoutine(context)
		})
	}

	server := &http.Server{
		Addr:    p.Address + ":" + strconv.Itoa(p.Port),
		Handler: p.Handle,
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
		<-p.SigTerm

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

	WrapMessage("INF", fmt.Sprintf("server started on %s:%d", p.Address, p.Port))
	return nil
}

func (h *HexaneConfig) HttpServerHandler(p *Http) error {
	var (
		err    error
		exists = false
	)

	for Head := HexaneServers.Head; Head != nil; Head = Head.Next {
		if Head.Address == p.Address && Head.Port == p.Port {

			exists = true
			h.UpdateServerEndpoints(Head)
			break
		}
	}
	if !exists {
		if err = h.StartNewServer(p); err != nil {
			return err
		}
		AddServer(p)
	}

	p.Ready <- true
	return err
}

func (h *HexaneConfig) RunServer() error {
	var (
		err error
		p   *Http
	)

	p = new(Http)

	if err = MapToStruct(h.UserConfig.Network.Config, p); err != nil {
		return err
	}

	p.SigTerm = make(chan bool)
	p.Ready = make(chan bool)

	go func() {
		err = h.HttpServerHandler(p)
	}()

	<-p.Ready
	if err != nil {
		return err
	}

	AddConfig(h)

	return nil
}

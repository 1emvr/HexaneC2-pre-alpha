package core

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

	if rsp, err = ParseMessage(body); err != nil {
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

func (h *HexaneConfig) StartNewServer(profile *Http) {
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

	profile := h.UserConfig.Network.Config.(*Http)
	serverExists := false

	for Head := HexaneServers.Head; Head != nil; Head = Head.Next {
		if Head.Address == profile.Address && Head.Port == profile.Port {

			serverExists = true
			h.UpdateServerEndpoints(Head)
			break
		}
	}
	if !serverExists {
		h.StartNewServer(profile)
	}
}

package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/node"
)

type paginationStubBackend struct {
	nodeBackend
	providers []*node.ProviderInfo
	messages  []*chat.Envelope
}

func (s *paginationStubBackend) GetProviders() []*node.ProviderInfo {
	return s.providers
}

func (s *paginationStubBackend) GetChatMessages(account string, since int64) []*chat.Envelope {
	return s.messages
}

func TestHandleGetProvidersAndChatMessagesPagination(t *testing.T) {
	stub := &paginationStubBackend{}
	for i := 0; i < 150; i++ {
		stub.providers = append(stub.providers, &node.ProviderInfo{Account: "prov"})
		stub.messages = append(stub.messages, &chat.Envelope{ID: "msg"})
	}
	h := &Handler{node: stub}

	req := httptest.NewRequest(http.MethodGet, "/providers?limit=10&offset=5", nil)
	rec := httptest.NewRecorder()
	h.handleGetProviders(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from handleGetProviders, got %d", rec.Code)
	}
	var gotProviders []*node.ProviderInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &gotProviders); err != nil {
		t.Fatalf("unmarshal providers: %v", err)
	}
	if len(gotProviders) != 10 {
		t.Fatalf("expected 10 paginated providers, got %d", len(gotProviders))
	}

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	st, err := h.chatAuth()
	if err != nil {
		t.Fatalf("chatAuth: %v", err)
	}
	ch, _, err := st.issueChallenge(time.Now().UnixNano())
	if err != nil {
		t.Fatalf("issueChallenge: %v", err)
	}
	chBytes, _ := hex.DecodeString(ch)
	sig := hex.EncodeToString(ed25519.Sign(kp.Private, chatSignTarget(chBytes)))

	q := url.Values{}
	q.Set("account", kp.Address())
	q.Set("pub_key", kp.PubKeyHex())
	q.Set("challenge", ch)
	q.Set("sig", sig)
	q.Set("limit", "10")
	reqChat := httptest.NewRequest(http.MethodGet, "/chat/messages?"+q.Encode(), nil)
	recChat := httptest.NewRecorder()
	h.handleChatMessages(recChat, reqChat)
	if recChat.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from handleChatMessages, got %d (%s)", recChat.Code, recChat.Body.String())
	}
	var gotMsgs []*chat.Envelope
	if err := json.Unmarshal(recChat.Body.Bytes(), &gotMsgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	if len(gotMsgs) != 10 {
		t.Fatalf("expected 10 paginated chat messages, got %d", len(gotMsgs))
	}
}
